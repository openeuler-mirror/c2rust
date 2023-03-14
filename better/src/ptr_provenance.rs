//! Pointer provenance analysis. This analysis is used for determining
//! the provenance of pointers, and whether to promote them to
//! references.
//!
//! The analysis is a form of set-based points-to analysis combined
//! with a taint analysis.

use crate::{
    analysis,
    compiler_interface::*,
    config::*,
    constants::*,
    rustc_ast::ast::LitKind,
    rustc_hir::{
        def::{DefKind, Res},
        intravisit::FnKind,
        *,
    },
    rustc_lint::{LateContext, LateLintPass, LintPass},
    rustc_middle::ty::{AdtDef, TyCtxt, TyKind, TyS, TypeAndMut},
    rustc_span::{symbol::Ident, Span},
    solver::*,
    types::Type,
    util::{profile, HashMap, HashSet},
    Name,
};
use def_id::{DefId, LOCAL_CRATE};
use itertools::Itertools;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem, panic,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use SimpleTerm::*;
use Term::*;

use crate::solver::{equality_based::*, set_based};

/// Whether we should poison the signatures of functions that are used
/// as function pointers
pub static POISON_SIGS_OF_FN_PTRS: AtomicBool = AtomicBool::new(false);

/// Whether we should compute ownership analysis results
pub static COMPUTE_OWNERSHIP: AtomicBool = AtomicBool::new(false);

/// Whether we should poison pointers cast to unrelated types
pub static POISON_UNRELATED_TYPE_CASTS: AtomicBool = AtomicBool::new(false);

/// Whether we should analyze bodies of globals, this does not matter
/// for counting but it matters for rewriting programs that have
/// nontrivial initialization code for globals.
pub static ANALYZE_GLOBAL_INITS: AtomicBool = AtomicBool::new(false);

/// Whether we should print generated constraints
pub static PRINT_CONSTRAINTS: AtomicBool = AtomicBool::new(false);

fn mk_ref<V>(co: SimpleTerm<V>, contra: SimpleTerm<V>) -> Term<V> {
    C(Ctor(REF.clone(), vec![co], vec![contra]))
}

fn get_def_qname<'tcx>(ctx: &LateContext<'tcx>, def_id: DefId) -> Name {
    Name::from(
        ctx.get_def_path(def_id)
            .iter()
            .map(|segment| segment.to_string())
            .filter(|s| !s.is_empty())
            .join("::"),
    )
}

pub fn local_crate_name(ctx: &LateContext<'_>) -> String {
    ctx.tcx.crate_name(LOCAL_CRATE).to_string()
}

/// Compare given qualified function name against the functions we can handle
pub fn qual_fn_we_can_handle(name: &str) -> bool {
    if name.contains("::") {
        RUST_FNS_WE_HANDLE.contains(name) || {
            if let [fn_name, _qual] = name.rsplitn(2, "::").collect::<Vec<&str>>()[..] {
                // TODO: check if qual is the current module, and malloc is extern declared here
                C_FNS_WE_HANDLE.contains(fn_name)
            } else {
                false
            }
        }
    } else {
        C_FNS_WE_HANDLE.contains(name)
    }
}

pub fn is_void_ptr(ctx: &LateContext<'_>, ty: &TyS) -> bool {
    if let TyKind::RawPtr(TypeAndMut { ty: pointee_ty, .. }) = ty.kind() {
        if let TyKind::Adt(AdtDef { did: def_id, .. }, _) = pointee_ty.kind() {
            let qname = get_def_qname(ctx, *def_id);
            return qname == *C_VOID;
        }
    }
    false
}

fn mentions_types(t: &Term<Loc<Name>>) -> bool {
    fn mentions_types_s(s: &SimpleTerm<Loc<Name>>) -> bool {
        matches!(s, LV(Loc::Access(..)))
    }

    match t {
        C(Ctor(name, co, contra)) => {
            *name != *REF || co.iter().any(mentions_types_s) || contra.iter().any(mentions_types_s)
        },
        S(s) => mentions_types_s(s),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
/// The context that current expression is used in
pub struct ExprCtx {
    /// Is this expression part of a value that is being assigned
    /// (i.e. an `lvalue` in C++ jargon). For example `e1`, `e2`, `e3`
    /// in the following statements would have this set to true, but
    /// `e4` set it to false:
    ///
    /// ```
    ///
    /// e1 = ...
    /// e2.f += ...
    /// (*e3)[e4] = ...
    /// ```
    is_assignee: bool,
    is_callee: bool,
}

impl ExprCtx {
    pub fn with_callee(&self, is_callee: bool) -> Self {
        ExprCtx {
            is_callee,
            ..self.clone()
        }
    }
    pub fn with_assignee(&self, is_assignee: bool) -> Self {
        ExprCtx {
            is_assignee,
            ..self.clone()
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
/// Different kinds of taints we want to distinguish for pointer
/// provenance
pub enum PoisonKind {
    /// Values resulting from pointer arithmetic
    PtrArith,
    /// Values flowing into pointer arithmetic
    PtrArithSink,
    /// Explicit reference
    ExplicitRef,
    /// Source for external C functions
    ExternCallReturn,
    /// Sink for parameters passed to external C functions
    ExternCallParam,
    /// Source for casting from `void *`
    VoidSource,
    /// Sink for casting to `void *`
    VoidSink,
    /// Source for values coming from constructs we don't handle (globals,
    /// inline asm etc.)
    MiscSource,
    /// Sink for values going to constructs we don't handle (globals,
    /// inline asm etc.)
    MiscSink,
    /// Sink for mutability analysis. We need only a
    /// sink because we need to mark only `&mut`/`*mut` that flows
    /// into a deref that is used in a mutable context.
    MutSink,
}

static POISON_SOURCES: [PoisonKind; 4] = [
    PoisonKind::PtrArith,
    PoisonKind::ExternCallReturn,
    PoisonKind::VoidSource,
    PoisonKind::MiscSource,
];

static POISON_SINKS: [PoisonKind; 4] = [
    PoisonKind::PtrArithSink,
    PoisonKind::ExternCallParam,
    PoisonKind::VoidSink,
    PoisonKind::MiscSink,
];

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
/// Different kinds of unsafe behavior we can extract syntactically
pub enum UnsafeBehavior {
    /// Reading a fields from untagged unions
    ReadFromUnion,
    /// Accessing a mutable global/static variable
    MutGlobalAccess,
    /// Inline assembly
    InlineAsm,
    /// Calling external functions, or unsafe fn pointers
    ExternCall,
    /// Raw pointer dereference
    RawPtrDeref,
    /// Unsafe casting by calling `mem::transmute`
    UnsafeCast,
    /// Memory allocation/deallocation by calling `malloc` and `free` directly
    Alloc,
}

/// All types of unsafe behavior a program may exhibit, this must be kept in sync with `UnsafeBehavior`
pub static ALL_UNSAFE_BEHAVIOR: [UnsafeBehavior; 7] = [
    UnsafeBehavior::ReadFromUnion,
    UnsafeBehavior::MutGlobalAccess,
    UnsafeBehavior::InlineAsm,
    UnsafeBehavior::ExternCall,
    UnsafeBehavior::RawPtrDeref,
    UnsafeBehavior::UnsafeCast,
    UnsafeBehavior::Alloc,
];

#[derive(Debug, PartialEq, Eq, Clone, Hash, PartialOrd, Ord)]
/// A location for pointer arithmetic analysis. The values inside the
/// tags depend on the representation.
pub enum Loc<T> {
    /// A variable in the program
    Var(T),
    /// Return value of a function
    RetVal(T),
    /// Parameter of a function, with an index
    Param(T, usize),
    /// Field access. The first argument is the type name, the second
    /// one is the field
    Access(T, T),
    /// A synthetic location derived from HIR IDs, this allows us to
    /// create a location variable bound to an AST node
    Synthetic(HirId),
    /// A pseudo-variable denoting unknown values
    Unknown,
    /// A freshly-generated location for variables to glue certain
    /// constraints
    Fresh(u32),
    /// A location marking values returned immediately from a call to
    /// malloc per call site, we don't mark those values as void *
    /// immediately to keep the analysis precise
    Malloc(HirId),
}

impl<T> Loc<T> {
    /// Returns true if this reference is directly derived from the program
    pub fn is_from_program(&self) -> bool {
        match self {
            Loc::Synthetic(_) | Loc::Unknown | Loc::Malloc(_) | Loc::Fresh(_) => false,
            _ => true,
        }
    }

    pub fn to_term(self) -> Term<Self> {
        S(LV(self))
    }

    pub fn to_st(self) -> SimpleTerm<Self> {
        LV(self)
    }

    pub fn fresh() -> Self {
        Loc::Fresh(LOC_COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

static LOC_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn reset_loc_counter() {
    LOC_COUNTER.store(0, Ordering::SeqCst);
}

impl<T: Clone> Loc<T> {
    /// Pack given value in a `Loc` with the same tag
    pub fn repack<U, F: FnMut(T) -> U>(self, fun: &mut F) -> Loc<U> {
        match self {
            Loc::Var(x) => Loc::Var(fun(x)),
            Loc::RetVal(f) => Loc::RetVal(fun(f)),
            Loc::Param(f, n) => Loc::Param(fun(f), n),
            Loc::Access(typename, field) => Loc::Access(fun(typename), fun(field)),
            Loc::Synthetic(h) => Loc::Synthetic(h),
            Loc::Unknown => Loc::Unknown,
            Loc::Fresh(n) => Loc::Fresh(n),
            Loc::Malloc(h) => Loc::Malloc(h),
        }
    }
}

/// The data structure to hold the analysis data
#[derive(Clone, PartialEq, Eq)]
pub struct PtrProvenanceAnalysis {
    /// Equality-based data flow constraints
    pub constraints: ConstraintSystem<Loc<Name>, PoisonKind>,
    /// Subset-based data flow constraints
    pub set_constraints: set_based::ConstraintSystem<Loc<Name>>,
    /// Mapping of locations to the function whose body they are
    /// derived from. This is useful for looking up which functions
    /// contain a poisoned LV.
    pub owners: HashMap<Loc<Name>, HashSet<Name>>,
    /// Mapping from expression IDs to set constraint terms, this is
    /// useful for looking up the value produced by an expression (not
    /// the side effects of the expression!) in the analysis results.
    pub expr_to_term: HashMap<HirId, Term<Loc<Name>>>,
    /// Contains all locations tainted with a given taint, these are
    /// propagated only through equality-based analysis
    pub poisons: HashMap<PoisonKind, HashSet<Loc<Name>>>,
    /// Contains the locations marked as owned pointers
    pub owned: HashSet<Loc<Name>>,
    /// We need to resolve typedefs before adding the constraints
    /// referencing types, so any constraint that refers to a type
    /// name is postponed until the typedefs are processed
    postponed_constraints: Vec<Constraint<Loc<Name>>>,
    /// See `postponed_constraints` for expalanation
    postponed_taints: Vec<(PoisonKind, Loc<Name>)>,
    /// Flag to determine whether we are postponing constraints until
    /// resolving types
    typedefs_are_resolved: bool,
    /// Mapping from type definitions to the types they
    /// represent. This assumes that type definitions don't have any
    /// generic arguments.
    pub typedefs: HashMap<Name, Type>,
}

impl PtrProvenanceAnalysis {
    fn new() -> Self {
        let mut analysis = PtrProvenanceAnalysis {
            constraints: ConstraintSystem::new(),
            set_constraints: set_based::ConstraintSystem::new(),
            owners: HashMap::default(),
            expr_to_term: HashMap::default(),
            poisons: HashMap::default(),
            owned: HashSet::default(),
            postponed_constraints: Vec::new(),
            postponed_taints: Vec::new(),
            typedefs_are_resolved: false,
            typedefs: HashMap::default(),
        };

        for poison in POISON_SOURCES.iter() {
            analysis.poisons.insert(*poison, HashSet::default());
        }
        for poison in POISON_SINKS.iter() {
            analysis.poisons.insert(*poison, HashSet::default());
        }

        analysis
    }

    /// Return the points-to set of the given location according to
    /// the equality-based analysis. This computes `ref⁻¹(x)`
    /// effectively. We return two variables for the two arguments of
    /// `ref` (the covariant and the contravariant set) which collect
    /// different poison data in the subset-based variant. This
    /// function returns `None` for the points to sets that are not
    /// variables (the empty set and the universe).
    pub fn points_to<'a>(&'a self, p: &Loc<Name>) -> HashSet<&Loc<Name>> {
        let p_num = if let Some(n) = self.constraints.to_maybe_num(p) {
            n
        } else {
            // p does not appear in the constraint system
            return HashSet::default();
        };
        let mut h = HashSet::default();
        if let Some(Ctor(_, co, contra)) = self
            .constraints
            .ctor_map(p_num)
            .and_then(|ctor_map| ctor_map.get(&*REF))
        {
            assert_eq!(co.len(), 1);
            assert_eq!(contra.len(), 1);
            let constraints = &self.constraints;
            let mut extract_var = |s: &SimpleTerm<u32>| {
                if s.is_lv() {
                    h.insert(constraints.to_var(*s.unwrap_lv()).unwrap());
                }
            };
            extract_var(&co[0]);
            extract_var(&contra[0]);
        }
        h
    }

    /// Add given data flow
    pub fn add_flow(&mut self, source: Term<Loc<Name>>, sink: Term<Loc<Name>>) {
        if (!self.typedefs_are_resolved) && (mentions_types(&source) || mentions_types(&sink)) {
            self.postponed_constraints.push(Constraint(source, sink));
            return;
        }

        if PRINT_CONSTRAINTS.load(Ordering::Relaxed) {
            log::info!("adding data flow {:?} -> {:?}", source, sink);
        }

        self.add_goal(Constraint(source, sink));
    }

    /// Add given subset-based constraint
    fn add_goal(&mut self, goal: Constraint<Loc<Name>>) {
        self.constraints.add_goal(goal.clone()).unwrap();
        self.set_constraints.add_goal(goal).unwrap();
    }

    /// Add given type of taint to given location
    pub fn add_poison(&mut self, poison: PoisonKind, loc: Loc<Name>) {
        if (!self.typedefs_are_resolved) && matches!(&loc, Loc::Access(..)) {
            self.postponed_taints.push((poison, loc));
            return;
        }

        if PRINT_CONSTRAINTS.load(Ordering::Relaxed) {
            log::info!("adding poison {:?} to {:?}", poison, loc);
        }

        self.poisons.entry(poison).or_default().insert(loc.clone());

        // add poison information to the equality solver, so it
        // can be propagated along the roots
        self.constraints.add_poison(loc, poison);
    }

    /// Mark given location as an owned pointer, this is orthogonal to
    /// whether it is poisoned
    pub fn mark_as_owned(&mut self, loc: Loc<Name>) {
        self.owned.insert(loc);
    }

    pub fn bind_expr_to_term(&mut self, expr_id: HirId, term: Term<Loc<Name>>) {
        self.expr_to_term.insert(expr_id, term);
    }

    pub fn declare_owner(&mut self, lv: &Loc<Name>, owner: &Name) {
        if !self.owners.contains_key(lv) {
            self.owners.insert(lv.clone(), HashSet::default());
        }

        self.owners.get_mut(lv).unwrap().insert(owner.clone());
    }

    #[must_use]
    pub fn solve(&mut self) -> Result<(), ConstraintError<Loc<Name>>> {
        // load the promoted pointers from the configuration
        for (loc, kind) in &CONFIG.read().unwrap().ptr_kind {
            use PtrKind::*;

            match kind {
                Raw => {
                    self.add_poison(PoisonKind::MiscSource, loc.clone());
                    self.add_poison(PoisonKind::MiscSink, loc.clone());
                },
                Owned => {
                    self.mark_as_owned(loc.clone());
                },
                Borrowing => {},
            }
        }

        // helper function to lookup typedef, returns a valid typedef
        // that resolves to the same type if it does not resolve to a
        // named type (struct, union, extern type, etc.)
        fn lookup_typedef(table: &HashMap<Name, Type>, name: Name) -> Name {
            match table.get(&name) {
                Some(ty) if matches!(ty, Type::Unknown(_) | Type::Syntactic(_)) => {
                    let resolved_type = Name::from(format!("{}", ty));
                    lookup_typedef(table, resolved_type)
                },
                Some(Type::Enum(n)) => n.clone(),
                Some(Type::Struct(n)) => n.clone(),
                Some(Type::Union(n)) => n.clone(),
                Some(_) | None => name,
            }
        }

        // By this point, all typedefs must be processed. We will
        // resolve them as needed and memoize the results.

        // move self.typedefs temporarily so we can use it without moving it around
        let typedefs = mem::take(&mut self.typedefs);
        let mut resolved_typedefs = HashMap::default();
        let mut resolve_type_name = |n: Name| {
            if typedefs.contains_key(&n) {
                // look up in the memo table
                resolved_typedefs
                    .entry(n.clone())
                    .or_insert_with(|| lookup_typedef(&typedefs, n))
                    .clone()
            } else {
                n
            }
        };
        let mut resolve_term = |t: Term<Loc<Name>>| match t {
            C(Ctor(name, co, contra)) => {
                let resolved_name = if name == *REF {
                    name
                } else {
                    resolve_type_name(name)
                };
                let mut resolve_simple_term = |s: SimpleTerm<Loc<Name>>| match s {
                    LV(loc) => LV(loc.repack(&mut resolve_type_name)),
                    s => s,
                };

                C(Ctor(
                    resolved_name,
                    co.into_iter().map(&mut resolve_simple_term).collect(),
                    contra.into_iter().map(&mut resolve_simple_term).collect(),
                ))
            },
            S(LV(loc)) => S(LV(loc.repack(&mut resolve_type_name))),
            S(_) => t,
        };
        self.typedefs_are_resolved = true;

        for Constraint(source, sink) in mem::take(&mut self.postponed_constraints) {
            self.add_flow(resolve_term(source), resolve_term(sink));
        }

        for (poison, loc) in mem::take(&mut self.postponed_taints) {
            self.add_poison(poison, loc.repack(&mut resolve_type_name));
        }
        // put back self.typedefs
        self.typedefs = typedefs;

        self.constraints.solve()?;

        if COMPUTE_OWNERSHIP.load(Ordering::SeqCst) {
            profile("set constraint solving", || self.set_constraints.solve())?;
        }

        profile("computing poison sets", || {
            let eq_classes = self.constraints.compute_eq_classes();
            for locs in self.poisons.values_mut() {
                let mut roots_to_add = HashSet::default();
                for loc in locs.iter() {
                    let num_loc = self.constraints.to_num(loc);
                    let root = self.constraints.find_mut(num_loc);
                    roots_to_add.insert(root);
                }
                for root in roots_to_add {
                    locs.extend(eq_classes[&root].clone());
                }
            }
            // Poison the points-to set of all extern pointers as well, we
            // don't need to build the whole poison set because we already
            // use the equality constraints inside `Self::points_to()`.
            //
            // Do this with fewest number of dummy variables because the
            // flows added by `add_flow` are also seen by the set
            // constraint solver.
            let solver = &mut self.constraints;
            let mut collect_roots = |set: &HashSet<Loc<Name>>| {
                set.iter()
                    .map(|l| {
                        let num = solver.to_num(l);
                        (solver.find_mut(num), l.clone())
                    })
                    .collect::<HashMap<u32, Loc<Name>>>()
            };
            let sink_roots = collect_roots(&self.poisons[&PoisonKind::ExternCallParam]);
            log::info!("# of extern param roots: {}", sink_roots.len());
            let source_roots = collect_roots(&self.poisons[&PoisonKind::ExternCallReturn]);
            log::info!("# of extern return roots: {}", source_roots.len());
            sink_roots.values().for_each(|sink| {
                let dummy_for_ptsto = Loc::fresh();
                self.add_flow(
                    sink.clone().to_term(),
                    mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                );
                self.add_poison(PoisonKind::MiscSink, dummy_for_ptsto);
            });
            source_roots.values().for_each(|source| {
                let dummy_for_ptsto = Loc::fresh();
                self.add_flow(
                    source.clone().to_term(),
                    mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                );
                self.add_poison(PoisonKind::MiscSource, dummy_for_ptsto);
            });
        });

        profile("propagating ownership", || {
            // propagate ownership information. we use SCCs to keep the
            // graph traversal small, although we add all relevant
            // variables to `self.owned` in the end.
            let worklist = {
                let set_c = &mut self.set_constraints;
                let owned = &self.owned;
                owned
                    .iter()
                    .map(|l| set_c.to_num(l))
                    .collect::<HashSet<u32>>()
            };
            let mut owned_sccs = HashSet::default();
            let subsets = self.set_constraints.compute_subsets();
            for next in worklist {
                // skip the item if it (and its subsets) have been already inserted
                if !owned_sccs.contains(&next) {
                    for subset in &subsets[next as usize] {
                        owned_sccs.insert(*subset);
                    }
                }
            }
            owned_sccs.iter().for_each(|scc| {
                self.owned
                    .extend(self.set_constraints.num_to_var()[*scc as usize].clone())
            });
        });

        Ok(())
    }

    pub fn is_poisoned(&self, loc: &Loc<Name>) -> bool {
        POISON_SOURCES.iter().any(|p| self.poisons[p].contains(loc))
            || POISON_SINKS.iter().any(|p| self.poisons[p].contains(loc))
    }

    pub fn is_expr_poisoned(&self, hir_id: HirId) -> bool {
        if let Some(S(LV(loc))) = self.expr_to_term.get(&hir_id) {
            self.is_poisoned(loc)
        } else {
            false
        }
    }

    pub fn is_owned(&self, hir_id: HirId) -> bool {
        if let Some(S(LV(loc))) = self.expr_to_term.get(&hir_id) {
            self.owned.contains(loc)
        } else {
            false
        }
    }

    pub fn is_loc_owned(&self, loc: &Loc<Name>) -> bool {
        self.owned.contains(loc)
    }

    pub fn expr_has_poison(&self, hir_id: HirId, poison: PoisonKind) -> bool {
        if let Some(S(LV(loc))) = self.expr_to_term.get(&hir_id) {
            self.has_poison(loc, poison)
        } else {
            false
        }
    }

    pub fn has_poison(&self, loc: &Loc<Name>, poison: PoisonKind) -> bool {
        self.poisons.get(&poison).map_or(false, |s| s.contains(loc))
    }

    pub fn poisons(&self, loc: &Loc<Name>) -> (HashSet<PoisonKind>, HashSet<PoisonKind>) {
        (
            POISON_SOURCES
                .iter()
                .filter(|p| self.poisons[p].contains(loc))
                .map(|p| *p)
                .collect(),
            POISON_SINKS
                .iter()
                .filter(|p| self.poisons[p].contains(loc))
                .map(|p| *p)
                .collect(),
        )
    }

    /// Checks if the flow `source -> sink` exists in the program according to the equality-based analysis
    pub fn eq_flow_exists(&mut self, source: &Loc<Name>, sink: &Loc<Name>) -> bool {
        let source_num = self.constraints.to_num(source);
        let sink_num = self.constraints.to_num(sink);
        self.constraints.find_mut(source_num) == self.constraints.find_mut(sink_num)
    }

    /// Checks if the data flow `source -> sink` exists according to the subset-based DFA
    pub fn subset_flow_exists(&mut self, source: &Loc<Name>, sink: &Loc<Name>) -> bool {
        self.set_constraints.is_subset(source, sink)
    }
}

impl analysis::AnalysisResult for PtrProvenanceAnalysis {
    fn name() -> String {
        "PtrProvenance".to_owned()
    }
}

#[derive(Clone, PartialEq, Eq)]
/// A version of pointer provenance analysis to keep the version
/// computed here around across iterations.
struct InitialPtrProvenance {
    ptr_provenance: PtrProvenanceAnalysis,
}

impl analysis::AnalysisResult for InitialPtrProvenance {
    fn name() -> String {
        "InitialPtrProvenance".to_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Call graph, does not handle trait methods yet.
pub struct CallGraph {
    /// Holds the callees of each function. This is the ground truth
    /// for the call graph, all the other parts of the graph are
    /// computed from this.
    callees: HashMap<Name, HashSet<Name>>,
    /// Holds the callers of each function
    callers: HashMap<Name, HashSet<Name>>,
    /// Holds the transitive closure of the call graph
    closure: HashMap<Name, HashSet<Name>>,
    /// Holds the transitive closure of callers, for inverse lookup
    inverse_closure: HashMap<Name, HashSet<Name>>,
    /// Whether the closure is no longer valid
    dirty: bool,
    /// Whether a function has certain types of code we don't handle
    unsafe_behavior: HashMap<Name, BTreeSet<UnsafeBehavior>>,
    /// Count of static occurrences of different unsafe behavior
    ub_count: BTreeMap<UnsafeBehavior, usize>,
    /// Unqualified names of functions defined in the program mapped
    /// to their qualified names. This is used for both determining truly extern functions, and for rewriting extern
    pub defined_fns: HashMap<Name, Name>,
    /// Extern functions declared in the program
    pub extern_fns: HashSet<Name>,
    /// Calls to functions whose extern status are not resolved yet
    /// (excluding calls to function pointers). We use this during the
    /// online building of initial call graph.
    unresolved_calls: Vec<(Name, Name)>,
    /// Functions that are used as function pointers
    pub used_as_fn_pointer: HashSet<Name>,
}

impl CallGraph {
    pub fn new() -> Self {
        CallGraph {
            callees: HashMap::default(),
            callers: HashMap::default(),
            closure: HashMap::default(),
            inverse_closure: HashMap::default(),
            dirty: false,
            unsafe_behavior: HashMap::default(),
            ub_count: BTreeMap::new(),
            defined_fns: HashMap::default(),
            extern_fns: HashSet::default(),
            unresolved_calls: Vec::new(),
            used_as_fn_pointer: HashSet::default(),
        }
    }

    /// Add this function declaration to relevant maps
    pub fn add_fn_decl(&mut self, fn_name: Name) {
        self.unsafe_behavior.insert(fn_name, BTreeSet::new());
    }
    // 在函数fn_name下添加它所包含的不安全行为
    pub fn add_unsafe_behavior(&mut self, fn_name: &Name, ub: UnsafeBehavior) {
        // also increment the counter
        *self.ub_count.entry(ub).or_insert(0) += 1;

        if !self.unsafe_behavior.contains_key(fn_name) {
            self.unsafe_behavior
                .insert(fn_name.clone(), BTreeSet::new());
        }

        self.unsafe_behavior.get_mut(fn_name).unwrap().insert(ub);
    }

    // 返回 unsafe_behavior Hash表
    pub fn unsafe_behavior(&self) -> &HashMap<Name, BTreeSet<UnsafeBehavior>> {
        &self.unsafe_behavior
    }
    // 返回 ub_count值
    pub fn ub_count(&self) -> &BTreeMap<UnsafeBehavior, usize> {
        &self.ub_count
    }

    pub fn transitive_callers(&self) -> Option<&HashMap<Name, HashSet<Name>>> {
        if self.dirty {
            None
        } else {
            Some(&self.inverse_closure)
        }
    }

    pub fn callees(&self) -> &HashMap<Name, HashSet<Name>> {
        &self.callees
    }

    pub fn callers(&self) -> &HashMap<Name, HashSet<Name>> {
        &self.callers
    }

    pub fn closure(&self) -> Option<&HashMap<Name, HashSet<Name>>> {
        if self.dirty {
            None
        } else {
            Some(&self.closure)
        }
    }

    pub fn inverse_closure(&self) -> Option<&HashMap<Name, HashSet<Name>>> {
        if self.dirty {
            None
        } else {
            Some(&self.inverse_closure)
        }
    }

    /// Add given call edge. The parameter `is_special` should be set
    /// if the callee is a special extern function we handle (e.g. `malloc`).
    pub fn add_call(&mut self, caller: Name, callee: Name, is_special: bool) {
        // TODO: take a reference and avoid copying unless necessary

        let mut insert_call_now = true;

        if callee == *TRANSMUTE_FN {
            self.add_unsafe_behavior(&caller, UnsafeBehavior::UnsafeCast);
        } else if !is_special && !self.defined_fns.contains_key(&callee) {
            // The callee is not a defined function, add this as a potentially extern call
            self.unresolved_calls.push((caller.clone(), callee.clone()));
            self.dirty = true;
            insert_call_now = false;
        } else if is_special
            && (callee.ends_with("::malloc")
                || callee.ends_with("::calloc")
                || callee.ends_with("::free"))
        {
            self.add_unsafe_behavior(&caller, UnsafeBehavior::Alloc);
        }

        if insert_call_now {
            self.dirty = self
                .callees
                .entry(caller)
                .or_insert_with(HashSet::default)
                .insert(callee)
                || self.dirty;
        }
    }

    pub fn compute_closure(&mut self) {
        if !self.dirty {
            return;
        }

        // at this point, all callees should be resolved, go through unresolved calls and resolve them
        for (caller, callee) in std::mem::take(&mut self.unresolved_calls) {
            let unqual_callee = Name::from(callee.rsplit_once("::").unwrap().1);
            if self.extern_fns.contains(&unqual_callee) {
                self.add_unsafe_behavior(&caller, UnsafeBehavior::ExternCall);
            }

            // insert the missing call edge
            let real_callee = self
                .defined_fns
                .get(&unqual_callee)
                .cloned()
                .unwrap_or(callee);
            self.dirty = self
                .callees
                .entry(caller)
                .or_insert_with(HashSet::default)
                .insert(real_callee)
                || self.dirty;
        }

        profile("call graph closure", || {
            // Compute transitive closure using repeated DFS

            // The set of all functions
            let fns: HashSet<&Name> = {
                let mut fns = HashSet::default();

                for (f, gs) in self.callees.iter() {
                    fns.insert(f);
                    fns.extend(gs);
                }

                fns
            };

            for f in fns.into_iter() {
                if let Some(callees) = self.callees.get(f) {
                    let mut worklist = callees.iter().map(|n| n.clone()).collect::<Vec<Name>>();
                    let mut seen = HashSet::default();

                    while let Some(g) = worklist.pop() {
                        seen.insert(g.clone());

                        for h in self.callees.get(&g).into_iter().flatten() {
                            if !seen.contains(h) {
                                worklist.push(h.clone());
                            }
                        }
                    }

                    // Put the computed result in the closure map
                    self.closure.insert(f.clone(), seen);
                } else {
                    self.closure.insert(f.clone(), HashSet::default());
                }
            }

            // build the caller graph
            for (caller, callees) in &self.callees {
                for callee in callees {
                    self.callers
                        .entry(callee.clone())
                        .or_insert(HashSet::default())
                        .insert(caller.clone());
                }
            }
            for caller in self.closure.keys() {
                // create empty entries for the callers too
                self.callers
                    .entry(caller.clone())
                    .or_insert(HashSet::default());
            }

            // build inverse closure
            for (caller, callees) in &self.closure {
                for callee in callees {
                    self.inverse_closure
                        .entry(callee.clone())
                        .or_insert(HashSet::default())
                        .insert(caller.clone());
                }
            }

            // propagate unsafe behavior to the closure
            for (callee, callers) in &self.inverse_closure {
                if let Some(ubs) = self.unsafe_behavior.get(callee).cloned() {
                    if ubs.is_empty() {
                        continue;
                    }
                    for caller in callers {
                        self.unsafe_behavior
                            .entry(caller.clone())
                            .or_insert(BTreeSet::new())
                            .extend(ubs.clone().into_iter());
                    }
                }
            }

            self.dirty = false;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_graph_test() {
        let mut call_graph = CallGraph::new();
        call_graph.defined_fns.extend(
            vec!["::e", "::f", "::g"]
                .into_iter()
                .map(|f| (Name::from(f), Name::from(f))),
        );

        let calls = vec![
            ("::f", "::g"),
            ("::g", "::h"),
            ("::i", "::h"),
            ("::g", "::j"),
            ("::e", "::j"),
            ("::j", "::e"),
            ("::g", "::g"),
        ]
        .into_iter()
        .map(|(f, g)| (Name::from(f), Name::from(g)))
        .collect::<Vec<(Name, Name)>>();

        let callers = vec![
            ("::e", vec!["::j"]),
            ("::f", vec![]),
            ("::g", vec!["::f", "::g"]),
            ("::i", vec![]),
            ("::h", vec!["::g", "::i"]),
            ("::j", vec!["::e", "::g"]),
        ]
        .into_iter()
        .map(|(f, gs)| {
            (
                Name::from(f),
                gs.into_iter().map(|g| Name::from(g)).collect(),
            )
        })
        .collect::<HashMap<Name, HashSet<Name>>>();

        for (f, g) in calls.into_iter() {
            call_graph.add_call(f, g, false);
        }

        let closure: HashMap<Name, HashSet<Name>> = vec![
            ("::f", vec!["::g", "::h", "::j", "::e"]),
            ("::g", vec!["::g", "::h", "::j", "::e"]),
            ("::h", vec![]),
            ("::i", vec!["::h"]),
            ("::e", vec!["::j", "::e"]),
            ("::j", vec!["::j", "::e"]),
        ]
        .into_iter()
        .map(|(f, gs)| {
            (
                Name::from(f),
                gs.into_iter()
                    .map(|g| Name::from(g))
                    .collect::<HashSet<Name>>(),
            )
        })
        .collect();

        call_graph.compute_closure();

        assert_eq!(call_graph.closure().unwrap(), &closure);
        assert_eq!(call_graph.callers(), &callers);
    }
}

impl analysis::AnalysisResult for CallGraph {
    fn name() -> String {
        "CallGraph".to_owned()
    }
}

#[derive(Clone)]
/// Context for the pointer provenance analysis. We use this to
/// decouple parts of the analysis from the visitors in LateLintPass.
struct AnalysisCtx<'a, 'tcx> {
    pub locals: HashMap<Ident, Loc<Name>>,
    pub fn_name: Name,
    pub ctx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> AnalysisCtx<'a, 'tcx> {
    fn new(fn_name: Name, ctx: &'a LateContext<'tcx>) -> AnalysisCtx<'a, 'tcx> {
        AnalysisCtx {
            locals: HashMap::default(),
            fn_name: fn_name,
            ctx: ctx,
        }
    }

    fn tcx(&self) -> &'a TyCtxt<'tcx> {
        &self.ctx.tcx
    }
}

/// Analysis pass implemented as a LateLintPass. Currently, the
/// analysis supports handling only 1 crate.
pub struct PtrProvenancePass {
    /// Analysis data
    pub taint_analysis: PtrProvenanceAnalysis,
    /// Call graph
    call_graph: CallGraph,
    /// Foreign function arities, we use these to add the extern
    /// call/return edges for truly extern functions, and to connect
    /// multiple declarations of the same function in different
    /// modules.
    extern_arity: HashMap<Name, usize>,
    /// Normal function arities, used for poisoning foreign function
    /// signatures
    fn_arity: HashMap<Name, usize>,
}

impl PtrProvenancePass {
    pub fn new() -> Box<LatePass> {
        Box::new(PtrProvenancePass {
            taint_analysis: PtrProvenanceAnalysis::new(),
            call_graph: CallGraph::new(),
            extern_arity: HashMap::default(),
            fn_arity: HashMap::default(),
        })
    }

    /// Returns data flow if this is an intrinsics that we inline during this analysis
    fn intrinsics_data_flow(fn_name: &Name) -> Option<&Vec<DataFlow>> {
        COMPILER_INTRINSICS.get(fn_name)
    }

    pub fn path_segment_to_string<'hir>(segment: &PathSegment<'hir>) -> String {
        // TODO: don't erase generic arguments
        format!("{}", segment.ident)
    }

    fn qpath_to_name(ctx: &AnalysisCtx, qpath: &QPath, hir_id: HirId) -> Name {
        use rustc_hir::def::Res::*;

        let resolve_path_directly = || {
            use QPath::*;
            match qpath {
                Resolved(_self_ty, path) => {
                    if path.segments.len() == 1 && ctx.locals.contains_key(&path.segments[0].ident)
                    {
                        // the path has only one identifier, and it is a
                        // local variable name, return the name qualified
                        // with the function
                        let last_segment = &path.segments[0].ident;
                        match ctx.locals[last_segment].clone() {
                            Loc::Var(name) => name,
                            loc => panic!(
                                "did not expect unnamed location mapped to variable in context: {} -> {:?}",
                                last_segment, loc
                            ),
                        }
                    } else {
                        Name::from(
                            path.segments
                                .iter()
                                .map(|segment| PtrProvenancePass::path_segment_to_string(segment))
                                .filter(|s| !s.is_empty())
                                .join("::"),
                        )
                    }
                },
                TypeRelative(self_ty, segment) => Name::from(format!(
                    "{:?}::{}",
                    self_ty,
                    PtrProvenancePass::path_segment_to_string(segment)
                )),
                LangItem(item, _) => Name::from(format!("{}", item.name())),
            }
        };

        match ctx.ctx.qpath_res(qpath, hir_id) {
            Def(_, def_id) => Name::from(get_def_qname(ctx.ctx, def_id)),
            Local(_) | Err => resolve_path_directly(),
            def => todo!("{:?}", def),
        }
    }

    fn qpath_to_loc<'a, 'tcx>(
        ctx: &AnalysisCtx<'a, 'tcx>,
        qpath: &QPath<'tcx>,
        hir_id: HirId,
    ) -> Loc<Name> {
        Loc::Var(Self::qpath_to_name(ctx, qpath, hir_id))
    }

    fn analyze_pattern<'a, 'tcx>(
        &mut self,
        ctx: &AnalysisCtx<'a, 'tcx>,
        pat: &'tcx Pat<'tcx>,
    ) -> (Option<Term<Loc<Name>>>, AnalysisCtx<'a, 'tcx>) {
        let mut extended_ctx = ctx.clone();
        let term = match &pat.kind {
            PatKind::Wild => None,
            PatKind::Binding(annotation, _id, name, sub_pattern) => {
                let id_lv = Loc::Var(Name::from(format!("{}::{}", ctx.fn_name, name)));
                let id_v = LV(id_lv.clone());
                let by_ref = matches!(
                    annotation,
                    BindingAnnotation::Ref | BindingAnnotation::RefMut
                );
                let term = if by_ref {
                    // create a dummy variable for the points-to set
                    let dummy = LV(Loc::fresh());
                    self.taint_analysis
                        .add_flow(mk_ref(dummy.clone(), dummy.clone()), S(id_v));
                    S(dummy)
                } else {
                    S(id_v.clone())
                };

                if let Some(sub_pat) = sub_pattern {
                    let (sub_term, sub_ctx) = self.analyze_pattern(ctx, sub_pat);
                    extended_ctx = sub_ctx;
                    if let Some(sub_t) = sub_term {
                        self.taint_analysis.add_flow(sub_t, term.clone());
                    }
                }

                extended_ctx.locals.insert(name.clone(), id_lv);

                Some(term)
            },
            PatKind::Struct(name, fields, ignore_rest) => {
                if *ignore_rest {
                    panic!(
                        "struct patterns with some fields ignored are not supported: {:#?}",
                        pat
                    );
                }

                let struct_name = Self::qpath_to_name(ctx, name, pat.hir_id);
                let field_terms = fields
                    .iter()
                    .map(|field| {
                        let (field_term, field_ctx) = self.analyze_pattern(ctx, field.pat);
                        extended_ctx = field_ctx;

                        let synthetic_var = Loc::Synthetic(field.pat.hir_id);

                        let field_var = match field_term {
                            Some(S(LV(var))) => var,
                            Some(term) => {
                                // add one term to bind the term to synthetic var
                                self.taint_analysis
                                    .add_flow(term.clone(), S(LV(synthetic_var.clone())));
                                synthetic_var
                            },
                            None => synthetic_var,
                        };

                        // add data flow from the field to the
                        // access LV because this analysis is
                        // field-based
                        self.taint_analysis.add_flow(
                            field_var.clone().to_term(),
                            Loc::Access(struct_name.clone(), Name::from(&*field.ident.as_str()))
                                .to_term(),
                        );

                        field_var
                    })
                    .collect::<Vec<Loc<Name>>>();

                // build a constructor with the struct name and fields
                //
                // TODO(maemre): order the fields?
                Some(C(Ctor::simple(
                    Name::from(struct_name),
                    field_terms,
                    vec![],
                )))
            },
            PatKind::TupleStruct(name, fields, ignore_rest) => {
                if ignore_rest.is_some() {
                    panic!(
                        "struct patterns with some fields ignored are not supported: {:#?}",
                        pat
                    );
                }

                let struct_name = Self::qpath_to_name(ctx, name, pat.hir_id);
                let field_terms = fields
                    .iter()
                    .map(|field| {
                        let (field_term, field_ctx) = self.analyze_pattern(ctx, field);
                        extended_ctx = field_ctx;

                        let synthetic_var = Loc::Synthetic(field.hir_id);

                        match field_term {
                            Some(S(LV(var))) => var,
                            Some(term) => {
                                self.taint_analysis
                                    .add_flow(term, S(LV(synthetic_var.clone())));
                                synthetic_var
                            },
                            None => synthetic_var,
                        }
                    })
                    .collect::<Vec<Loc<Name>>>();

                // build a constructor with the struct name and fields
                //
                // TODO(maemre): order the fields?
                Some(C(Ctor::simple(
                    Name::from(struct_name),
                    field_terms,
                    vec![],
                )))
            },
            PatKind::Or(_sub_patterns) => None, // or pattern cannot bind new variables
            PatKind::Path(_name) => None,       // constants cannot bind new variables
            PatKind::Tuple(elems, None) => {
                let struct_name = format!("tuple${}", elems.len());
                let field_terms = elems
                    .iter()
                    .map(|field| {
                        let (field_term, field_ctx) = self.analyze_pattern(ctx, field);
                        extended_ctx = field_ctx;

                        let synthetic_var = Loc::Synthetic(field.hir_id);

                        match field_term {
                            Some(S(LV(var))) => var,
                            Some(term) => {
                                self.taint_analysis
                                    .add_flow(term, S(LV(synthetic_var.clone())));
                                synthetic_var
                            },
                            None => synthetic_var,
                        }
                    })
                    .collect::<Vec<Loc<Name>>>();
                Some(C(Ctor::simple(
                    Name::from(struct_name),
                    field_terms,
                    vec![],
                )))
            },
            PatKind::Tuple(_, Some(_)) => {
                panic!("tuple patterns with `..` are not supported: {:?}", pat.span)
            },
            PatKind::Box(_sub_pattern) => panic!("box patterns are not supported"),
            PatKind::Ref(_sub_pattern, _mutbl) => {
                panic!("ref patterns are not supported: {:?}", pat.span)
            },
            PatKind::Lit(_) => None,
            PatKind::Range(_lhs, _rhs, _inclusive) => panic!("range patterns are not supported"),
            PatKind::Slice(_before, _middle, _after) => panic!("slice patterns are not supported"),
        };

        (term, extended_ctx)
    }

    fn analyze_block<'a, 'tcx>(
        &mut self,
        ctx: &AnalysisCtx<'a, 'tcx>,
        block: &'tcx Block<'tcx>,
    ) -> Option<Term<Loc<Name>>> {
        let mut local_ctx = ctx.clone(); // TODO: don't do this clone if not necessary
        for stmt in block.stmts {
            if let Some(extended_ctx) = self.analyze_stmt(&local_ctx, stmt) {
                local_ctx = extended_ctx;
            }
        }

        // Analyze the expression at the end, the resulting
        // location for this block exists only if there is an
        // end expression
        block
            .expr
            .and_then(|e| self.analyze_expr(&local_ctx, e, ExprCtx::default()))
    }

    /// Analyze given expression
    ///
    /// # Arguments from `expr_ctx` (expression context)
    /// ## `is_assignee`
    /// Whether the current expression is directly on the
    /// left-hand side of an assignment (but not a combined
    /// assignment). This is useful for distinguishing writes to
    /// unions from reads. For example, when analyzing `x.foo.bar
    /// = z`, only `x.foo.bar` will have this flag set to `true`, and
    /// `x.foo`, `x`, and `z` will have this flag set to `false`.
    fn analyze_expr<'a, 'tcx>(
        &mut self,
        ctx: &AnalysisCtx<'a, 'tcx>,
        expr: &'tcx Expr<'tcx>,
        expr_ctx: ExprCtx,
    ) -> Option<Term<Loc<Name>>> {
        let expr_loc = Loc::Synthetic(expr.hir_id);
        let expr_term = expr_loc.clone().to_term();
        let result = match &expr.kind {
            ExprKind::Box(_) => panic!("boxes are not supported"),
            ExprKind::ConstBlock(_) => panic!("ConstBlock are not supported"),
            ExprKind::Array(elems) => {
                // We add ∀ e ∈ elems. expr ⊆ ref(e; e)
                //
                // Effectively treating arrays like pointers/mutable
                // containers because arrays can be mutated and
                // subtyping (adding subset constraints on
                // assignments) don't work well with that.
                //
                // See "Partial online cycle elimination in inclusion
                // constraint graphs" by Fähndrich et al. for a
                // detailed argument of why ref has both a covariant
                // and a contravariant argument.

                for e in elems.iter() {
                    if let Some(elem_term) = self.analyze_expr(ctx, e, ExprCtx::default()) {
                        let elem_var = if let S(x) = elem_term {
                            x
                        } else {
                            // the element is a complex term, create
                            // an intermediary variable
                            let x = LV(Loc::fresh());
                            // equate `x` to the element's term by
                            // creating a cycle
                            self.taint_analysis
                                .add_flow(S(x.clone()), elem_term.clone());
                            self.taint_analysis
                                .add_flow(elem_term.clone(), S(x.clone()));
                            x
                        };

                        self.taint_analysis.add_flow(
                            expr_term.clone(),
                            mk_ref(elem_var.clone(), elem_var.clone()),
                        );
                    }
                }
                Some(expr_term)
            },
            ExprKind::Call(fun, args) => {
                let callee_name = match self.analyze_expr(
                    ctx,
                    fun,
                    ExprCtx {
                        is_assignee: false,
                        is_callee: true,
                    },
                ) {
                    Some(S(LV(Loc::Var(fn_name)))) => Some(fn_name),
                    _ => {
                        /*log::warn!(
                            "function pointer called at {:?}. The analysis will be unsound and imprecise!",
                            fun.span,
                        );*/
                        self.call_graph
                            .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::ExternCall);
                        None
                    },
                };

                for (i, arg) in args.iter().enumerate() {
                    // arg_i ⊆ param_i
                    if let Some(arg_term) = self.analyze_expr(ctx, arg, ExprCtx::default()) {
                        if let Some(c) = callee_name.clone() {
                            if i == 0 {
                                if FNS_REQUIRING_RAW_PTR.contains(&c) {
                                    // the function requires a raw pointer as its first argument
                                    let arg_loc = match arg_term.clone() {
                                        S(LV(loc)) => loc,
                                        t => {
                                            let loc = Loc::fresh();
                                            self.taint_analysis.add_flow(t, loc.clone().to_term());
                                            loc
                                        },
                                    };
                                    self.taint_analysis
                                        .add_poison(PoisonKind::MiscSink, arg_loc);
                                }
                            }

                            self.taint_analysis
                                .add_flow(arg_term, S(LV(Loc::Param(c, i))));
                        } else {
                            // there is no callee name, so the callee
                            // must be a function pointer. Mark the
                            // parameters as potentially extern
                            let arg_loc = if let Some(loc) = arg_term.get_lv() {
                                loc.clone()
                            } else {
                                // todo: create the syntetic location for
                                // argument expression and re-bind the
                                // expression to that location
                                todo!()
                            };

                            self.taint_analysis
                                .add_poison(PoisonKind::ExternCallParam, arg_loc);
                        }
                    }
                }

                // is this a special function we can handle?
                let is_special = callee_name
                    .as_ref()
                    .map_or(false, |c| qual_fn_we_can_handle(&*c));

                // Add call to the call graph, we don't resolve
                // unknown functions or variables (e.g. closures) so
                // the call graph is going to be unsound
                callee_name.clone().map(|c| {
                    self.call_graph.add_call(ctx.fn_name.clone(), c, is_special);
                });

                if let Some(callee) = callee_name.clone() {
                    if !is_special && is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr)) {
                        self.taint_analysis
                            .add_poison(PoisonKind::VoidSource, Loc::RetVal(callee));
                    }
                }

                if let Some(c) = callee_name.clone() {
                    if c.as_ref().ends_with("::malloc") || c.as_ref().ends_with("::calloc") {
                        // Create a tagged set variable for each call
                        // site of malloc
                        Some(Loc::Malloc(expr.hir_id).to_term())
                    } else if is_special {
                        // do not let the special function return
                        // values flow into sinks, and return a unique
                        // variable for the call site instead

                        // Check if this is a call to transmute, if so
                        // add poison. TODO: use a different flag for
                        // this.
                        if POISON_SIGS_OF_FN_PTRS.load(Ordering::Relaxed) {
                            self.taint_analysis
                                .add_poison(PoisonKind::MiscSource, expr_loc);
                        }
                        Some(expr_term)
                    } else {
                        Some(Loc::RetVal(c).to_term())
                    }
                } else {
                    // there is no callee name, so the callee
                    // must be a function pointer. Mark the
                    // return value as potentially extern
                    self.taint_analysis
                        .add_poison(PoisonKind::ExternCallReturn, expr_loc);
                    Some(expr_term)
                }
            },
            ExprKind::MethodCall(_fun_with_generics, _, args, _) => {
                if let Some(callee_def_id) =
                    ctx.ctx.typeck_results().type_dependent_def_id(expr.hir_id)
                {
                    let callee_name = Name::from(get_def_qname(ctx.ctx, callee_def_id));

                    /* println!(
                        "{} {}",
                        format!("METHOD CALLEE: {}", callee_name).red(),
                        format!("{:?}", fun_with_generics).bold()
                    ); */

                    // Also build call graph
                    //
                    // TODO: we don't resolve trait methods, the
                    // initial C program is supposed to not generate
                    // them, we may need that when we introduce other
                    // approaches that generate trait-based calls.
                    self.call_graph.add_call(
                        ctx.fn_name.clone(),
                        callee_name.clone(),
                        qual_fn_we_can_handle(&callee_name),
                    );

                    let loc = if let Some(data_flows) = Self::intrinsics_data_flow(&callee_name) {
                        // this is a compiler intrinsic, create a
                        // synthetic node for this call, then create
                        // constraints for the data flow edges for
                        // this call

                        // analyze the arguments and collect their terms
                        let arg_locs: Vec<Option<Term<Loc<Name>>>> = args
                            .iter()
                            .map(|arg| self.analyze_expr(ctx, arg, ExprCtx::default()))
                            .collect();

                        for (source, target) in data_flows {
                            let get_term = |node: &DataFlowNode| match node {
                                DataFlowNode::RetVal => Some(&expr_term),
                                DataFlowNode::Param(i) => arg_locs[*i].as_ref(),
                            };

                            if let (Some(source_term), Some(target_term)) =
                                (get_term(source), get_term(target))
                            {
                                // There are terms for both ends of
                                // this edge, add the corresponding
                                // constraint
                                self.taint_analysis
                                    .add_flow(source_term.clone(), target_term.clone());
                            }
                        }

                        if PTR_ARITH_METHODS.contains(&callee_name) {
                            // poison all arguments and the return value with use in pointer arithmetic
                            self.taint_analysis
                                .add_poison(PoisonKind::PtrArith, expr_loc.clone());
                            arg_locs.iter().flatten().for_each(|arg| {
                                let arg_term = arg.clone();
                                let arg_loc = match arg_term {
                                    S(LV(loc)) => loc,
                                    _ => unreachable!(),
                                };

                                self.taint_analysis
                                    .add_poison(PoisonKind::PtrArithSink, arg_loc)
                            });
                        }

                        expr_loc
                    } else {
                        // this is not an intrinsic function
                        for (i, arg) in args.iter().enumerate() {
                            // arg_i ⊆ param_i
                            if let Some(arg_term) = self.analyze_expr(ctx, arg, ExprCtx::default())
                            {
                                self.taint_analysis
                                    .add_flow(arg_term, S(LV(Loc::Param(callee_name.clone(), i))));
                            }
                        }

                        Loc::RetVal(callee_name)
                    };

                    if is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr)) {
                        self.taint_analysis
                            .add_poison(PoisonKind::VoidSource, loc.clone());
                    }

                    Some(loc.to_term())
                } else {
                    panic!("Cannot get the Def ID for method call node {:?}", expr)
                }
            },
            ExprKind::Tup(_elems) => todo!("explicit tuples are not implemented yet"),
            ExprKind::Binary(_op, lhs, rhs) => {
                // TODO: check if ptr arithmetic (by checking operands), add poison if so

                // Add constraints lhs ⊆ expr, rhs ⊆ expr
                if let Some(lhs_loc) = self.analyze_expr(ctx, lhs, ExprCtx::default()) {
                    self.taint_analysis.add_flow(lhs_loc, expr_term.clone());
                }
                if let Some(rhs_loc) = self.analyze_expr(ctx, rhs, ExprCtx::default()) {
                    self.taint_analysis.add_flow(rhs_loc, expr_term.clone());
                }

                Some(expr_term)
            },
            ExprKind::Unary(op, arg) => {
                let arg_term = self.analyze_expr(ctx, arg, ExprCtx::default());
                // refine the taint analysis based on whether any
                // unary operators are involved in dereferencing
                if *op == UnOp::Deref {
                    // mark unsafe behavior if this is dereferencing a
                    // raw pointer
                    if ctx
                        .ctx
                        .typeck_results()
                        .expr_ty_adjusted(arg)
                        .is_unsafe_ptr()
                    {
                        self.call_graph
                            .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::RawPtrDeref);
                    }

                    // ref(X, X) is the reference location containing
                    // X (inverse of points-to set)
                    //
                    // arg ⊆ ref(expr; 0)
                    let ref_term = mk_ref(expr_term.clone().extract_simple(), EmptySet);
                    self.taint_analysis.add_flow(arg_term.unwrap(), ref_term);
                    Some(expr_term)
                } else {
                    arg_term
                }
            },
            ExprKind::Lit(lit) => {
                // Mark string literals as something we don't handle
                match lit.node {
                    LitKind::Str(..) | LitKind::ByteStr(..) => {
                        self.taint_analysis
                            .add_poison(PoisonKind::MiscSource, expr_loc.clone());
                    },
                    _ => {},
                }

                Some(expr_term)
            },
            ExprKind::Cast(sub, _ty) => {
                let ty = ctx.ctx.typeck_results().expr_ty(expr);
                // type of the subexpression
                let sub_ty = ctx.ctx.typeck_results().expr_ty_adjusted(sub);
                let sub_result = self.analyze_expr(ctx, sub, expr_ctx.with_callee(false));
                let cast_var = Loc::Synthetic(expr.hir_id);

                // check if this is a function pointer, if so remember
                // the function used as a pointer.
                //
                // N.B. this check is disabled because we reason about
                // this in ExprKind::Path already
                /*
                if ty.is_fn_ptr() || sub_ty.is_fn() {
                    if let ExprKind::Path(qpath) = &sub.kind {
                        // this is a function directly cast to/from a
                        // pointer. remember its use as a fn pointer
                        let path_lv = Self::qpath_to_loc(ctx, qpath, sub.hir_id);
                        if let Res::Def(DefKind::Fn, _) = ctx.ctx.qpath_res(qpath, expr.hir_id) {
                        let fn_name = Self::qpath_to_name(ctx, qpath, sub.hir_id);
                        self.call_graph
                            .used_as_fn_pointer
                            .insert(fn_name);
                        }
                    }
                }*/

                // Check if sub_ty and ty mismatch modulo mutability
                if POISON_UNRELATED_TYPE_CASTS.load(Ordering::Relaxed) {
                    if ty.is_unsafe_ptr() || sub_ty.peel_refs().is_unsafe_ptr() {
                        // Find the ultimate pointee types, peeling nested pointers
                        let mut pointee = ty;
                        let mut sub_pointee = sub_ty;
                        while pointee.is_unsafe_ptr() && sub_pointee.is_unsafe_ptr() {
                            pointee = pointee.builtin_deref(true).unwrap().ty;
                            sub_pointee = sub_pointee.builtin_deref(true).unwrap().ty;
                        }

                        // If the pointees mismatch, poison this cast
                        if Type::from_ty(ctx.ctx, pointee) != Type::from_ty(ctx.ctx, sub_pointee) {
                            let dummy = Loc::fresh();
                            self.taint_analysis
                                .add_poison(PoisonKind::MiscSource, cast_var.clone());
                            self.taint_analysis
                                .add_flow(sub_result.clone().unwrap(), dummy.clone().to_term());
                            self.taint_analysis.add_poison(PoisonKind::MiscSink, dummy);
                        }
                    }
                }

                if is_void_ptr(ctx.ctx, ty) {
                    // this is a cast to a void pointer,
                    // create a new synthetic variable, and
                    // connect sinks & sources

                    if let Some(sub_term) = sub_result {
                        let dummy = Loc::fresh();
                        self.taint_analysis
                            .add_flow(sub_term, dummy.clone().to_term());
                        self.taint_analysis
                            .add_poison(PoisonKind::VoidSink, dummy.clone());
                        self.taint_analysis
                            .add_flow(dummy.to_term(), cast_var.clone().to_term());
                    }
                    self.taint_analysis
                        .add_poison(PoisonKind::VoidSource, cast_var.clone());

                    if matches!(Type::from_ty(ctx.ctx, ty), Type::Ptr(_, box Type::Ptr(..))) {
                        // this is a nested pointer, taint the inner
                        // pointer too, because we can't have a
                        // reference behind a raw pointer
                        //
                        // TODO: do this recursively for multiple levels of nesting
                        //
                        // We are injecting the taint using a dummy
                        // variable because the constraint solver does
                        // not support projections. A better way of
                        // doing this would be to remember this taint
                        // and to add it when solving the constraint
                        // system.
                        let dummy_for_ptsto = Loc::fresh();
                        self.taint_analysis.add_flow(
                            mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                            cast_var.clone().to_term(),
                        );
                        self.taint_analysis
                            .add_poison(PoisonKind::MiscSource, dummy_for_ptsto);
                    }
                    Some(cast_var.to_term())
                } else if is_void_ptr(ctx.ctx, sub_ty) {
                    // Don't taint this cast if this is immediately
                    // from a malloc
                    if matches!(sub_result, Some(S(LV(Loc::Malloc(_))))) {
                        sub_result
                    } else {
                        // this is a cast from a void pointer, add a source for the cast result
                        self.taint_analysis
                            .add_poison(PoisonKind::VoidSource, cast_var.clone());

                        if matches!(Type::from_ty(ctx.ctx, ty), Type::Ptr(_, box Type::Ptr(..))) {
                            // this is a nested pointer, taint the inner
                            // pointer too, because we can't have a
                            // reference behind a raw pointer
                            //
                            // TODO: do this recursively for multiple levels of nesting
                            //
                            // We are injecting the taint using a dummy
                            // variable because the constraint solver does
                            // not support projections. A better way of
                            // doing this would be to remember this taint
                            // and to add it when solving the constraint
                            // system.
                            let dummy_for_ptsto = Loc::fresh();
                            self.taint_analysis.add_flow(
                                cast_var.clone().to_term(),
                                mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                            );
                            self.taint_analysis
                                .add_poison(PoisonKind::MiscSink, dummy_for_ptsto);
                        }
                        Some(cast_var.to_term())
                    }
                } else {
                    sub_result
                }
            },
            ExprKind::Type(_expr, _ty) => {
                panic!("type references are not supported, at: {:?}", expr.span)
            },
            ExprKind::DropTemps(inner) => self.analyze_expr(ctx, inner, ExprCtx::default()),
            ExprKind::Let(..) => panic!("Let are not supported"),
            ExprKind::If(cond, then_expr, None) => {
                // TODO
                if let Some(cond_term) = self.analyze_expr(ctx, cond, ExprCtx::default()){
                    self.taint_analysis.add_flow(cond_term, expr_term.clone());
                } 
                else if let Some(then_term) = self.analyze_expr(ctx, then_expr, ExprCtx::default()) {
                    // then_branch ⊆ result
                    self.taint_analysis.add_flow(then_term, expr_term.clone());
                }
                Some(expr_term)
            },
            ExprKind::If(cond, then_expr, Some(else_expr)) => {
                // TODO
                if let Some(cond_term) = self.analyze_expr(ctx, cond, ExprCtx::default()){
                    self.taint_analysis.add_flow(cond_term, expr_term.clone());
                } 
                else if let Some(then_term) = self.analyze_expr(ctx, then_expr, ExprCtx::default()) {
                    // then_branch ⊆ result
                    self.taint_analysis.add_flow(then_term, expr_term.clone());
                }
                else if let Some(else_term) = self.analyze_expr(ctx, else_expr, ExprCtx::default()) {
                    // then_branch ⊆ result
                    self.taint_analysis.add_flow(else_term, expr_term.clone());
                }
                Some(expr_term)
            }
            // ExprKind::Let(..) => panic!("Let are not supported"),
            ExprKind::Loop(body, _label, _source, _span) => {
                self.analyze_block(ctx, body);
                None
            },
            ExprKind::Match(scrutinee, arms, _source) => {
                let maybe_scrutinee_term = self.analyze_expr(ctx, scrutinee, ExprCtx::default());
                let match_term = S(LV(Loc::Synthetic(expr.hir_id)));
                for arm in *arms {
                    // TODO: extend the context with the arm's pattern
                    let (pattern_term, extended_ctx) = self.analyze_pattern(ctx, arm.pat);
                    // flow information from scrutinee to each arm's pattern
                    maybe_scrutinee_term.as_ref().map(|scrutinee_term| {
                        pattern_term.map(|pat_term| {
                            self.taint_analysis
                                .add_flow(scrutinee_term.clone(), pat_term);
                        })
                    });
                    // analyze the guard, we don't refine based on the
                    // guard but we are interested in the provenance
                    // of the pointers in the guard
                    if let Some(Guard::If(guard)) = arm.guard {
                        self.analyze_expr(&extended_ctx, guard, ExprCtx::default());
                    }
                    if let Some(arm_term) =
                        self.analyze_expr(&extended_ctx, arm.body, ExprCtx::default())
                    {
                        // arm_i ⊆ result
                        self.taint_analysis.add_flow(arm_term, match_term.clone());
                    }
                }
                Some(match_term)
            },
            ExprKind::Closure(_capture_by, _fn_decl, _body_id, _, _movability) => {
                log::error!("closures are not implemented yet");
                None
            },
            ExprKind::Block(block, _label) => self.analyze_block(ctx, block),
            ExprKind::Assign(lhs, rhs, _) => {
                let lhs_term = self.analyze_expr(
                    ctx,
                    lhs,
                    ExprCtx {
                        is_assignee: true,
                        is_callee: false,
                    },
                );
                let rhs_term = self.analyze_expr(ctx, rhs, ExprCtx::default());
                lhs_term.map(|l| {
                    // flow rhs ⊆ lhs
                    rhs_term.map(|r| self.taint_analysis.add_flow(r, l))
                });
                None // assignments produce ()
            },
            ExprKind::AssignOp(_op, lhs, rhs) => {
                // TODO: check for ptr arith ops
                let lhs_term = self.analyze_expr(ctx, lhs, ExprCtx::default());
                let rhs_term = self.analyze_expr(ctx, rhs, ExprCtx::default());
                lhs_term.map(|l| {
                    // flow rhs ⊆ lhs
                    rhs_term.map(|r| self.taint_analysis.add_flow(r, l))
                });
                None // assignments produce ()
            },
            ExprKind::Field(parent, field) => {
                self.analyze_expr(ctx, parent, ExprCtx::default());

                // get parent type, then build Access(ParentType, field)
                //
                // we use the type debug printer to get a normalized type representation

                let parent_ty = ctx.ctx.typeck_results().expr_ty_adjusted(parent);

                // check if the parent is a union
                let adt_def = parent_ty.ty_adt_def().unwrap();

                if (!expr_ctx.is_assignee) && adt_def.is_union() {
                    self.call_graph
                        .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::ReadFromUnion);
                }

                let def_id = adt_def.did;
                let loc = Loc::Access(
                    Name::from(get_def_qname(ctx.ctx, def_id)),
                    Name::from(format!("{}", field)),
                );
                if is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr)) {
                    self.taint_analysis
                        .add_poison(PoisonKind::VoidSource, loc.clone());
                }
                Some(loc.to_term())
            },
            ExprKind::Index(parent, index) => {
                // flow pointers from the type of parent?
                // similar to dereferencing from it

                let e = expr_term.clone().extract_simple();

                // Recursively analyze the index expression
                self.analyze_expr(ctx, index, ExprCtx::default());

                // Add constraint parent ⊆ ref(expr; expr)
                if let Some(parent_loc) = self.analyze_expr(ctx, parent, ExprCtx::default()) {
                    self.taint_analysis
                        .add_flow(parent_loc, mk_ref(e.clone(), e));
                }

                if is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr)) {
                    self.taint_analysis
                        .add_poison(PoisonKind::VoidSource, expr_loc.clone());
                }

                Some(expr_term)
            },
            ExprKind::Path(qpath) => {
                // TODO: add subset constraints for unresolved paths to resolve trait methods
                let path_lv = Self::qpath_to_loc(ctx, qpath, expr.hir_id);

                match ctx.ctx.qpath_res(qpath, expr.hir_id) {
                    Res::Def(DefKind::Static, def_id) => {
                        // this is a global variable
                        if ctx.tcx().static_mutability(def_id) == Some(Mutability::Mut) {
                            self.call_graph
                                .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::MutGlobalAccess);
                        }
                    },
                    Res::Def(DefKind::Fn, _) if !expr_ctx.is_callee => {
                        // this is a function that is used in a
                        // non-function context. Remember this
                        // function to freeze its function signature
                        // later on
                        self.call_graph
                            .used_as_fn_pointer
                            .insert(Self::qpath_to_name(ctx, qpath, expr.hir_id));
                    },
                    _ => (),
                }
                if is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr)) {
                    self.taint_analysis
                        .add_poison(PoisonKind::VoidSource, path_lv.clone());
                }
                Some(path_lv.to_term())
            },
            ExprKind::AddrOf(_borrow_kind, mutbl, subexpr) => {
                // if we are taking a mutable borrow, then it can be
                // used for an assignment later on, so set the flag to true
                let subexpr_term = self.analyze_expr(
                    ctx,
                    subexpr,
                    ExprCtx::default().with_assignee(*mutbl == Mutability::Mut),
                );

                subexpr_term.map(|t| {
                    // add `ref(subexpr; subexpr) ⊆ expr` and return
                    // `expr` so that we return a variable that can be
                    // checked against poisons
                    self.taint_analysis.add_flow(
                        mk_ref(t.clone().extract_simple(), t.extract_simple()),
                        expr_term.clone(),
                    );
                    expr_term
                })
            },
            ExprKind::Break(_, _) => None,
            ExprKind::Continue(_) => None,
            ExprKind::Ret(None) => None,
            ExprKind::Ret(Some(expr)) => {
                // expr ⊆ ret_f
                //
                // the return statement does not produce a value so
                // there is no location to return

                if let Some(expr_term) = self.analyze_expr(ctx, expr, ExprCtx::default()) {
                    let ret_loc = Loc::RetVal(ctx.fn_name.clone());
                    self.taint_analysis.add_flow(expr_term, S(LV(ret_loc)));
                }
                None
            },
            ExprKind::InlineAsm(_) => {
                // panic!("inline assembly is not supported")
                Some(expr_term)
            },
            ExprKind::LlvmInlineAsm(_) => {
                log::warn!(
                    "LLVM inline assembly is not supported. Pointer provenance results will be imprecise"
                );
                self.call_graph
                    .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::InlineAsm);
                None
            },
            ExprKind::Struct(name, fields, None) => {
                let struct_name = Self::qpath_to_name(ctx, name, expr.hir_id);
                let field_terms = fields
                    .iter()
                    .map(|field| {
                        let field_term = self
                            .analyze_expr(ctx, field.expr, ExprCtx::default())
                            .unwrap_or(S(LV(Loc::Synthetic(field.expr.hir_id))));

                        let field_var = match field_term {
                            S(LV(var)) => var,
                            _ => {
                                let synthetic_var = Loc::Synthetic(field.expr.hir_id);
                                self.taint_analysis
                                    .add_flow(field_term, S(LV(synthetic_var.clone())));
                                synthetic_var
                            },
                        };

                        // add data flow from the field to the access
                        // LV because this analysis is field-based
                        self.taint_analysis.add_flow(
                            field_var.clone().to_term(),
                            Loc::Access(struct_name.clone(), Name::from(&*field.ident.as_str()))
                                .to_term(),
                        );

                        field_var
                    })
                    .collect::<Vec<Loc<Name>>>();

                // build a constructor with the struct name and fields
                //
                // TODO(maemre): order the fields?
                Some(C(Ctor::simple(struct_name, field_terms, vec![])))
            },
            ExprKind::Struct(_name, _fields, Some(_base)) => panic!(
                "struct expressions with bases are not supported: {:?}",
                expr
            ),
            ExprKind::Repeat(expr, _n_times) => {
                // deliberately lose the array information and
                // propagate the taint from the repeated expression
                self.analyze_expr(ctx, expr, ExprCtx::default())
            },
            ExprKind::Yield(_, _) => panic!("yield is not supported"),
            ExprKind::Err => panic!("there is an error node in the HIR"),
            // _ => unimplemented!(),
        };

        if let Some(S(LV(lv))) = &result {
            self.taint_analysis.declare_owner(&lv, &ctx.fn_name);
        }

        if let Some(term) = &result {
            // Repacking here wastefully creates a copy of the string
            // version.
            //
            // TODO(maemre): repack early and pass around u32 terms
            // inside analyze_expr.
            self.taint_analysis
                .bind_expr_to_term(expr.hir_id, term.clone());
        }

        result
    }

    fn analyze_stmt<'a, 'tcx>(
        &mut self,
        ctx: &AnalysisCtx<'a, 'tcx>,
        stmt: &'tcx Stmt<'tcx>,
    ) -> Option<AnalysisCtx<'a, 'tcx>> {
        match &stmt.kind {
            StmtKind::Local(let_stmt) => {
                let (pat_term, extended_ctx) = self.analyze_pattern(ctx, let_stmt.pat);
                let expr_term = let_stmt
                    .init
                    .and_then(|e| self.analyze_expr(ctx, e, ExprCtx::default()));

                if let Some(pat_term) = pat_term {
                    if let Some(expr_term) = expr_term {
                        self.taint_analysis.add_flow(expr_term, pat_term);
                    }
                }

                Some(extended_ctx)
            },
            StmtKind::Item(_id) => {
                // TODO: visit this item by getting the item from item
                // ID then visiting the static or constant value
                // inside, and visiting the owner to get the variable
                log::warn!(
                    "Skipping language item (possibly a static variable) at: {:?}",
                    stmt.span
                );
                None
            },
            StmtKind::Expr(expr) => {
                self.analyze_expr(ctx, expr, ExprCtx::default());
                None
            },
            StmtKind::Semi(expr) => {
                self.analyze_expr(ctx, expr, ExprCtx::default());
                None
            },
        }
    }

    fn analyze_body<'tcx>(
        &mut self,
        fn_name: Name,
        Body { params, value, .. }: &'tcx Body<'tcx>,
        ctx: &LateContext<'tcx>,
        is_main: bool,
    ) {
        // add constraints for each parameter, then add the variables
        // inside params to Γ
        let mut ctx = AnalysisCtx::new(fn_name, ctx);

        for (i, param) in params.iter().enumerate() {
            // analyze each pattern to extend locals
            let (param_term, new_ctx) = self.analyze_pattern(&ctx, &param.pat);
            ctx = new_ctx;
            // connect the parameter declared in the pattern to the formal parameter
            if let Some(param) = param_term {
                // param_i ⊆ param term
                let param_loc = S(LV(Loc::Param(ctx.fn_name.clone(), i)));

                self.taint_analysis.add_flow(param_loc, param);
            }
        }

        // if this is the main function, taint argv and ref⁻¹(argv)
        if is_main {
            let argv = Loc::Param(ctx.fn_name.clone(), 1);
            // create a variable for the points-to set of argv
            let argv_deref = Loc::fresh();
            self.taint_analysis.add_flow(
                mk_ref(argv_deref.clone().to_st(), argv_deref.clone().to_st()),
                argv.clone().to_term(),
            );

            self.taint_analysis
                .add_poison(PoisonKind::MiscSource, argv.clone());
            self.taint_analysis.add_poison(PoisonKind::MiscSink, argv);
            self.taint_analysis
                .add_poison(PoisonKind::MiscSource, argv_deref.clone());
            self.taint_analysis
                .add_poison(PoisonKind::MiscSink, argv_deref);
        }

        let mut inject_void = |loc: Loc<Name>| {
            self.taint_analysis
                .add_poison(PoisonKind::VoidSink, loc.clone());
            self.taint_analysis.add_poison(PoisonKind::VoidSource, loc);
        };

        // add `void *` poison to the parameters and the return value
        for (i, param) in params.iter().enumerate() {
            let ty = ctx.ctx.typeck_results().pat_ty(param.pat);
            if let TyKind::RawPtr(TypeAndMut { ty, .. }) = ty.kind() {
                if format!("{}", ty) == "std::ffi::c_void" {
                    inject_void(Loc::Param(ctx.fn_name.clone(), i));
                }
            }
        }

        let return_ty = ctx.ctx.typeck_results().expr_ty_adjusted(&value);
        if let TyKind::RawPtr(TypeAndMut { ty, .. }) = return_ty.kind() {
            if format!("{}", ty) == "std::ffi::c_void" {
                inject_void(Loc::RetVal(ctx.fn_name.clone()));
            }
        }

        // analyze the body expression
        self.analyze_expr(&ctx, &value, ExprCtx::default());
    }

    fn process_foreign_fn<'tcx>(&mut self, fn_name: Name, fn_decl: &'tcx FnDecl<'tcx>) {
        let unqual_name = Name::from(fn_name.rsplit_once("::").unwrap().1);
        if let Some(true_name) = self.call_graph.defined_fns.get(&unqual_name).cloned() {
            self.connect_fns(fn_name, true_name, fn_decl.inputs.len());
        } else {
            let arity = if fn_decl.c_variadic {
                // For variadic C functions, assume the maximum arity
                // is 127, as that is the limit the C standard
                // requires 127 parameters to be supported
                22
            } else {
                fn_decl.inputs.len()
            };
            self.extern_arity.insert(fn_name, arity);
        }
    }

    fn add_extern_poison(&mut self, extern_fn_name: Name, arity: usize) {
        for i in 0..arity {
            // add each parameter as a sink
            self.taint_analysis.add_poison(
                PoisonKind::ExternCallParam,
                Loc::Param(extern_fn_name.clone(), i),
            );
        }
        // add the return value as a source
        self.taint_analysis
            .add_poison(PoisonKind::ExternCallReturn, Loc::RetVal(extern_fn_name));
    }

    fn connect_fns(&mut self, extern_fn_name: Name, true_fn_name: Name, arity: usize) {
        for i in 0..arity {
            // add each parameter as a sink
            self.taint_analysis.add_flow(
                S(LV(Loc::Param(extern_fn_name.clone(), i))),
                S(LV(Loc::Param(true_fn_name.clone(), i))),
            );
        }
        // add the return value as a source
        self.taint_analysis.add_flow(
            S(LV(Loc::RetVal(true_fn_name))),
            S(LV(Loc::RetVal(extern_fn_name))),
        );
    }
}

impl LintPass for PtrProvenancePass {
    fn name(&self) -> &'static str {
        "PtrProvenancePass"
    }
}

impl<'tcx> LateLintPass<'tcx> for PtrProvenancePass {
    fn check_fn_post(
        &mut self,
        ctx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        hir_id: HirId,
    ) {
        if matches!(kind, FnKind::Closure) {
        // if matches!(kind, FnKind::Closure(_)) {
            log::warn!("Skipping closure at {:?}", span);
            return;
        }

        let def_id = DefId {
            krate: LOCAL_CRATE,
            index: ctx.tcx.hir().local_def_id(hir_id).local_def_index,
        };
        let def_qname = get_def_qname(ctx, def_id);
        let unqual_name = match kind {
            FnKind::ItemFn(id, ..) => id.as_str(),
            FnKind::Method(id, ..) => id.as_str(),
            FnKind::Closure => unreachable!(),
        };

        self.call_graph
            .defined_fns
            .insert(Name::from(&*unqual_name), def_qname.clone());

        if span.in_derive_expansion() {
            return;
        }

        // add this function to the relevant parts of call graph
        self.call_graph.add_fn_decl(def_qname.clone());

        self.fn_arity.insert(def_qname.clone(), decl.inputs.len());

        let is_main = &*unqual_name == "main_0";
        self.analyze_body(def_qname, body, ctx, is_main);
    }

    fn check_foreign_item(&mut self, ctx: &LateContext<'tcx>, item: &'tcx ForeignItem<'tcx>) {
        use ForeignItemKind::*;

        // add sources and sinks for external functions so we can
        // match the pointers flowing from/into them
        match &item.kind {
            Fn(fn_decl, _param_names, generics) => {
                // make sure that there are no generic type variables declared in foreign function declarations, they are not supported
                let def_id = DefId {
                    krate: LOCAL_CRATE,
                    index: ctx.tcx.hir().local_def_id(item.hir_id()).local_def_index,
                };
                let name = get_def_qname(ctx, def_id);
                assert!(
                    generics.params.iter().all(|param| match &param.kind {
                        GenericParamKind::Lifetime { .. } => true,
                        _ => false,
                    }),
                    "non-lifetime generic variables in the declaration of external function {}",
                    name
                );

                if !qual_fn_we_can_handle(&name) {
                    let unqual_name = Name::from(&*item.ident.as_str());
                    if !self.call_graph.defined_fns.contains_key(&unqual_name) {
                        self.call_graph.extern_fns.insert(unqual_name);
                    }
                    self.process_foreign_fn(name, fn_decl);
                }
            },
            Static(_, _) => {
                // This is an external static variable, poison it only
                // when computing lifetimes. It may be resolved by
                // ResolveImports so it is not poisoned there.
                if ANALYZE_GLOBAL_INITS.load(Ordering::Relaxed) {
                    let def_id = DefId {
                        krate: LOCAL_CRATE,
                        index: ctx.tcx.hir().local_def_id(item.hir_id()).local_def_index,
                    };
                    let name = get_def_qname(ctx, def_id);
                    let loc = Loc::Var(name);
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSource, loc.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSink, loc.clone());
                    // Also poison the points-to set.
                    //
                    // TODO: do this only if the type is a nested
                    // pointer (can't know this because the semantic
                    // types are not available at this point).
                    let dummy_for_ptsto = Loc::fresh();
                    self.taint_analysis.add_flow(
                        mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                        loc.to_term(),
                    );
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSource, dummy_for_ptsto.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSink, dummy_for_ptsto);
                }
            },
            _ => {},
        }
    }

    fn check_body_post(&mut self, ctx: &LateContext<'tcx>, body: &'tcx Body<'tcx>) {
        if ANALYZE_GLOBAL_INITS.load(Ordering::Relaxed) {
            let body_id = body.id();
            let hir_map = ctx.tcx.hir();
            let owner = hir_map.body_owner(body_id);
            let owner_def_id = hir_map.body_owner_def_id(body_id);
            if !hir_map.body_owner_kind(owner).is_fn_or_closure() {
                // Use this to analyze only the body of global variable initializers.
                let name = Name::from(get_def_qname(ctx, owner_def_id.to_def_id()));
                self.analyze_body(name, body, ctx, false);
            }
        }
    }

    fn check_item_post(&mut self, ctx: &LateContext<'tcx>, item: &Item) {
        use ItemKind::*;

        let def_id = DefId {
            krate: LOCAL_CRATE,
            index: ctx.tcx.hir().local_def_id(item.hir_id()).local_def_index,
        };

        let name = || Name::from(get_def_qname(ctx, def_id));

        match &item.kind {
            // mutable global variable
            Static(ty, Mutability::Mut, _) => {
                // mark this as a miscellaneous source/sink of unsafe data flow
                let path_lv = Loc::Var(name());
                self.taint_analysis
                    .add_poison(PoisonKind::MiscSource, path_lv.clone());
                self.taint_analysis
                    .add_poison(PoisonKind::MiscSink, path_lv.clone());
                // also taint all references this value holds
                if matches!(ty.kind, rustc_hir::TyKind::Ptr(_) | rustc_hir::TyKind::Array(..) | rustc_hir::TyKind::Rptr(..))
                {
                    // create a dummy variable for the pointee
                    let inner = Loc::fresh();
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSource, inner.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSink, inner.clone());
                    self.taint_analysis
                        .add_flow(mk_ref(LV(inner.clone()), LV(inner)), path_lv.to_term());
                }
                // TODO: taint the specific field dereferences as well
            },
            // typedef, map it to the struct type it represents, if it
            // represents a named type directly (rather than a pointer
            // or array for example)
            ItemKind::TyAlias(ty, generics) => {
                assert!(
                    generics.params.is_empty(),
                    "typedef has generics at {:?}",
                    ty.span
                );
                self.taint_analysis
                    .typedefs
                    .insert(name(), Type::from_hir_ty(ctx, ty));
            },
            _ => {},
        }
    }

    fn check_crate_post(&mut self, _: &LateContext<'tcx>) {
        // Add unresolved extern poison
        for (extern_fn, arity) in std::mem::take(&mut self.extern_arity) {
            let unqual_name = Name::from(extern_fn.rsplit_once("::").unwrap().1);
            if let Some(true_name) = self.call_graph.defined_fns.get(&unqual_name).cloned() {
                self.connect_fns(extern_fn, Name::from(true_name), arity);
            } else {
                self.add_extern_poison(extern_fn, arity);
            }
        }

        if POISON_SIGS_OF_FN_PTRS.load(Ordering::Relaxed) {
            for f in &self.call_graph.used_as_fn_pointer {
                for i in 0..self.fn_arity.len() {
                    self.taint_analysis
                        .add_poison(PoisonKind::MiscSource, Loc::Param(f.clone(), i));
                }
                self.taint_analysis
                    .add_poison(PoisonKind::MiscSink, Loc::RetVal(f.clone()));
            }
        }

        // Solve pointer provenance
        profile("constraint solving", || {
            self.taint_analysis.solve().unwrap()
        });

        // Clean up functions declared extern in one module then defined in another module
        let defined_fns = &self.call_graph.defined_fns;
        self.call_graph
            .extern_fns
            .retain(|f| !defined_fns.contains_key(f));

        // Compute the closure of the call graph
        self.call_graph.compute_closure();

        // Update the results
        analysis::replace::<PtrProvenanceAnalysis>(Box::new(self.taint_analysis.clone()));

        if analysis::DEBUG_ANALYSIS_CHANGES {
            // Compare the analysis results point-wise
            if let Some(InitialPtrProvenance {
                ptr_provenance: old_taint_analysis,
            }) = analysis::result::<InitialPtrProvenance>()
            {
                println!("comparing analysis results");
                println!(
                    "constraints: {}",
                    old_taint_analysis.constraints == self.taint_analysis.constraints
                );
                println!(
                    "owners: {}",
                    old_taint_analysis.owners == self.taint_analysis.owners
                );
                println!(
                    "expr_to_term: {}",
                    old_taint_analysis.expr_to_term == self.taint_analysis.expr_to_term
                );
                let poisons_are_same = old_taint_analysis.poisons == self.taint_analysis.poisons;
                println!("poisons: {}", poisons_are_same);
                if !poisons_are_same {
                    // find and print the difference in poisons
                    for (kind, set) in old_taint_analysis.poisons {
                        println!(" - {:?}: ", kind);
                        let missing = set.difference(&self.taint_analysis.poisons[&kind]);
                        missing.for_each(|loc| {
                            println!("    - {:?}", loc);
                        });
                        let added = self.taint_analysis.poisons[&kind].difference(&set);
                        added.for_each(|loc| {
                            println!("    + {:?}", loc);
                        });
                    }
                }
                println!(
                    "typedefs: {}",
                    old_taint_analysis.typedefs == self.taint_analysis.typedefs
                );
            }

            analysis::replace::<InitialPtrProvenance>(Box::new(InitialPtrProvenance {
                ptr_provenance: self.taint_analysis.clone(),
            }));
        }
        analysis::replace::<CallGraph>(Box::new(self.call_graph.clone()));
    }
}
