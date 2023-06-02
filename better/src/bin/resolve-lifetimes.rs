#![feature(rustc_private)]
#![feature(box_patterns)]
#![feature(str_split_once)]
#![feature(map_into_keys_values)]
#![feature(or_insert_with_key)]
#![feature(map_first_last)]
#![feature(bool_to_option)]
#![feature(pattern)]
extern crate env_logger;

#[macro_use]
extern crate clap;

use better::{
    analysis,
    analysis::{
        commons::{Node, *},
        span::*,
        struct_info_pass::StructInfoPass,
    },
    colored::*,
    compiler_interface::*,
    config::*,
    constants::*,
    io::{FileIO, OutputMode},
    lazy_static::lazy_static,
    ptr_arithmetic as ptr_arith,
    ptr_arithmetic::{PointerAddMode, PtrArithExpr, PtrArithOp, PtrArithOpType},
    ptr_provenance::*,
    rustc_ast::ast::LitKind,
    rustc_driver,
    rustc_errors::emitter::{ColorConfig, HumanReadableErrorType},
    rustc_hir,
    rustc_hir::{intravisit::FnKind, Generics, *},
    rustc_interface,
    rustc_lint::{LateContext, LateLintPass, LintContext, LintPass},
    rustc_middle,
    rustc_middle::ty::adjustment::{Adjust, AutoBorrow, PointerCast},
    rustc_session::config::ErrorOutputType,
    rustc_span::{sym, symbol::Ident, BytePos, FileName, FileNameDisplayPreference, Span},
    rustc_target::spec::abi::Abi,
    solver::{SimpleTerm::LV, Term},
    types::{FnSig, Lifetime, *},
    util::{HashMap, HashSet},
};
use itertools::Itertools;
use rustfix::{CodeFix, Replacement, Snippet, Solution, Suggestion};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::RangeBounds,
    panic,
    path::PathBuf,
    process::exit,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Mutex,
    },
};

lazy_static! {
    /// Rustfix suggestions for editing the source files
    ///
    /// File -> expression depth -> vec<suggestion>
    static ref RUSTFIX_SUGGESTIONS: Mutex<HashMap<PathBuf, BTreeMap<i32, Vec<Suggestion>>>> = Mutex::new(HashMap::default());
    /// Source code for each file
    static ref SOURCE_CODE: Mutex<HashMap<PathBuf, String>> = Mutex::new(HashMap::default());

    /// Buffer for compiler JSON diagnostic output
    static ref ERROR_BUFFER: Mutex<Vec<u8>> = Mutex::new(vec![]);

    /// The beginning position of the source file for the main crate
    static ref CRATE_FILE_POS: Mutex<Option<BytePos>> = Mutex::new(None);

    /// make the helper mod only add once
    static ref HELPER_FLAG: Mutex<bool> = Mutex::new(false);
}

static APPLY_FIXES: AtomicBool = AtomicBool::new(true);
static REMOVE_UNSAFE: AtomicBool = AtomicBool::new(false);

/// Whether to use a single lifetime for all struct fields, this can
/// speed up the convergence rate at the expense of not catching
/// independence of different pointers' lifetimes within a struct.
static MERGE_FIELD_LIFETIMES: AtomicBool = AtomicBool::new(false);

/// To enable debug prints in specific circumstances
static DEBUG: AtomicBool = AtomicBool::new(true);

/// context for whether a pointer is expected to be mutable
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MutCtx {
    Mut,
    Not,
    Unknown,
    /// Assign reference
    Assignee,
    /// Transfer ownership
    Move,
}

/// context for general pointer rewrite information
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct RewriteCtx {
    m: MutCtx,
    in_free: bool,
    /// The parent expression if the current expression is on a match arm.
    match_parent: Option<HirId>,
}

impl RewriteCtx {
    fn from_mc(m: MutCtx) -> Self {
        RewriteCtx {
            m,
            in_free: false,
            match_parent: None,
        }
    }

    fn with_mc(self, m: MutCtx) -> Self {
        RewriteCtx { m, ..self }
    }

    fn mut_() -> Self {
        RewriteCtx::from_mc(MutCtx::Mut)
    }
    fn not() -> Self {
        RewriteCtx::from_mc(MutCtx::Not)
    }
    fn unknown() -> Self {
        RewriteCtx::from_mc(MutCtx::Unknown)
    }
    fn assignee() -> Self {
        RewriteCtx::from_mc(MutCtx::Assignee)
    }
    fn move_() -> Self {
        RewriteCtx::from_mc(MutCtx::Move)
    }
    fn reset_parent(&self) -> Self {
        RewriteCtx {
            match_parent: None,
            ..*self
        }
    }
    fn with_match_parent(&self, parent: HirId) -> Self {
        RewriteCtx {
            match_parent: Some(parent),
            ..*self
        }
    }
}

/// context for type rewriting
enum TypeRewriteCtx<'a> {
    /// Inside function signature with explicit lifetimes
    FnSig(&'a mut LifetimeGen),
    /// Inside struct definition with given points-to node referring to the
    /// current function signature being rewritten
    Struct(Node),
}

fn has_non_arith_poison(locs: &HashSet<Loc<Name>>, provenance: &PtrProvenanceAnalysis) -> bool {
    (!provenance.aggregate_poisons(locs).is_empty()) && !are_locs_arith(locs, provenance)
}

fn are_locs_arith(poisons: &HashSet<Loc<Name>>, provenance: &PtrProvenanceAnalysis) -> bool {
    poisons
        .iter()
        .all(|l| !provenance.is_poisoned(l) || ptr_arith::is_unique_poison(provenance.poisons(l)))
        && poisons
            .iter()
            .any(|l| ptr_arith::is_unique_poison(provenance.poisons(l)))
}

fn process_ptr_arith_args<'a, D: IntoIterator<Item = &'a Expr<'a>>>(
    args: Option<Vec<&'a Expr<'a>>>,
    default_args: impl FnOnce() -> D,
    mut callback: impl FnMut(usize, &'a Expr<'a>),
) {
    match args {
        None => default_args()
            .into_iter()
            .enumerate()
            .for_each(|(i, a)| callback(i, a)),
        Some(a) => a.into_iter().enumerate().for_each(|(i, a)| callback(i, a)),
    }
}

/// Redirect the compiler output to a buffer we can parse
fn setup_output(cfg: &mut rustc_interface::Config) {
    let opts = &mut cfg.opts;
    opts.error_format = ErrorOutputType::Json {
        pretty: true,
        json_rendered: HumanReadableErrorType::Short(ColorConfig::Never),
    };
}

/// Check if an expression is just computing zero-initialization
fn is_zero_initializer(expr: &Expr) -> bool {
    match expr.kind {
        ExprKind::Cast(inner, _) => is_zero_initializer(inner),
        ExprKind::Repeat(inner, _) => is_zero_initializer(inner),
        ExprKind::Array(elems) => elems.iter().all(is_zero_initializer),
        ExprKind::Struct(_, fields, None) => {
            fields.iter().all(|field| is_zero_initializer(field.expr))
        },
        ExprKind::Tup(elems) => elems.iter().all(is_zero_initializer),
        _ => matches!(get_constant_value(expr), Some(LitKind::Int(0, _))),
    }
}

enum LifetimeGen {
    /// Variant that generates explicit lifetimes by default, holds the index of
    /// the lastly generated lifetime.
    ExplicitByDefault(u32),
    /// Variant that generates only the given lifetime
    SameLifetime(Lifetime),
}

impl LifetimeGen {
    /// All lifetimes generated using this generator so far
    pub fn generated_lifetimes(&self) -> Vec<Lifetime> {
        use LifetimeGen::*;
        match self {
            ExplicitByDefault(n) => (0..*n)
                .map(|i| Lifetime::from(format!("'a{}", i + 1)))
                .collect(),
            SameLifetime(l) => vec![l.clone()],
        }
    }

    /// Lifetime generator that outputs a fresh, explicit lifetime for each call
    pub fn explicit_by_default() -> Self {
        LifetimeGen::ExplicitByDefault(0)
    }
    /// Lifetime generator that always outputs the same lifetime, everywhere in the program
    #[allow(dead_code)]
    pub fn stable_const_gen() -> Self {
        LifetimeGen::SameLifetime(Lifetime::from("'a"))
    }

    /// Lifetime generator that always outputs `'_`
    pub fn implicit_only() -> Self {
        LifetimeGen::SameLifetime(Lifetime::from("'_"))
    }

    /// Lifetime generator that always outputs `'_`
    #[allow(dead_code)]
    pub fn empty_only() -> Self {
        LifetimeGen::SameLifetime(Lifetime::from(""))
    }

    /// Lifetime generator that always outputs `'static`
    pub fn static_only() -> Self {
        LifetimeGen::SameLifetime(Lifetime::from("'static"))
    }

    /// Lifetime generator that always outputs the same lifetime that is not named anywhere else in the program
    #[allow(dead_code)]
    pub fn fresh_const_gen() -> Self {
        static NEXT_INDEX: AtomicU32 = AtomicU32::new(0);
        LifetimeGen::SameLifetime(Lifetime::from(format!(
            "'b{}",
            NEXT_INDEX.fetch_add(1, Ordering::SeqCst)
        )))
    }

    pub fn fresh(&mut self) -> Lifetime {
        use LifetimeGen::*;

        match self {
            ExplicitByDefault(ref mut l) => {
                *l += 1;
                Lifetime::from(format!("'a{}", *l))
            },
            SameLifetime(ref l) => l.clone(),
        }
    }
}

/// A pass for the rewriting part of this tool
struct RewritePass {
    /// Results of the struct info analysis
    struct_info: StructInfo,
    /// Results of the pointer provenance analysis
    ptr_provenance: PtrProvenanceAnalysis,
    /// The configuration containing ownership and lifetime information
    config: Configuration,
    /// To generate lifetimes for the whole program
    lifetime_gen: LifetimeGen,
    /// Lifetime assignment to struct fields that are going to be rewritten
    lifetimes: HashMap<(Node, Link), Lifetime>,
    /// Lifetime parameter list for each struct and function (we use a
    /// BTreeSet to have a stable order)
    lifetime_params: HashMap<Node, BTreeSet<Lifetime>>,
    /// New function signatures for the functions that are going to be rewritten
    new_signatures: HashMap<Name, FnSig>,
    /// Memoization table to precompute all callers and callees we can handle
    fns_we_cannot_handle: HashSet<Name>,
    /// Whether we should remove `#[derive(..)]`. We remove it if
    /// current struct now has a non-empty set of lifetime parameters
    remove_derive: bool,
    /// recursion depth for rewriting expressions
    depth: i32,
    /// Rewritten types of global variables
    global_types: HashMap<Name, Type>,
    /// Whether currently rewriting a typedef
    in_typedef_rewrite: bool,
    /// Span info, so that we can record spans for some rewrites to look them up
    /// later when handling compiler errors.
    span_info: SpanInfo,
}

impl RewritePass {
    pub fn new() -> Box<LatePass> {
        let call_graph = analysis::result::<CallGraph>().unwrap();
        let mut fns_we_cannot_handle = HashSet::default();
        // precompute all callees we can handle.
        //
        // TODO: propagate this more efficiently if there are too many
        // edges in the call graph closure (such as by reducing the
        // graph to a DAG of its SCCs, then doing a single DFA)
        call_graph
            .inverse_closure()
            .unwrap()
            .iter()
            .for_each(|(f, callers)| {
                if !qual_fn_we_can_handle(f) && !fns_we_cannot_handle.contains(f) {
                    fns_we_cannot_handle.insert(f.clone());
                    callers.iter().for_each(|g| {
                        fns_we_cannot_handle.insert(g.clone());
                    });
                }
            });

        let mut pass = Box::new(RewritePass {
            struct_info: analysis::result::<StructInfo>().unwrap(),
            ptr_provenance: analysis::result::<PtrProvenanceAnalysis>().unwrap(),
            config: CONFIG.read().unwrap().clone(),
            fns_we_cannot_handle,
            lifetime_gen: LifetimeGen::explicit_by_default(),
            lifetimes: HashMap::default(),
            lifetime_params: HashMap::default(),
            new_signatures: HashMap::default(),
            remove_derive: false,
            depth: 1,
            global_types: HashMap::default(),
            in_typedef_rewrite: false,
            span_info: analysis::result::<SpanInfo>().unwrap(),
        });

        // add taint for fields of structs that occur in external APIs
        for node in &pass.struct_info.occurs_in_external_apis {
            let analysis = &mut pass.ptr_provenance;
            match node {
                Node::Struct(struct_name) => {
                    let add_extern_poison = |(f_name, f_ty): &(Name, Type)| {
                        let field_loc = Loc::Access(struct_name.clone(), f_name.clone());
                        // if this is a complex type containing a function pointer, then
                        // we need to create the relevant λ locations in case this
                        // function pointer is never instantiated with a concrete
                        // function in the library we are rewriting.
                        analysis.create_dummy_locs(field_loc.clone(), f_ty, true);
                        analysis.add_poison(PoisonKind::ExternCallParam, field_loc.clone());
                        analysis.add_poison(PoisonKind::ExternCallReturn, field_loc);
                    };

                    if let Some(struct_def) = pass.struct_info.struct_defs.get(struct_name) {
                        // The case for when this is a struct
                        struct_def.fields.iter().for_each(add_extern_poison);
                    } else if pass.struct_info.union_defs.contains_key(struct_name) {
                        // The case for when this is a union, we don't translate
                        // unions so ignore them
                        log::warn!(
                            "union {} is used in external APIs, not doing anything since we don't translate unions",
                            struct_name
                        );
                    }
                },
                Node::FnPtr(loc, sig) => {
                    let analysis = &mut pass.ptr_provenance;
                    // Go through all types pointed to by this function pointer and poison them
                    // TODO: handle varargs
                    log::warn!("378 - Node::FnPtr(loc, sig): {:?}", sig.param_types);
                    let param_locs = sig
                        .param_types
                        .iter()
                        .map(|ty| {
                            let param_loc = Loc::fresh();
                            analysis.create_dummy_locs(param_loc.clone(), ty, false);
                            analysis.add_poison(PoisonKind::ExternCallParam, param_loc.clone());
                            param_loc.to_st()
                        })
                        .collect::<Vec<better::solver::SimpleTerm<Loc<Name>>>>();
                    let ret_loc = {
                        let loc = Loc::fresh();
                        analysis.create_dummy_locs(loc.clone(), sig.ret_type.as_ref(), true);
                        analysis.add_poison(PoisonKind::ExternCallReturn, loc.clone());
                        loc.to_st()
                    };
                    let lambda = mk_lambda(param_locs, ret_loc);
                    analysis.add_flow(loc.clone().to_term(), lambda);
                },
                _ => unreachable!(),
            }
        }
        // solve the taint analysis again, then update the global record
        pass.ptr_provenance
            .propagate_occurrence_poisons_through_lambdas();
        pass.ptr_provenance.solve().unwrap();
        pass.ptr_provenance.set_constraints.solve().unwrap();
        analysis::replace(Box::new(pass.ptr_provenance.clone()));

        pass.compute_field_lifetimes();
        pass.compute_fn_sig_lifetimes();

        // println!(
        //     "Occurs in external APIs: {:#?}",
        //     pass.struct_info.occurs_in_external_apis
        // );
        //println!("New signatures: {:#?}", pass.new_signatures);

        pass
    }

    /// Computes lifetimes for each struct field by traversing the SCC
    /// graph, and assigning a unique lifetime for each edge in the
    /// graph, if the source contains only rewriteable structs
    fn compute_field_lifetimes(&mut self) {
        let mut scc_edge_to_lifetime = HashMap::default();
        let lifetime_gen = &mut self.lifetime_gen;
        let occurs_in_external_apis = &self.struct_info.occurs_in_external_apis;
        let ptr_provenance = &mut self.ptr_provenance;
        let blessed_from_libc = |struct_name: &Name| {
            let unqual_name = struct_name.as_ref().rsplit_once("::").unwrap().1;
            LIBC_TYPES.contains(unqual_name)
        };
        let in_limit_study = LIMIT_STUDY.load(Ordering::Relaxed);

        // Walks given type's structure to see if there are any pointers in it
        // that will be rewritten to (borrowing) references. Ignores function pointers.
        //
        // The first return value is whether there is such a reference, the
        // second return value is whether there is a Box at the top level or
        // possibly inside an array.
        fn contains_ref(
            ty: &Type,
            locs: HashSet<&Loc<Name>>,
            ptr_provenance: &PtrProvenanceAnalysis,
        ) -> (bool, bool) {
            let compute_points_to = || {
                locs.iter()
                    .flat_map(|l| ptr_provenance.points_to(*l))
                    .collect::<HashSet<&Loc<Name>>>()
            };
            match ty.peel_option() {
                Type::Ptr(_, box inner) => {
                    let poisons = ptr_provenance.aggregate_poisons(locs.iter().map(|l| *l));
                    if non_arith_poison_in_set(poisons) {
                        (
                            contains_ref(inner, compute_points_to(), ptr_provenance).0,
                            false,
                        )
                    } else if locs.iter().any(|l| ptr_provenance.is_loc_owned(l)) {
                        (
                            contains_ref(inner, compute_points_to(), ptr_provenance).0,
                            true,
                        )
                    } else {
                        (true, false)
                    }
                },
                Type::Array(box inner, _) => {
                    contains_ref(inner, compute_points_to(), ptr_provenance)
                },
                _ => (false, false),
            }
        }

        for (source, targets) in &self
            .struct_info
            .points_to_graph
            .scc_graph
            .iter()
            .map(|(k, vs)| (*k, vs.clone().into_iter().collect()))
            .collect::<BTreeMap<u32, BTreeMap<(Node, Link), u32>>>()
        {
            if self.struct_info.points_to_graph.scc_contents[source]
                .iter()
                .any(|node| {
                    occurs_in_external_apis.contains(node)
                        || match node {
                            Node::Struct(name) => !in_limit_study && blessed_from_libc(name),
                            Node::FnPtr(..) => false,
                            Node::Fn(..) => unreachable!(
                                "there shouldn't be any standalone functions in the points-to graph"
                            ),
                        }
                })
            {
                // the source has structs contained in external APIs
                continue;
            } else {
                for (struct_and_field, target) in targets {
                    let should_create_lifetime = match struct_and_field {
                        (Node::Struct(source_struct), Link::Field(field)) => {
                            // check if this field is poisoned
                            let access_loc =
                                Some(Loc::Access(source_struct.clone(), field.clone()));

                            let (needs_lifetime, has_box) = contains_ref(
                                self.struct_info.struct_defs[source_struct]
                                    .fields
                                    .iter()
                                    .find_map(|(f, t)| if f == field { Some(t) } else { None })
                                    .unwrap(),
                                access_loc.iter().collect(),
                                ptr_provenance,
                            );
                            if has_box {
                                self.struct_info
                                    .has_boxes
                                    .insert(struct_and_field.0.clone());
                            }
                            needs_lifetime
                        },
                        (Node::FnPtr(access_loc, sig), Link::Param(i)) => {
                            // Get the location for this parameter by projecting
                            // out lambdas in the field this fn pointer is
                            // associated with.
                            //
                            // This is using the equality-based analysis to
                            // project out the constructors, we may need to use
                            // the set-based analysis for ownership as well.
                            log::warn!("fn compute_field_lifetimes: 524 {:?}", sig);
                            let locs = ptr_provenance
                                .project_lambdas(access_loc, sig.known_arity())
                                .0
                                .get_mut(*i)
                                .map_or(HashSet::default(), std::mem::take);

                            if locs.iter().any(|l| {
                                ptr_provenance.is_poisoned(l)
                                    && !ptr_arith::is_unique_poison(ptr_provenance.poisons(l))
                            }) || locs.iter().any(|l| ptr_provenance.is_loc_owned(l))
                            {
                                false
                            } else {
                                true
                            }
                        },
                        (Node::FnPtr(access_loc, sig), Link::RetVal) => {
                            // Get the location for this parameter by projecting
                            // out lambdas in the field this fn pointer is
                            // associated with.
                            // Get the location for the return value
                            log::warn!("fn compute_field_lifetimes: 549 {:?}", sig);
                            let locs = ptr_provenance
                                .project_lambdas(&access_loc, sig.known_arity())
                                .1;

                            if locs.iter().any(|l| {
                                ptr_provenance.is_poisoned(l)
                                    && !ptr_arith::is_unique_poison(ptr_provenance.poisons(l))
                            }) || locs.iter().any(|l| ptr_provenance.is_loc_owned(l))
                            {
                                false
                            } else {
                                true
                            }
                        },
                        _ => unreachable!("did not expect the combination {:?}", struct_and_field),
                    };
                    if should_create_lifetime {
                        let lifetime =
                            scc_edge_to_lifetime
                                .entry((source, target))
                                .or_insert_with(|| {
                                    if MERGE_FIELD_LIFETIMES.load(Ordering::Relaxed) {
                                        Lifetime::from("'a")
                                    } else {
                                        lifetime_gen.fresh()
                                    }
                                });

                        self.lifetimes
                            .insert(struct_and_field.clone(), lifetime.clone());

                        self.lifetime_params
                            .entry(struct_and_field.0.clone())
                            .or_insert(BTreeSet::new())
                            .insert(lifetime.clone());
                    }
                }
            };
        }

        for (name, struct_) in &self.struct_info.struct_defs {
            if self
                .struct_info
                .occurs_in_external_apis
                .contains(&Node::Struct(name.clone()))
                || (!in_limit_study && blessed_from_libc(name))
            {
                continue;
            }
            for (field, ty) in &struct_.fields {
                // peel arrays to unwrap arrays of pointers
                let locs = Some(Loc::Access(name.clone(), field.clone()));

                let struct_and_field = (Node::Struct(name.clone()), Link::Field(field.clone()));
                let (needs_lifetime, has_boxes) =
                    contains_ref(ty, locs.iter().collect(), ptr_provenance);
                if has_boxes {
                    self.struct_info
                        .has_boxes
                        .insert(struct_and_field.0.clone());
                    continue;
                }

                if needs_lifetime {
                    if self.lifetimes.contains_key(&struct_and_field) {
                        continue;
                    }

                    let lifetime = if MERGE_FIELD_LIFETIMES.load(Ordering::Relaxed) {
                        Lifetime::from("'a")
                    } else {
                        lifetime_gen.fresh()
                    };
                    self.lifetimes
                        .insert(struct_and_field.clone(), lifetime.clone());

                    self.lifetime_params
                        .entry(struct_and_field.0)
                        .or_insert(BTreeSet::new())
                        .insert(lifetime.clone());
                }
            }
        }

        // generate lifetime variables for pointers inside function pointer
        // nodes in the graph
        let ordered_nodes = {
            let mut n = self
                .struct_info
                .points_to_graph
                .graph
                .keys()
                .collect::<Vec<&Node>>();
            n.sort();
            n
        };

        for n in ordered_nodes {
            if self.struct_info.occurs_in_external_apis.contains(n) {
                continue;
            }
            if let Node::FnPtr(loc, sig) = n {
                // TODO: check if this location is related to a frozen struct
                let (mut param_locs, ret_loc) =
                    ptr_provenance.project_lambdas(loc, sig.known_arity());
                if param_locs.len() < sig.param_types.len() {
                    param_locs.resize_with(sig.param_types.len(), Default::default);
                }
                for (i, ty) in sig.param_types.iter().enumerate() {
                    if let Type::Ptr(_, inner) = ty {
                        // do not change void pointers
                        if **inner == Type::Unknown(C_VOID_PATH.clone()) {
                            continue;
                        }

                        if param_locs[i].iter().any(|loc| {
                            ptr_provenance.is_poisoned(loc)
                                && !ptr_arith::is_unique_poison(ptr_provenance.poisons(loc))
                        }) {
                            continue;
                        }

                        if param_locs[i]
                            .iter()
                            .any(|loc| ptr_provenance.is_loc_owned(loc))
                        {
                            // No need to insert the function pointer
                            // into has_boxes, it takes a box as an
                            // argument/return value but the function
                            // pointer itself is still copyable.
                            continue;
                        }

                        let node_and_link = (n.clone(), Link::Param(i));
                        if self.lifetimes.contains_key(&node_and_link) {
                            continue;
                        }

                        let lifetime = if MERGE_FIELD_LIFETIMES.load(Ordering::Relaxed) {
                            Lifetime::from("'a")
                        } else {
                            lifetime_gen.fresh()
                        };
                        self.lifetimes
                            .insert(node_and_link.clone(), lifetime.clone());
                        self.lifetime_params
                            .entry(node_and_link.0)
                            .or_insert(BTreeSet::new())
                            .insert(lifetime.clone());
                    }
                }

                if let Type::Ptr(_, inner) = sig.ret_type.as_ref() {
                    // do not change void pointers
                    if **inner == Type::Unknown(C_VOID_PATH.clone()) {
                        continue;
                    }

                    if ret_loc.iter().any(|loc| {
                        ptr_provenance.is_poisoned(loc)
                            && !ptr_arith::is_unique_poison(ptr_provenance.poisons(loc))
                    }) {
                        continue;
                    }

                    if ret_loc.iter().any(|loc| ptr_provenance.is_loc_owned(loc)) {
                        // No need to insert the function pointer
                        // into has_boxes, it takes a box as an
                        // argument/return value but the function
                        // pointer itself is still copyable.
                        continue;
                    }

                    let node_and_link = (n.clone(), Link::RetVal);
                    if self.lifetimes.contains_key(&node_and_link) {
                        continue;
                    }

                    let lifetime = if MERGE_FIELD_LIFETIMES.load(Ordering::Relaxed) {
                        Lifetime::from("'a")
                    } else {
                        lifetime_gen.fresh()
                    };
                    self.lifetimes
                        .insert(node_and_link.clone(), lifetime.clone());
                    self.lifetime_params
                        .entry(node_and_link.0)
                        .or_insert(BTreeSet::new())
                        .insert(lifetime.clone());
                }
            }
        }

        // println!("{}", "struct lifetime params".yellow());
        // for (strukt, lp) in &self.lifetime_params {
        //     println!("{} -> {:?}", strukt, lp);
        // }
        for source_node in self.struct_info.points_to_graph.graph.keys() {
            if occurs_in_external_apis.contains(source_node)
                || match source_node {
                    Node::Struct(name) => !in_limit_study && blessed_from_libc(name),
                    Node::FnPtr(..) => false,
                    Node::Fn(..) => unreachable!(
                        "there shouldn't be any standalone functions in the points-to graph"
                    ),
                }
            {
                // the source (the current struct, or the owner of the
                // fn ptr) is contained in external APIs
                continue;
            }
            // collect lifetimes from all transitively pointed
            // objects. this can be more efficient and done with a
            // single DFS and memoization.
            let pointee_lifetimes = {
                let mut visited = HashSet::default();
                let mut worklist = vec![source_node];
                let mut lifetimes = BTreeSet::<Lifetime>::default();
                while let Some(pointee) = worklist.pop() {
                    if !visited.contains(pointee) {
                        visited.insert(pointee.clone());
                        // add the transitively pointed structs
                        worklist.extend(self.struct_info.points_to_graph.graph[pointee].values());
                        // get the edge labels, and get the lifetimes from them
                        lifetimes.extend(
                            self.lifetime_params
                                .get(pointee)
                                .cloned()
                                .unwrap_or(BTreeSet::default()),
                        );
                    }
                }
                lifetimes
            };
            // extend the lifetimes of the source structs
            if !pointee_lifetimes.is_empty() {
                self.lifetime_params
                    .entry(source_node.clone())
                    .or_insert(BTreeSet::new())
                    .extend(pointee_lifetimes.clone());
            }
        }
        // println!("{}", "struct lifetime params".red());
        // for (strukt, lp) in &self.lifetime_params {
        //     println!("{:?} -> {:?}", strukt, lp);
        // }

        // propagate lifetime parameters from contained structs'
        // transitive closure. `contains_graph` should already contain
        // the transitive closure by this point.
        for (container, containees) in &self.struct_info.contains_graph {
            for containee in containees {
                if let Some(params) = self.lifetime_params.get(containee).cloned() {
                    if !params.is_empty() {
                        self.lifetime_params
                            .entry(container.clone())
                            .or_default()
                            .extend(params);
                    }
                }
            }
        }

        // propagate information about boxes in inner structs to the outer
        // structs that directly (not via a pointer) contain them.
        for (container, containees) in &self.struct_info.structs_inside {
            if !self.struct_info.has_boxes.contains(container)
                && containees
                    .iter()
                    .any(|c| self.struct_info.has_boxes.contains(c))
            {
                self.struct_info.has_boxes.insert(container.clone());
            }
        }

        // println!("contained: {:#?}", contained);
        // println!("{}", "struct lifetime params".green());
        // for (strukt, lp) in &self.lifetime_params {
        //     println!("{} -> {:?}", strukt, lp);
        // }
        // println!("struct info: {:#?}", self.struct_info);
    }

    /// rewrite types in function signatures, if the relevant location
    /// is not poisoned.
    fn rewrite_type(
        &self,
        ty: &Type,
        loc: HashSet<&Loc<Name>>,
        new_lifetimes: &mut Vec<Lifetime>,
        lifetime_gen: &mut LifetimeGen,
    ) -> Type {
        use CustomSliceCell as SliceCell;
        use CustomSliceType as SliceTy;
        use Type::*;
        log::warn!("fn rewrite_type: Type - {:?}", ty);
        match ty {
            Ptr(mtbl, inner) => {
                let ref_or_ptr_arith = loc.iter().all(|l| {
                    !self.ptr_provenance.is_poisoned(l)
                        || ptr_arith::is_unique_poison(self.ptr_provenance.poisons(l))
                });

                let is_poisoned = loc.iter().any(|l| self.ptr_provenance.is_poisoned(l));
                let is_owned =
                    !loc.is_empty() && loc.iter().all(|l| self.ptr_provenance.is_loc_owned(l));
                // TODO (ryans): should this be .all() or .any()?
                let is_ref_cell = loc.iter().all(|l| self.ptr_provenance.is_loc_refcell(l));
                // ref_or_ptr_arith is an upper bound, and is_poisoned is a lower bound
                let ptr_arith = ref_or_ptr_arith && is_poisoned;

                let slice_cell = if is_ref_cell {
                    SliceCell::RefCell
                } else {
                    SliceCell::NoCell
                };

                // Allocate the outer lifetime first, if needed. This
                // variable contains a lifetime if the pointer itself
                // is not poisoned.
                let lifetime_if_ref_or_arith = if ref_or_ptr_arith && !is_owned {
                    let l = lifetime_gen.fresh();
                    new_lifetimes.push(l.clone());
                    Some(l)
                } else {
                    None
                };
                let inner_locs = loc
                    .into_iter()
                    .flat_map(|l| self.ptr_provenance.points_to(l))
                    .collect();
                let new_inner =
                    Box::new(self.rewrite_type(inner, inner_locs, new_lifetimes, lifetime_gen));
                if let Some(l) = lifetime_if_ref_or_arith {
                    if ptr_arith {
                        OptionT(Box::new(CustomSlice(
                            SliceTy::for_ref(l, *mtbl, slice_cell),
                            new_inner,
                        )))
                    } else {
                        OptionT(Box::new(Ref(*mtbl, l, new_inner)))
                    }
                } else if ref_or_ptr_arith && is_owned {
                    if ptr_arith {
                        OptionT(Box::new(CustomSlice(
                            SliceTy::for_owned(slice_cell),
                            new_inner,
                        )))
                    } else {
                        OptionT(Box::new(Boxed(new_inner)))
                    }
                } else {
                    // keep the outer type as is
                    Ptr(*mtbl, new_inner)
                }
            },
            Array(inner, size) => {
                let is_owned =
                    !loc.is_empty() && loc.iter().all(|l| self.ptr_provenance.is_loc_owned(l));
                let is_ref_cell = loc.iter().all(|l| self.ptr_provenance.is_loc_refcell(l));
                let ptr_arith = are_locs_arith(
                    &loc.iter().map(|l| (*l).clone()).collect(),
                    &self.ptr_provenance,
                );

                let slice_cell = if is_ref_cell {
                    SliceCell::RefCell
                } else {
                    SliceCell::NoCell
                };

                let inner_locs = loc
                    .clone()
                    .into_iter()
                    .flat_map(|l| self.ptr_provenance.points_to(l))
                    .collect();
                let new_inner =
                    Box::new(self.rewrite_type(inner, inner_locs, new_lifetimes, lifetime_gen));
                // Wrap arrays in Option to allow initializing them when
                // introducing ownership. We wrap all arrays in options to
                // simplify code generation involving arrays.
                if ptr_arith && !is_owned {
                    OptionT(Box::new(CustomSlice(
                        SliceTy::Array(slice_cell, size.clone()),
                        new_inner,
                    )))
                } else if ptr_arith && is_owned {
                    OptionT(Box::new(CustomSlice(
                        SliceTy::for_owned(slice_cell),
                        new_inner,
                    )))
                } else {
                    // keep the outer type as is
                    Array(new_inner, size.clone())
                }
            },
            Struct(name) => {
                // generate lifetime variables to apply to this
                // struct if needed
                if let Some(params) = self.lifetime_params.get(&Node::Struct(name.clone())) {
                    let lifetime_args: Vec<Lifetime> =
                        (0..params.len()).map(|_| lifetime_gen.fresh()).collect();
                    new_lifetimes.extend(lifetime_args.clone());
                    App(Box::new(Struct(name.clone())), lifetime_args)
                } else {
                    // no lifetime parameters for this struct, no
                    // need to make it into lifetime application
                    ty.clone()
                }
            },
            OptionT(box inner) => OptionT(Box::new(self.rewrite_type(
                inner,
                loc,
                new_lifetimes,
                lifetime_gen,
            ))),
            Fn(sig) => {
                assert!(
                    !loc.is_empty(),
                    "no location to pass to fn sig to rewrite the type {}",
                    ty
                );
                log::warn!("972 --- fn rewrite_type: Fn(sig) {:?}", sig);
                println!("Fnsig: {:?}", ty);
                if loc.is_empty() {
                    log::warn!("+++++++++++++ loc.is_empty +++++++++++++");
                    return ty.clone();
                }
                let config = CONFIG.read().unwrap();
                Fn(self.compute_fn_sig(
                    FnTaintInfo::FnPtr(loc.iter().next().unwrap()),
                    sig,
                    &*config,
                    TypeRewriteCtx::FnSig(lifetime_gen),
                ))
            },
            _ => ty.clone(),
        }
    }

    /// Refine given signature according to the given taint info describing the
    /// function's location in the taint analysis.
    ///
    /// If the taint info corresponds to a concrete function, then explicit
    /// lifetimes and lifetime bounds will be generated, otherwise the lifetime
    /// constraints are assumed to be implicit (e.g. in case of function
    /// pointers) and no lifetime constraints will be injected. This may cause
    /// some problems.
    ///
    /// TODO(maemre): See if we need to extend the configuration lattice to
    /// support arbitrary function location qualifiers or to derive these
    /// constraints from the alias set for function pointers
    ///
    /// The current implementation uses the equality-based analysis and picks a
    /// representative for each λ argument for function pointer (due to the
    /// internal workings of the equality-based analysis). If we need to switch
    /// to set-based analysis (or mix the two), we may need to blow up the
    /// points-to locations so it would become expensive. There are several
    /// solutions we can implement in the future to address this:
    ///
    /// - Make `rewrite_type` work with internal location representations to
    /// avoid reifying the set of aliases.
    ///
    /// - Pick a representative for each location, making sure that the
    /// recursive queries over the representatives will be accurate. This may
    /// create a problem when mixing the equality and set-based queries
    /// (e.g. determining ownership and ptr arith when we start resolving mixed
    /// ptr constraints).
    fn compute_fn_sig(
        &self,
        taint_info: FnTaintInfo<Name>,
        fn_sig: &FnSig,
        config: &Configuration,
        // Where we are rewriting this signature in
        ctx: TypeRewriteCtx,
    ) -> FnSig {
        use FnTaintInfo::*;

        // TODO: make sure we don't generate lifetime qualifiers that are
        // already in use in the signature
        let (mut lifetime_gen, struct_field_node) = match ctx {
            TypeRewriteCtx::Struct(node) => (None, Some(node)),
            TypeRewriteCtx::FnSig(gen) => (Some(gen), None),
        };

        // The lambda constructors that are in the same equivalence class for fn
        // pointers, it is a single lambda constructor for us because of the
        // inner workings of the equivalence-based analysis.
        let loc: Loc<Name> = match &taint_info {
            Known(fn_name) => Loc::Var((*fn_name).clone()),
            FnPtr(loc) => (*loc).clone(),
        };

        let (param_locs, ret_locs) = self
            .ptr_provenance
            .project_lambdas(&loc, fn_sig.known_arity());

        let param_types = fn_sig
            .param_types
            .iter()
            .enumerate()
            .map(|(i, ty)| {
                // - rewrite structs to include lifetimes
                // - rewrite typedefs to the type they represent
                // - rewrite pointers to introduce lifetimes
                if let Some(node) = &struct_field_node {
                    // jump back to computing field types rather than generating
                    // fresh lifetime variables.
                    let lifetime = self.lifetimes.get(&(node.clone(), Link::Param(i))).cloned();
                    let param_loc = param_locs.get(i).cloned().unwrap_or_default();
                    if let FnPtr(loc) = taint_info {
                        log::trace!(
                            "param {:?}#{} lifetime: {:?} loc: {:?} poison: {:?}",
                            loc,
                            i,
                            lifetime,
                            param_loc,
                            param_loc.iter().map(|l| self.ptr_provenance.poisons(l))
                        );
                    }
                    self.compute_field_type(ty.clone(), lifetime, param_loc.into_iter().collect())
                } else {
                    let locs = param_locs.get(i).map_or(HashSet::default(), |s| {
                        s.iter().collect::<HashSet<&Loc<Name>>>()
                    });
                    self.rewrite_type(ty, locs, &mut vec![], *lifetime_gen.as_mut().unwrap())
                }
            })
            .collect();

        let ret_type = Box::new(if let Some(node) = struct_field_node {
            // jump back to computing field types rather than generating
            // fresh lifetime variables.
            let lifetime = self.lifetimes.get(&(node, Link::RetVal)).cloned();
            self.compute_field_type(fn_sig.ret_type.as_ref().clone(), lifetime, ret_locs)
        } else {
            let ret_loc_set = ret_locs.iter().collect::<HashSet<&Loc<Name>>>();
            self.rewrite_type(
                &fn_sig.ret_type,
                ret_loc_set,
                &mut vec![],
                *lifetime_gen.as_mut().unwrap(),
            )
        });

        // Load lifetime bounds from the configuration if this is a known function
        let lifetime_bounds = if let Known(fn_name) = taint_info {
            let qual = Qual {
                kind: QualKind::Fn,
                q_name: fn_name.clone(),
            };
            if let Some(bounds) = config.bounds.get(&qual) {
                bounds
                    .iter()
                    .flat_map(|(lower, uppers)| {
                        let l = lower.clone();
                        uppers.iter().map(move |upper| (l.clone(), upper.clone()))
                    })
                    .collect::<Vec<(Lifetime, Lifetime)>>()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let anonymous_lifetime = Lifetime::from("'_");
        let static_lifetime = Lifetime::from("'static");

        let mut lifetimes = fn_sig.lifetime_quals.clone();
        if taint_info.is_known_fn() {
            lifetimes.append(&mut lifetime_gen.unwrap().generated_lifetimes());

            // remove duplicates in the lifetime declarations while
            // preserving the insertion order (because the old signature
            // may have some lifetimes)
            let mut lifetime_set = HashSet::default();
            for l in std::mem::take(&mut lifetimes) {
                if !lifetime_set.contains(&l) && *l != anonymous_lifetime && *l != static_lifetime {
                    lifetime_set.insert(l.clone());
                    lifetimes.push(l);
                }
            }
        }

        FnSig {
            param_types: param_types,
            ret_type: ret_type,
            lifetime_quals: lifetimes,
            lifetime_bounds,
            ..fn_sig.clone()
        }
    }

    /// Compute lifetimes in function signatures by going through each
    /// parameter and introducing lifetimes if the parameter is not
    /// involved in pointer arithmetic
    fn compute_fn_sig_lifetimes(&mut self) {
        // extract relevant fields to help the compiler figure out
        // borrowing in closures
        let mut new_lifetimes = HashMap::default();
        let mut new_signatures = HashMap::default();

        // Lock the configuration
        let config = CONFIG.read().unwrap();

        for (fn_name, (fn_sig, flavor)) in &self.struct_info.fn_sigs {
            if *flavor != FnFlavor::Normal && *flavor != FnFlavor::UsedAsFnPtr {
                continue;
            }

            let mut lifetime_gen = LifetimeGen::explicit_by_default();
            let rewrite_ctx = TypeRewriteCtx::FnSig(&mut lifetime_gen);
            let new_sig =
                self.compute_fn_sig(FnTaintInfo::Known(fn_name), fn_sig, &*config, rewrite_ctx);

            // the signature has changed, update the lifetime params:
            new_lifetimes.insert(
                Node::Fn(fn_name.clone()),
                new_sig.lifetime_quals.clone().into_iter().collect(),
            );
            new_signatures.insert(fn_name.clone(), new_sig);
        }

        self.lifetime_params.extend(new_lifetimes);
        self.new_signatures = new_signatures;
    }

    /// Generates the code to compute the default value for `ty`
    fn default_value(&self, ty: &Type) -> Option<String> {
        use Type::*;

        match ty {
            Struct(_) => {
                if self.struct_info.can_generate_default(ty) {
                    Some(format!("{}::new()", ty))
                } else {
                    None
                }
            },
            Enum(_name) => {
                log::warn!(
                    "Cannot generate default values for enums, this will have cascading effects"
                );
                None
            },
            Union(name) => {
                log::warn!(
                    "Cannot generate default values for union {:?}, this will have cascading effects",
                    name
                );
                None
            },
            RefCell(box inner) => self
                .default_value(inner)
                .map(|s| format!("::std::cell::RefCell::new({})", s)),
            Unknown(path) if CONST_DEFAULT_VALUE_EXPRS.contains_key(&flatten_path(path)) => {
                Some(CONST_DEFAULT_VALUE_EXPRS[&flatten_path(path)].to_string())
            },
            Unknown(path) if IMPLEMENTS_DEFAULT.contains(&flatten_path(path)) => {
                Some(format!("{}::default()", ty))
            },
            Ptr(_, _) => Some(format!("(0 as {})", ty)),
            OptionT(_) => Some("None".to_string()),
            Bool => Some("false".to_string()),
            Array(inner, size) => {
                // repeat the default value because the `[e; N]` syntax requires
                // `inner` to implement `Copy`, and `Default::default()` doesn't
                // work if `size` is > 31.
                self.default_value(inner)
                    .map(|v| format!("[{}]", format!("{},", v).repeat(size.unwrap())))
            },
            CustomSlice(slice_ty, inner) => match slice_ty {
                CustomSliceType::Ref(..) | CustomSliceType::RefMut(..) => None,
                CustomSliceType::Boxed(_) => {
                    Some("crate::__laertes_array::CustomSlice::new(Box::default())".into())
                },
                CustomSliceType::Array(CustomSliceCell::NoCell, l) => {
                    self.default_value(inner).map(|v| {
                        format!(
                            "crate::__laertes_array::CustomSlice::new([{}; {}])",
                            v,
                            l.unwrap()
                        )
                    })
                },
                CustomSliceType::Array(CustomSliceCell::RefCell, l) => {
                    self.default_value(inner).map(|v| {
                        format!(
                            "crate::__laertes_array::CustomSlice::from_vec(vec![{}; {}])",
                            v,
                            l.unwrap()
                        )
                    })
                },
            },
            App(ty, _) => {
                // strip lifetime application
                self.default_value(ty)
            },
            Int(_) | Uint(_) => Some("0".to_string()),
            Float(_) => Some("0.0".to_string()),
            Fn(_) => None,
            _ => todo!("generate default for {:?}", ty),
        }
    }

    // suggestions for left-hand side of expressions
    fn make_suggestion(
        &self,
        ctx: &LateContext<'_>,
        span: Span,
        message: String,
        replacement: String,
    ) {
        self.make_suggestion_impl(ctx, span, message, replacement, self.depth)
    }

    // suggestions for right-hand side of expressions. this is so that
    // we order the suggestions for rustfix to process correctly when
    // two expressions' beginning/end coincide
    fn make_suggestion_after(
        &self,
        ctx: &LateContext<'_>,
        span: Span,
        message: String,
        replacement: String,
    ) {
        self.make_suggestion_impl(ctx, span, message, replacement, -self.depth)
    }

    fn make_suggestion_impl(
        &self,
        ctx: &LateContext<'_>,
        span: Span,
        message: String,
        replacement: String,
        depth: i32,
    ) {
        use rustfix::{LinePosition, LineRange};

        let source_map = ctx.sess().source_map();
        let fname = source_map.span_to_filename(span);

        let fname_real = match fname {
            FileName::Real(ref n) => n,
            _ => {
                println!(
                    "{}",
                    format!("WARNING: Attempted to fix generated code at {:?}", span)
                        .bold()
                        .red()
                );
                return;
            },
        };

        let file = source_map.get_source_file(&fname).unwrap();
        // get the char offsets within the file
        let lo_offset = file.original_relative_byte_pos(span.lo()).0;
        let hi_offset = file.original_relative_byte_pos(span.hi()).0;
        // get the line and the column numbers
        let lo = file.lookup_file_pos_with_col_display(span.lo());
        let hi = file.lookup_file_pos_with_col_display(span.hi());
        let line_range = LineRange {
            start: LinePosition {
                line: lo.0,
                column: lo.2,
            },
            end: LinePosition {
                line: hi.0,
                column: hi.2,
            },
        };
        let file_name_display_preference = FileNameDisplayPreference::Remapped;
        // The Snippet object represents a piece of source code within a file.
        let snippet = Snippet {
            // file_name: file_name.as_string();
            file_name: (*fname_real)
                .to_string_lossy(file_name_display_preference)
                .to_string(),
            line_range,
            range: (lo_offset as usize)..(hi_offset as usize),
            text: (
                "".into(),
                source_map.span_to_snippet(span).unwrap(),
                "".into(),
            ),
        };

        EDIT_OFFSETS.lock().unwrap().add_edit(
            // Name::from(fname_real.local_path().to_str().unwrap()),
            Name::from(fname_real.local_path().unwrap().to_str().unwrap()),
            lo_offset,
            hi_offset - lo_offset,
            replacement.len() as u32,
        );

        let mut suggestions = RUSTFIX_SUGGESTIONS.lock().unwrap();

        suggestions
            // .entry(fname_real.local_path().into())
            .entry(fname_real.local_path().unwrap().into())
            .or_default()
            .entry(depth)
            .or_insert(vec![])
            .push(Suggestion {
                message: "".to_owned(),
                snippets: vec![snippet.clone()],
                solutions: vec![Solution {
                    message,
                    replacements: vec![Replacement {
                        snippet,
                        replacement,
                    }],
                }],
            });
    }

    /// Merge given rustfix suggestions (merge suggestions altering contiguous
    /// snippets). All suggestions must be related to a single file.
    fn merge_suggestions(
        suggestions: BTreeMap<i32, Vec<Suggestion>>,
    ) -> BTreeMap<i32, Vec<Suggestion>> {
        // helper functions

        let append_snippet = |a: &mut Snippet, b: &Snippet| {
            assert_eq!(a.range.end, b.range.start);
            a.range.end = b.range.end;
            a.line_range.end = b.line_range.end;
            a.text.1.push_str(&b.text.1);
            a.text.2 = b.text.2.clone();
        };

        // merged_suggestions : end of replacement range -> depth -> [suggestion]
        let mut merged_suggestions: HashMap<usize, BTreeMap<i32, Vec<Suggestion>>> =
            HashMap::default();
        // record suggestions along with their depth so that they can be
        // reordered when needed
        //
        for (depth, suggestions_at_depth) in suggestions.into_iter() {
            for mut suggestion in suggestions_at_depth {
                assert_eq!(suggestion.snippets.len(), 1);
                assert_eq!(suggestion.solutions.len(), 1);
                let solution = &suggestion.solutions[0];
                assert_eq!(solution.replacements.len(), 1);
                let replacement = &solution.replacements[0];
                let range = replacement.snippet.range.clone();
                let suggestions_right_before = merged_suggestions.entry(range.start).or_default();

                // find the latest rewrite that ends where this one starts
                if let Some(mut last_vec) = suggestions_right_before.last_entry() {
                    // we need to pop the last suggestion, because the end point changed.
                    // we then effectively compute:
                    // last_suggestion <- last_suggestion + suggestion
                    // suggestion <- last_suggestion
                    //
                    // then, when we insert the current suggestion, the end point data in merged_suggestions will be correct.
                    if let Some(mut last_suggestion) = last_vec.get_mut().pop() {
                        let last_solution = &mut last_suggestion.solutions[0];
                        last_solution.message.push_str(" THEN ");
                        last_solution
                            .message
                            .push_str(&suggestion.solutions[0].message);
                        // apply this insertion after the last insertion

                        // update replacement text
                        last_solution.replacements[0]
                            .replacement
                            .push_str(&replacement.replacement);

                        // update/merge snippets
                        append_snippet(
                            &mut last_solution.replacements[0].snippet,
                            &replacement.snippet,
                        );
                        append_snippet(&mut last_suggestion.snippets[0], &suggestion.snippets[0]);
                        suggestion = last_suggestion;
                    }
                    merged_suggestions
                        .entry(range.end)
                        .or_default()
                        .entry(depth)
                        .or_default()
                        .push(suggestion);
                } else {
                    // try suggestions right after this one
                    /*    let suggestions_right_after = merged_suggestions.entry(range.start).or_default();
                    if let Some(mut last_vec) = suggestions_right_after.last_entry() {
                        // Update this suggestion by moving the data from the last
                        // solution, if there is a last solution. After the conditional, we will insert this solution at the appropriate point.
                        if let Some(last_suggestion) = last_vec.get_mut().pop() {
                            let last_solution = &last_suggestion.solutions[0];
                            let solution = &mut suggestion.solutions[0];
                            solution.message.push_str(" THEN ");
                            solution
                                .message
                                .push_str(&last_solution.message);

                            // update replacement text
                            solution.replacements[0]
                                .replacement
                                .push_str(&last_solution.replacements[0].replacement);

                            // update/merge snippets
                            append_snippet(
                                &mut solution.replacements[0].snippet,
                                &last_solution.replacements[0].snippet,
                            );
                            append_snippet(&mut suggestion.snippets[0], &last_suggestion.snippets[0]);
                        }


                            merged_suggestions
                                .entry(range.end)
                                .or_default()
                                .entry(depth)
                                .or_default()
                                .push(suggestion);

                    } else {
                        */
                    merged_suggestions
                        .entry(range.end)
                        .or_default()
                        .entry(depth)
                        .or_default()
                        .push(suggestion);
                }
            }
        }

        // order merged suggestions
        let mut ordered_suggestions = BTreeMap::<i32, Vec<Suggestion>>::default();

        for depth_to_suggestions in merged_suggestions.into_values() {
            for (depth, suggestions_at_depth) in depth_to_suggestions {
                ordered_suggestions
                    .entry(depth)
                    .or_default()
                    .extend(suggestions_at_depth);
            }
        }
        ordered_suggestions
    }

    /// Rewrite given type
    fn compute_field_type(
        &self,
        resolved_type: Type,
        lifetime: Option<Lifetime>,
        poison_locs: HashSet<Loc<Name>>,
    ) -> Type {
        use CustomSliceCell as SliceCell;
        fn inner_locs(
            locs: impl std::borrow::Borrow<HashSet<Loc<Name>>>,
            provenance: &PtrProvenanceAnalysis,
        ) -> HashSet<Loc<Name>> {
            locs.borrow()
                .iter()
                .flat_map(|l| provenance.points_to(l))
                .cloned()
                .collect()
        }

        fn locs_slice_cell(
            poisons: &HashSet<Loc<Name>>,
            provenance: &PtrProvenanceAnalysis,
        ) -> SliceCell {
            if poisons.iter().all(|l| provenance.is_loc_refcell(l)) {
                SliceCell::RefCell
            } else {
                SliceCell::NoCell
            }
        }

        if DEBUG.load(Ordering::Relaxed) {
            println!(
                "resolved type: {} lifetime: {:?} locs: {:?}\npoison: {:?}",
                resolved_type,
                lifetime,
                poison_locs,
                self.ptr_provenance.aggregate_poisons(poison_locs.iter())
            );
        }
        match resolved_type {
            Type::Ptr(mutbl, box inner_ty) => {
                if let Some(l) = &lifetime {
                    // convert `*<mutability>` to
                    // `&'lifetime <mutability>`

                    let new_inner = Box::new(self.compute_field_type(
                        inner_ty,
                        lifetime.clone(),
                        inner_locs(&poison_locs, &self.ptr_provenance),
                    ));

                    if are_locs_arith(&poison_locs, &self.ptr_provenance) {
                        Type::OptionT(Box::new(Type::CustomSlice(
                            CustomSliceType::for_ref(
                                l.clone(),
                                mutbl,
                                locs_slice_cell(&poison_locs, &self.ptr_provenance),
                            ),
                            new_inner,
                        )))
                    } else if poison_locs
                        .iter()
                        .any(|l| self.ptr_provenance.is_poisoned(l))
                    {
                        // There is some non-arithmetic poison, this should be a raw pointer
                        Type::Ptr(
                            mutbl,
                            Box::new(self.compute_field_type(
                                *new_inner,
                                lifetime,
                                inner_locs(poison_locs, &self.ptr_provenance),
                            )),
                        )
                    } else if !poison_locs.is_empty()
                        && poison_locs
                            .iter()
                            .all(|l| self.ptr_provenance.is_loc_owned(l))
                    {
                        Type::OptionT(Box::new(Type::Boxed(new_inner)))
                    } else {
                        Type::OptionT(Box::new(Type::Ref(mutbl, l.clone(), new_inner)))
                    }
                } else if !poison_locs.is_empty()
                    && poison_locs
                        .iter()
                        .any(|loc| self.ptr_provenance.is_loc_owned(loc))
                {
                    let new_inner = Box::new(self.compute_field_type(
                        inner_ty,
                        lifetime.clone(),
                        inner_locs(&poison_locs, &self.ptr_provenance),
                    ));

                    if are_locs_arith(&poison_locs, &self.ptr_provenance) {
                        Type::OptionT(Box::new(Type::CustomSlice(
                            CustomSliceType::for_owned(locs_slice_cell(
                                &poison_locs,
                                &self.ptr_provenance,
                            )),
                            new_inner,
                        )))
                    } else if poison_locs
                        .iter()
                        .any(|l| self.ptr_provenance.is_poisoned(l))
                    {
                        // There is some non-arithmetic poison, this should be a raw pointer
                        Type::Ptr(
                            mutbl,
                            Box::new(self.compute_field_type(
                                *new_inner,
                                lifetime,
                                inner_locs(poison_locs, &self.ptr_provenance),
                            )),
                        )
                    } else {
                        Type::OptionT(Box::new(Type::Boxed(new_inner)))
                    }
                } else {
                    if are_locs_arith(&poison_locs, &self.ptr_provenance) {
                        log::warn!("Missing lifetime for field with pointer arithmetic poison!");
                    }
                    // if there isn't a lifetime on this edge, do not rewrite
                    // the pointer, but we may need to rewrite the struct
                    // inside
                    Type::Ptr(
                        mutbl,
                        Box::new(self.compute_field_type(
                            inner_ty,
                            lifetime,
                            inner_locs(poison_locs, &self.ptr_provenance),
                        )),
                    )
                }
            },
            Type::Struct(ref name) => {
                if let Some(lifetime_params) = self.lifetime_params.get(&Node::Struct(name.clone()))
                {
                    Type::App(
                        Box::new(resolved_type),
                        lifetime_params.clone().into_iter().collect(),
                    )
                } else {
                    resolved_type
                }
            },
            Type::Array(inner, len) => {
                use CustomSliceType as SliceTy;

                let is_owned = !poison_locs.is_empty()
                    && poison_locs
                        .iter()
                        .all(|l| self.ptr_provenance.is_loc_owned(l));
                let ptr_arith = are_locs_arith(&poison_locs, &self.ptr_provenance);
                let slice_cell = locs_slice_cell(&poison_locs, &self.ptr_provenance);

                let inner = Box::new(self.compute_field_type(
                    *inner,
                    lifetime,
                    inner_locs(poison_locs.clone(), &self.ptr_provenance),
                ));

                // Wrap arrays in Option to allow initializing them when
                // introducing ownership. We wrap all arrays in options to
                // simplify code generation involving arrays.
                if ptr_arith && !is_owned {
                    Type::OptionT(Box::new(Type::CustomSlice(
                        SliceTy::Array(slice_cell, len.clone()),
                        inner,
                    )))
                } else if ptr_arith && is_owned {
                    Type::OptionT(Box::new(Type::CustomSlice(
                        SliceTy::for_owned(slice_cell),
                        inner,
                    )))
                } else {
                    // keep the outer type as is
                    Type::Array(inner, len.clone())
                }
            },
            Type::OptionT(box inner) => {
                // assumption: Option doesn't change locations
                Type::OptionT(Box::new(self.compute_field_type(
                    inner,
                    lifetime,
                    poison_locs,
                )))
            },
            Type::Fn(sig) if !poison_locs.is_empty() => {
                // Rewrite function signature according to the lifetimes
                // generated by walking the points-to graph. We do not quantify
                // the bounds
                let config = CONFIG.read().unwrap();
                log::warn!(
                    "at loc {:?} for function with signature {}",
                    poison_locs,
                    Type::Fn(sig.clone())
                );
                let loc = if poison_locs.len() == 1 {
                    poison_locs.iter().next().unwrap()
                } else {
                    // collect roots and make sure there is only 1 root, this is probably redundant
                    log::warn!(
                        "> 1 locations given for function pointer type computation, checking if they have the same eq class and using a representative"
                    );
                    let eq_solver = &self.ptr_provenance.constraints;
                    let roots = poison_locs
                        .iter()
                        .flat_map(|l| eq_solver.to_maybe_num(l))
                        .map(|l| eq_solver.find(l))
                        .collect::<HashSet<u32>>();
                    assert!(
                        roots.len() == 1,
                        "Locations from {} > 1 equivalence classes are given, maybe the taint analysis is incomplete?",
                        roots.len()
                    );
                    eq_solver.to_var(roots.into_iter().next().unwrap()).unwrap()
                };
                Type::Fn(self.compute_fn_sig(
                    FnTaintInfo::FnPtr(loc),
                    &sig,
                    &*config,
                    TypeRewriteCtx::Struct(Node::FnPtr(loc.clone(), sig.clone())),
                ))
            },
            // skip
            //
            // Type::Fn(ref sig) if self.in_typedef_rewrite => {
            //     log::warn!(
            //         "no locations for function with signature {:?}. Pretending that it is not poisoned.",
            //         resolved_type
            //     );
            //     let config = CONFIG.read().unwrap();
            //     let loc = Loc::fresh();
            //     Type::Fn(self.compute_fn_sig(
            //         FnTaintInfo::FnPtr(&loc),
            //         sig,
            //         &*config,
            //         TypeRewriteCtx::FnSig(&mut LifetimeGen::explicit_by_default()),
            //     ))
            // },
            Type::Fn(_) => {
                log::warn!(
                    "no locations for function with signature {:?}.",
                    resolved_type
                );
                resolved_type
            },
            // it is a non-ptr, non-fn, non-struct field, keep it as is for now
            r => r,
        }
    }

    fn rewrite_struct(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        ident: Ident,
        fields: &[FieldDef<'_>],
        span: Span,
        only_impl_default: bool,
    ) {
        if only_impl_default {
            log::error!(
                "generating only impl Default for `{}`, and not rewriting it otherwise because it occurs in external APIs",
                name
            );
        }

        let node = Node::Struct(name.clone());
        // Add the lifetime parameters after the name
        let lifetime_param_string = self
            .lifetime_params
            .get(&node)
            .cloned()
            .map_or("".to_string(), |lifetime_params| {
                format!("<{}>", lifetime_params.iter().join(", "))
            });

        self.remove_derive = false;

        if self.struct_info.has_boxes.contains(&node) {
            // this struct is not copyable because it contains a Box, comment
            // out the `#[derive(Copy, Clone)]` attribute
            self.remove_derive = true;
        }

        if lifetime_param_string != "" {
            self.make_suggestion(
                ctx,
                ident.span.shrink_to_hi(),
                format!("Add lifetime parameters to the struct {}", name),
                lifetime_param_string.clone(),
            );
        }

        // default values of the fields
        let mut default_values: Vec<(Name, Option<String>)> = vec![];
        // check if we can generate a value for all fields
        let generate_default = self
            .struct_info
            .can_generate_default(&Type::Struct(name.clone()));
        if !generate_default {
            log::debug!("cannot generate default for {:?}", name);
        }

        {
            // Rewrite types inside that we introduced a lifetime for, and
            // generate default values
            for FieldDef { ident, ty, .. } in fields {
                let field = Name::from(&*ident.as_str());
                let lifetime = self
                    .lifetimes
                    .get(&(node.clone(), Link::Field(field.clone())))
                    .cloned();
                let resolved_type = self.struct_info.resolve_type(&Type::from_hir_ty(ctx, ty));
                let loc = Some(Loc::Access(name.clone(), field.clone()))
                    .into_iter()
                    .collect::<HashSet<Loc<Name>>>();
                let new_field_ty = if only_impl_default {
                    resolved_type.clone()
                } else {
                    self.compute_field_type(resolved_type.clone(), lifetime, loc.clone())
                };

                // if this field is not copy-able, comment out the
                // `#[derive(Copy, Clone)]` attribute.
                self.remove_derive = self.remove_derive
                    || match &new_field_ty {
                        Type::CustomSlice(slice_ty, _) => {
                            matches!(slice_ty.cell(), CustomSliceCell::RefCell)
                        },
                        Type::Ref(mutbl, _, _) => *mutbl == Mutability::Mut,
                        Type::OptionT(box Type::Boxed(..)) => true,
                        Type::OptionT(box Type::Ref(mutbl, _, _)) => *mutbl == Mutability::Mut,
                        ty if ty.is_primitive() => false,
                        Type::OptionT(box Type::Fn(..)) | Type::Fn(..) => false,
                        _ => {
                            let mut locs = HashSet::default();
                            better::compiler_interface::error_handling::collect_ptr_locs(
                                &self.struct_info,
                                &self.ptr_provenance,
                                &resolved_type,
                                loc,
                                &mut locs,
                            );
                            locs.iter().any(|l| {
                                !self.ptr_provenance.is_poisoned(l)
                                    || ptr_arith::is_unique_poison(self.ptr_provenance.poisons(l))
                            })
                        },
                    };

                if generate_default {
                    default_values.push((field, self.default_value(&new_field_ty)));
                }

                // insert the rewrite
                self.make_suggestion(
                    ctx,
                    ty.span,
                    "introduce lifetime and re-write expanded typedef".to_owned(),
                    format!("{}", new_field_ty),
                );
            }
        }
        DEBUG.store(false, Ordering::SeqCst);

        if generate_default {
            // implement std::default::Default for this struct
            let default_impl = format!(
                "
impl{0} {1}{0} {{
    pub const fn new() -> Self {{
        {1} {{
{2}
        }}
    }}
}}

impl{0} std::default::Default for {1}{0} {{
    fn default() -> Self {{ {1}::new() }}
}}
",
                lifetime_param_string,
                ident.name.as_str(),
                default_values
                    .into_iter()
                    .map(|(field, init)| format!(
                        "        {}: {}",
                        field,
                        init.expect(&format!(
                            "should have generated a default value for {}.{}",
                            name, field
                        ))
                    ))
                    .join(",\n")
            );

            // TODO: don't generate this for structs containing extern
            // types, and add miscallenous poison to all the values in
            // them
            self.make_suggestion(
                ctx,
                span.shrink_to_hi(),
                "implement Default trait".to_owned(),
                default_impl,
            );
        }
    }

    fn rewrite_typedef(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        lhs_span: Span,
        ty: &rustc_hir::Ty,
    ) {
        log::warn!("RL————rewrite_typedef: name {:?}", name);
        self.in_typedef_rewrite = true;
        // rewrite the RHS using field rewrite logic
        let resolved_type = self.struct_info.resolve_type(&Type::from_hir_ty(ctx, ty));
        let new_ty = self.compute_field_type(resolved_type, None, HashSet::default());

        // insert the rewrite
        self.make_suggestion(
            ctx,
            ty.span,
            "re-write expanded typedef".to_owned(),
            format!("{}", new_ty),
        );

        // collect the lifetimes on the RHS and add them as parameters
        let mut lifetime_params = BTreeSet::new();
        new_ty.collect_lifetimes_into(&mut lifetime_params);

        if !lifetime_params.is_empty() {
            self.make_suggestion(
                ctx,
                lhs_span.shrink_to_hi(),
                format!("Add lifetime parameters to the typedef {}", name),
                format!("<{}>", lifetime_params.iter().join(", ")),
            );
        }
        self.in_typedef_rewrite = false;
    }

    fn fn_has_unsafety_we_cannot_handle(
        &self,
        _ctx: &LateContext,
        fn_name: &Name,
        fn_decl: &FnDecl,
    ) -> bool {
        if fn_decl.c_variadic {
            return true;
        }

        // TODO: check if any statements in this function can't be fixed, maybe have this when traversing the body

        self.fns_we_cannot_handle.contains(fn_name)
        // TODO: check extern ub here
    }

    /// Generates the string representation of a version of the given
    /// fn header that is not unsafe.
    fn safe_header_snippet(fn_header: FnHeader) -> String {
        assert_eq!(fn_header.asyncness, IsAsync::NotAsync);
        let const_str = if fn_header.is_const() { "const " } else { "" };
        let extern_str = if fn_header.abi == Abi::Rust {
            "".to_string()
        } else {
            format!("extern \"{}\" ", fn_header.abi.name())
        };
        format!(" {}{}fn ", const_str, extern_str)
    }

    /// Checks if the given expression is poisoned
    fn is_poisoned(&self, hir_id: HirId) -> bool {
        if let Some(Term::S(LV(inner_loc))) = self.ptr_provenance.expr_to_term.get(&hir_id) {
            self.ptr_provenance.is_poisoned(inner_loc)
        } else {
            false
        }
    }

    /// Checks if the given expression is uniquely poisoned by pointer arithmetic
    fn is_ptr_arith(&self, hir_id: HirId) -> bool {
        ptr_arith::is_unique_poison(self.poisons(hir_id))
    }

    /// Returns the poison sets of the given expression
    fn poisons(&self, hir_id: HirId) -> (HashSet<PoisonKind>, HashSet<PoisonKind>) {
        if let Some(Term::S(LV(inner_loc))) = self.ptr_provenance.expr_to_term.get(&hir_id) {
            if self.ptr_provenance.is_poisoned(inner_loc) {
                return self.ptr_provenance.poisons(inner_loc);
            }
        }
        Default::default()
    }

    // TODO(maemre): document
    // TODO: analyze is_owned and is_refcell
    /// Rewrites given expression if it can be rewritten as an arithmetic
    /// expression. Returns a tuple consisting of the following if the rewrite
    /// is successful:
    ///
    /// - A vector of subexpressions that should be recursively rewritten.
    ///
    /// - Whether the rewritten expression is a temporary reference (i.e., it
    /// borrows some other value). This is useful for making sure that we aren't
    /// re-borrowing temporary references as return values.
    fn rewrite_ptr_arith<'a>(
        &self,
        ctx: &LateContext,
        poison_id: HirId,
        expr: &'a Expr<'a>,
        rewrite_ctx: RewriteCtx,
        deref: Option<&'a Expr<'a>>,
        handled: &mut bool,
    ) -> Option<(Vec<&'a Expr<'a>>, bool)> {
        use CustomSliceCell as SliceCell;
        use Mutability as Mut;
        use PointerAddMode as AddMode;

        let mut_ctx = rewrite_ctx.m;

        #[derive(Debug, Clone, Copy)]
        enum Flow {
            Borrow(Mut),
            Move,
        }

        #[derive(Debug, Clone, Copy)]
        enum OpType {
            /// Dereference a single index
            Get(Mut),
            /// Update the slice offset
            Slice(Flow),
        }

        #[derive(Debug, Clone, Copy)]
        struct Format {
            /// Does the self parameter need parentheses
            self_hygienic: bool,
            /// Is the self parameter wrapped in Option<T>
            self_is_opt: bool,
            /// Does the index parameter need parentheses
            index_hygienic: bool,
        }

        // Return the rewrite triple (code to insert before, middle, after) for the given slice operation
        fn slice_op(
            op_type: OpType,
            slice_cell: SliceCell,
            add_mode: AddMode,
            format: Format,
            span: Span,
        ) -> (String, String, &'static str) {
            log::trace!(
                "slice_op(\n  op_type = {:?}\n  slice_cell = {:?}\n  add_mode = {:?}\n  format = {:?}\n  span = {:?}\n)",
                op_type,
                slice_cell,
                add_mode,
                format,
                span
            );

            let Format {
                self_hygienic,
                self_is_opt,
                index_hygienic,
            } = format;

            // whether to borrow with mutability or move the slice ref
            let flow = match op_type {
                OpType::Get(mutbl) => match (mutbl, slice_cell) {
                    (Mut::Not, _) | (_, SliceCell::RefCell) => Flow::Borrow(Mut::Not),
                    (Mut::Mut, SliceCell::NoCell) => Flow::Borrow(Mut::Mut),
                },
                OpType::Slice(flow) => flow,
            };

            (
                // repl_lo
                format!(
                    "{prefix}crate::__laertes_array::{trait_fn}_{mode}{mutbl}({prefix_slice}{self_paren}",
                    prefix = match op_type {
                        OpType::Get(..) => "(*",
                        OpType::Slice(..) => "Some(",
                    },
                    trait_fn = match op_type {
                        OpType::Get(mutbl) => match (mutbl, slice_cell) {
                            // Non-RefCell indexes
                            (Mut::Not, SliceCell::NoCell) => "Get::<&_>::get",
                            (Mut::Mut, SliceCell::NoCell) => "GetMut::<&mut _>::get",

                            // RefCell indexes
                            (Mut::Not, SliceCell::RefCell) => "Get::<::std::cell::Ref<_>>::get",
                            (Mut::Mut, SliceCell::RefCell) => "Get::<::std::cell::RefMut<_>>::get",
                        },
                        OpType::Slice(flow) => match flow {
                            Flow::Borrow(Mut::Not) => "Slice::slice",
                            Flow::Borrow(Mut::Mut) => "SliceMut::slice",
                            Flow::Move => "IntoSlice::into_slice",
                        },
                    },
                    mode = match add_mode {
                        AddMode::Signed => "offset",
                        AddMode::Add => "add",
                        AddMode::Sub => "sub",
                    },
                    mutbl = match flow {
                        Flow::Borrow(Mut::Mut) => "_mut",
                        Flow::Borrow(Mut::Not) | Flow::Move => "",
                    },
                    prefix_slice = if self_is_opt {
                        ""
                    } else {
                        match flow {
                            Flow::Borrow(Mut::Not) => "&",
                            Flow::Borrow(Mut::Mut) => "&mut ",
                            Flow::Move => "",
                        }
                    },
                    self_paren = if self_hygienic { "" } else { "(" },
                ),
                // repl_mid
                format!(
                    "{self_paren}{suffix_slice}, {index}",
                    self_paren = if self_hygienic { "" } else { ")" },
                    suffix_slice = if self_is_opt {
                        match flow {
                            Flow::Borrow(Mut::Not) => ".as_ref().unwrap()",
                            Flow::Borrow(Mut::Mut) => ".as_mut().unwrap()",
                            Flow::Move => ".unwrap()",
                        }
                    } else {
                        ""
                    },
                    index = if index_hygienic { "" } else { "(" },
                ),
                // repl_hi
                if index_hygienic { "))" } else { ")))" },
            )
        }

        let get_flow = |lhs_id: Option<HirId>| {
            log::trace!(
                "TODO REMOVE THIS but anyway checking expr {:?} and deref {:?} and lhs {:?} against {:#?}",
                expr.hir_id,
                deref.map(|d| d.hir_id),
                lhs_id,
                self.config.move_flows
            );

            if Some(expr.hir_id)
                .into_iter()
                .chain(deref.map(|d| d.hir_id))
                .chain(lhs_id)
                .any(|i| self.config.is_move(i))
                // if this is an argument or initializer, make sure that the
                // sink for this expression is owned.
                && self.ptr_provenance.arg_or_init.get(&expr.hir_id).map_or(true, |f|
                                                                            f.is_owned(&self.ptr_provenance))
            {
                log::trace!("move flow at {:?}", expr.span);
                return Flow::Move;
            }

            let relevant_hir_id = deref.as_ref().map_or(expr.hir_id, |d| d.hir_id);
            log::trace!(
                "mut ctx {:?} / owned: {} at {:?}",
                mut_ctx,
                self.ptr_provenance.is_owned(relevant_hir_id),
                expr.span
            );
            match (mut_ctx, self.ptr_provenance.is_owned(relevant_hir_id)) {
                (MutCtx::Not, false) => Flow::Borrow(Mut::Not),
                (MutCtx::Mut, false) | (MutCtx::Assignee, false) => Flow::Borrow(Mut::Mut),
                (MutCtx::Unknown, false) => Flow::Borrow(
                    if ctx.typeck_results().expr_ty_adjusted(expr).is_mutable_ptr() {
                        Mut::Mut
                    } else {
                        Mut::Not
                    },
                ),
                (_, true) | (MutCtx::Move, _) => Flow::Move,
            }
        };

        let parsed = ptr_arith::parse_expr_late(ctx, expr);
        log::trace!("parsed: {:?}", parsed);

        if !self.is_ptr_arith(poison_id)
            && !matches!(
                parsed,
                Some(PtrArithExpr {
                    op: PtrArithOp {
                        ty: PtrArithOpType::OffsetFrom,
                        ..
                    },
                    ..
                })
            )
        {
            if log::log_enabled!(log::Level::Trace) {
                if let Some(op) = parsed {
                    log::trace!(
                        "not processing unpoisoned ptr arith op {:#?} at {:?} (poisons: {:?})",
                        op.op,
                        expr.span,
                        self.poisons(poison_id),
                    );
                }
            }

            return None;
        }

        let flow = get_flow(parsed.as_ref().map(|p| p.lhs.hir_id));

        let slice_cell = if self
            .ptr_provenance
            .is_refcell(parsed.as_ref().map_or(expr.hir_id, |p| p.lhs.hir_id))
        {
            SliceCell::RefCell
        } else {
            SliceCell::NoCell
        };

        let rewrite_binary = |op_type, mode, fmt, lhs: &Expr, rhs: &Expr| {
            let (repl_lo, repl_mid, repl_hi) = slice_op(op_type, slice_cell, mode, fmt, expr.span);

            let span_outer = deref.map_or(expr.span, |d| d.span);
            let ctxt = span_outer.ctxt();
            let span_lo = Span::new(span_outer.lo(), lhs.span.lo(), ctxt, None);
            let span_mid = Span::new(lhs.span.hi(), rhs.span.lo(), ctxt, None);
            let span_hi = Span::new(rhs.span.hi(), span_outer.hi(), ctxt, None);

            const MSG: &str = "ptr_arith: rewrite pointer offset";

            self.make_suggestion(ctx, span_lo, MSG.into(), repl_lo);
            self.make_suggestion_after(ctx, span_mid, MSG.into(), repl_mid);
            self.make_suggestion_after(ctx, span_hi, MSG.into(), repl_hi.into());
        };

        // TODO (ryans): hack, but all other solutions seem pretty intensive at the moment
        let try_strip_receiver_opt = |receiver: &'a Expr<'a>, out: Option<&mut &'a Expr<'a>>| {
            match ptr_arith::parse_expr_late(ctx, receiver) {
                Some(PtrArithExpr {
                    op:
                        PtrArithOp {
                            ty: PtrArithOpType::SliceAsPtr { is_range: false },
                            ..
                        },
                    lhs,
                    rhs: None,
                }) => {
                    out.map(|out| {
                        let ctxt = receiver.span.ctxt();
                        let span_lo = Span::new(receiver.span.lo(), lhs.span.lo(), ctxt, None);
                        let span_hi = Span::new(lhs.span.hi(), receiver.span.hi(), ctxt, None);

                        const MSG: &str = "ptr_arith: remove slice->ptr conversion";

                        self.make_suggestion(ctx, span_lo, MSG.into(), "".into());
                        self.make_suggestion_after(ctx, span_hi, MSG.into(), "".into());

                        *out = lhs;
                    });

                    false
                },
                Some(_) | None => false,
            }
        };

        log::trace!(
            "rewrite_ptr_arith\n  slice_cell = {:?}\n  flow = {:?}\n  expr = {:?}\n  parsed = {:#?}",
            slice_cell,
            flow,
            deref.map_or(expr.span, |d| d.span),
            parsed.as_ref().map(|p| p.op),
        );

        let ret: Option<(Vec<&Expr>, bool)> = match (parsed, deref) {
            (
                Some(PtrArithExpr {
                    op:
                        PtrArithOp {
                            is_mut: _,
                            ty: PtrArithOpType::Add { mode, wrap: _ },
                        },
                    mut lhs,
                    rhs: Some(rhs),
                }),
                deref_span,
            ) => {
                let op_type = deref_span.map_or(OpType::Slice(flow), |_| {
                    OpType::Get(match flow {
                        Flow::Borrow(mutbl) => mutbl,
                        Flow::Move => Mut::Mut,
                    })
                });
                rewrite_binary(
                    op_type,
                    mode,
                    Format {
                        self_hygienic: true,
                        self_is_opt: !try_strip_receiver_opt(lhs, None),
                        index_hygienic: false,
                    },
                    lhs,
                    rhs,
                );

                try_strip_receiver_opt(lhs, Some(&mut lhs));

                Some((vec![lhs, rhs], matches!(op_type, OpType::Slice(..))))
            },
            (e, Some(deref)) => {
                if let Some(e) = e {
                    log::debug!(
                        "bypassing ptr arith op {:?} for deref at {:?}",
                        e.op,
                        expr.span
                    );
                }

                const MSG: &str = "ptr_arith: rewrite pointer deref";

                let (repl_lo, repl_mid, repl_hi) = slice_op(
                    OpType::Get(match flow {
                        Flow::Borrow(mutbl) => mutbl,
                        Flow::Move => {
                            log::warn!(
                                "Implicit slice get operation in move context at {:?}",
                                expr.span
                            );

                            if mut_ctx == MutCtx::Not {
                                Mut::Not
                            } else {
                                Mut::Mut
                            }
                        },
                    }),
                    slice_cell,
                    AddMode::Add,
                    Format {
                        self_hygienic: false,
                        self_is_opt: !try_strip_receiver_opt(expr, None),
                        index_hygienic: true,
                    },
                    expr.span,
                );
                let repl_hi = format!("{}0{}", repl_mid, repl_hi);

                let deref_span = deref.span;
                let span_lo = Span::new(deref_span.lo(), expr.span.lo(), deref_span.ctxt(), None);
                let span_hi = Span::new(expr.span.hi(), deref_span.hi(), deref_span.ctxt(), None);

                self.make_suggestion(ctx, span_lo, MSG.into(), repl_lo);
                self.make_suggestion_after(ctx, span_hi, MSG.into(), repl_hi);

                let mut ret = expr;

                try_strip_receiver_opt(ret, Some(&mut ret));

                // NOTE: This relies on deref_span being Some to not cause a stack overflow
                Some((vec![ret], false))
            },
            /******** NOTE: ALL CASES BELOW THIS WILL NOT FIRE FOR UnDeref ********/
            (
                Some(PtrArithExpr {
                    op:
                        PtrArithOp {
                            is_mut: None,
                            ty: PtrArithOpType::AddSafe,
                        },
                    lhs,
                    rhs: Some(rhs),
                }),
                None,
            ) => {
                rewrite_binary(
                    OpType::Get(match flow {
                        Flow::Borrow(mutbl) => mutbl,
                        Flow::Move => panic!(
                            "Native slice get operation in move context at {:?}",
                            expr.span
                        ),
                    }),
                    AddMode::Add,
                    Format {
                        self_hygienic: false,
                        self_is_opt: true,
                        index_hygienic: false,
                    },
                    lhs,
                    rhs,
                );

                // This is not a temporary ref because the OpType we use is Get
                Some((vec![lhs, rhs], false))
            },
            (
                Some(PtrArithExpr {
                    op:
                        PtrArithOp {
                            is_mut: Some(is_mut),
                            // TODO: can we handle ranges? do they even occur in the wild?
                            ty: PtrArithOpType::SliceAsPtr { is_range: false },
                        },
                    lhs: inner,
                    rhs: None,
                }),
                None,
            ) => {
                const MSG: &str = "ptr_arith: rewrite slice->ptr conversion";
                const DUMMY_SLICE_AS_PTR: bool = false; // Less compatible but maybe simpler?

                // TODO: todo
                let guess_flow = match (is_mut, self.ptr_provenance.is_owned(expr.hir_id)) {
                    (false, false) => Flow::Borrow(Mut::Not),
                    (true, false) => Flow::Borrow(Mut::Mut),
                    (_, true) => Flow::Move,
                };

                log::debug!(
                    "guess_flow: {:?} and flow: {:?} at {:?}",
                    guess_flow,
                    flow,
                    expr.span
                );

                // TODO: it would be nice to use borrow_mut here, but it creates a temporary
                let (repl_lo, repl_hi) = if DUMMY_SLICE_AS_PTR {
                    // ("Some(", ")")
                    ("Some(".into(), ")".into())
                } else {
                    // ("crate::__laertes_array::borrow_mut(&mut Some(", "))")
                    let (repl_lo, repl_mid, repl_hi) = slice_op(
                        OpType::Slice(flow),
                        slice_cell,
                        AddMode::Add,
                        Format {
                            self_hygienic: true,
                            self_is_opt: true,
                            index_hygienic: true,
                        },
                        expr.span,
                    );
                    let repl_hi = format!("{}0{}", repl_mid, repl_hi);

                    (repl_lo, repl_hi)
                };

                let span_lo = Span::new(expr.span.lo(), inner.span.lo(), expr.span.ctxt(), None);
                let span_hi = Span::new(inner.span.hi(), expr.span.hi(), expr.span.ctxt(), None);

                self.make_suggestion(ctx, span_lo, MSG.into(), repl_lo.into());
                self.make_suggestion_after(ctx, span_hi, MSG.into(), repl_hi.into());

                Some((vec![inner], true))
            },
            (
                Some(PtrArithExpr {
                    op:
                        PtrArithOp {
                            is_mut: _,
                            ty: PtrArithOpType::OffsetFrom,
                        },
                    lhs,
                    rhs: Some(rhs),
                }),
                None,
            ) if self.is_ptr_arith(lhs.hir_id) && self.is_ptr_arith(rhs.hir_id) => {
                let ctxt = expr.span.ctxt();
                let span_lo = Span::new(expr.span.lo(), lhs.span.lo(), ctxt, None);
                let span_mid = Span::new(lhs.span.hi(), rhs.span.lo(), ctxt, None);
                let span_hi = Span::new(rhs.span.hi(), expr.span.hi(), ctxt, None);

                const MSG: &str = "ptr_arith: rewrite offset_from";

                self.make_suggestion(
                    ctx,
                    span_lo,
                    MSG.into(),
                    "crate::__laertes_array::offset_from(& ".into(),
                );
                self.make_suggestion_after(ctx, span_mid, MSG.into(), ", & ".into());
                self.make_suggestion_after(ctx, span_hi, MSG.into(), ")".into());
                Some((vec![lhs, rhs], false))
            },
            (Some(e), None) => {
                log::warn!("not processing ptr arith op {:?} at {:?}", e.op, expr.span);
                None
            },
            (None, None) => {
                log::debug!("not processing non-ptr arith op at {:?}", expr.span);
                None
            },
        };

        *handled = *handled || ret.is_some();

        ret
    }

    fn wrap_array_lit(&self, ctx: &LateContext, expr: &Expr) {
        const MSG: &str = "ptr_arith: Wrap this array in a CustomSlice";

        let span = expr.span;

        if self.ptr_provenance.is_refcell(expr.hir_id) {
            let (item, array) =
                match Type::from_ty(ctx, ctx.typeck_results().expr_ty_adjusted(expr)) {
                    Type::Array(inner, len) => (
                        inner.clone(),
                        Type::Array(Box::new(Type::RefCell(inner)), len),
                    ),
                    _ => todo!("compute array literal type"),
                };

            self.make_suggestion(
                ctx,
                span.shrink_to_lo(),
                MSG.into(),
                format!(
                    "Some(crate::__laertes_array::CustomSlice::<{}, {}>::from_vec(vec!",
                    item, array,
                ),
            );
            self.make_suggestion_after(ctx, span.shrink_to_hi(), MSG.into(), "))".into());
        } else if self.ptr_provenance.is_owned(expr.hir_id) {
            self.make_suggestion(
                ctx,
                span.shrink_to_lo(),
                MSG.into(),
                "Some(crate::__laertes_array::CustomSlice::boxed_from_vec(vec!".into(),
            );
            self.make_suggestion_after(ctx, span.shrink_to_hi(), MSG.into(), "))".into());
        } else {
            self.make_suggestion(
                ctx,
                span.shrink_to_lo(),
                MSG.into(),
                "Some(crate::__laertes_array::CustomSlice::new(".into(),
            );
            self.make_suggestion_after(ctx, span.shrink_to_hi(), MSG.into(), "))".into());
        }
    }

    /// Check if the given expression immediately flows into a raw pointer.
    #[inline(always)]
    fn flows_into_raw(&self, hir_id: &HirId, rewrite_ctx: &RewriteCtx) -> bool {
        let query_df_edge_to_raw = |hir_id| {
            self.ptr_provenance
                .arg_or_init
                .get(hir_id)
                .map_or(false, |f| f.is_poisoned(&self.ptr_provenance))
        };
        query_df_edge_to_raw(hir_id) || {
            if let Some(parent) = &rewrite_ctx.match_parent {
                query_df_edge_to_raw(parent)
            } else {
                false
            }
        }
    }

    /// Check if a rewritten type contains references that cannot be Copy (even as nested struct fields)
    fn contains_references(&self, ty: &Type) -> bool {
        match ty {
            Type::Struct(name) => {
                self.struct_info.struct_defs[name]
                    .fields
                    .iter()
                    .any(|(field, ty)| {
                        self.contains_references(
                            &self.rewrite_type(
                                &self.struct_info.resolve_type(&ty),
                                Some(Loc::Access(name.clone(), field.clone()))
                                    .iter()
                                    .collect(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            ),
                        )
                    })
            },
            Type::Union(name) => {
                self.struct_info.union_defs[name]
                    .fields
                    .iter()
                    .any(|(field, ty)| {
                        self.contains_references(
                            &self.rewrite_type(
                                &self.struct_info.resolve_type(&ty),
                                Some(Loc::Access(name.clone(), field.clone()))
                                    .iter()
                                    .collect(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            ),
                        )
                    })
            },
            Type::App(box inner, _) => self.contains_references(inner),
            Type::OptionT(box inner) => self.contains_references(inner),
            Type::Array(box inner, _) => self.contains_references(inner),
            Type::Tuple(inner) => inner.iter().any(|t| self.contains_references(t)),
            Type::Ptr(..) => false,
            Type::Fn(..) => false,
            Type::Syntactic(..) => false,
            Type::Str => false, // str implements Copy, so it is fine in this context
            Type::Ref(..)
            | Type::Boxed(..)
            | Type::Slice(..)
            | Type::CustomSlice(..)
            | Type::RefCell(..) => true,
            Type::Bool | Type::Char | Type::Int(_) | Type::Uint(_) | Type::Float(_) => false,
            Type::Extern(..) | Type::Never | Type::Opaque | Type::Unknown(..) | Type::Enum(..) => {
                false
            }, // this is underapproximating
        }
    }

    /// Rewrite given expression to eliminate raw pointers.
    ///
    /// `rewrite_ctx` indicates the context the expression is used in
    /// to determine how to re-borrow mutable references, and whether
    /// it is an argument to a call to free().
    fn rewrite_expr(&mut self, ctx: &LateContext<'_>, expr: &Expr<'_>, rewrite_ctx: RewriteCtx) {
        // log::warn!("++++++rewrite_expr: {:?}", expr);
        self.depth += 2;
        // Is this a raw pointer (after rewrites) dereference
        let mut raw_pointer_deref = false;
        // Whether the current expression is already a temporary reference (it
        // borrows another object, and its lifetime doesn't need any further
        // reduction). In this case, we don't need to add another borrow. In
        // fact, double borrowing would cause compiler errors if this reference
        // is supposed to escape the current scope (e.g., it is a return value).
        let mut already_borrowed_in_temp = false;
        let mut ptr_arith_handled = false;
        // Whether current expression is a block-containing expression
        // (a block or if statement). This is used for skipping
        // borrows around cases where the grammar requires a block or
        // double-borrows (one around the block, another around the
        // last expression).
        let mut block_expr = false;
        // Whether we rewrote a null ptr to None, in this case we don't need
        // borrow/borrow_mut (and we should drop them for arrays so that type
        // inference can work)
        let mut rewrote_null_ptr = false;
        // Is this expression's result being moved through move
        // flows. For most expressions, the following condition is
        // enough, but for the limit study, we may also need to check
        // the inner expression of a cast
        let mut is_move = self
            .config
            .move_flows
            .contains(&SerializableHirId(expr.hir_id));
        if is_move {
            log::trace!("move at {:?}", expr.span);
        }
        // true if the current expression is raw OR at a raw
        // pointer boundary (i.e., about to become raw).
        let flows_into_raw =
            self.is_poisoned(expr.hir_id) || self.flows_into_raw(&expr.hir_id, &rewrite_ctx);

        // Is this expression a box derived from malloc
        let mut box_from_malloc = false;
        match &expr.kind {
            ExprKind::Array(elems) => {
                if self.is_ptr_arith(expr.hir_id) {
                    self.wrap_array_lit(ctx, expr);
                }

                elems.iter().for_each(|e| {
                    self.rewrite_expr(ctx, e, RewriteCtx::unknown());
                })
            },
            ExprKind::Repeat(elem, _len) => {
                // extract size from type, as it is easier than walking the AST
                let size = if let Type::Array(_, Some(n)) =
                    Type::from_ty(ctx, ctx.typeck_results().expr_ty(expr))
                {
                    n
                } else {
                    unreachable!("unexpected lit kind in repeat expression: {:?} ");
                };
                match elem.kind {
                    ExprKind::Cast(inner, _ty)
                        if matches!(get_constant_value(inner), Some(LitKind::Int(0, _))) =>
                    {
                        // If we are repeating a series of null pointers, then
                        // expand this repeat to account for the fact that
                        // Option<&mut _> is non-Copy (even if it's known to be
                        // null)

                        let cast_ty = ctx.typeck_results().expr_ty(elem);
                        if matches!(cast_ty.kind(), rustc_middle::ty::TyKind::RawPtr(_))
                            && (!self.is_poisoned(elem.hir_id) || self.is_ptr_arith(elem.hir_id))
                            && !self.flows_into_raw(&elem.hir_id, &rewrite_ctx.reset_parent())
                        {
                            let loc = self.ptr_provenance.expr_to_term[&elem.hir_id]
                                .get_lv()
                                .into_iter()
                                .collect::<HashSet<&Loc<Name>>>();
                            match self.rewrite_type(
                                &Type::from_ty(ctx, cast_ty),
                                loc.clone(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            ) {
                                Type::OptionT(new_ty) => {
                                    let expanded_repeat = format!(
                                        "[{}]",
                                        format!("Option::<{}>::None,", new_ty).repeat(size)
                                    );
                                    self.make_suggestion(
                                        ctx,
                                        expr.span,
                                        "rewrite repeated array full of null pointers".to_owned(),
                                        expanded_repeat,
                                    );
                                },
                                Type::Ptr(..) => {
                                    // This will be kept as a pointer, so we can repeat it
                                    self.rewrite_expr(ctx, elem, rewrite_ctx.reset_parent());
                                },
                                t => {
                                    let l = self.ptr_provenance.expr_to_term[&expr.hir_id]
                                        .get_lv()
                                        .unwrap();
                                    unreachable!(
                                        "the new type should be surrounded with an Option, got {:?} poisons: {:?}",
                                        t,
                                        self.ptr_provenance.poisons(l)
                                    );
                                },
                            }
                        } else {
                            self.rewrite_expr(ctx, elem, rewrite_ctx.reset_parent());
                        }
                    },
                    _ => {
                        // this returns Some(new type of the expression) if we need to expand the repeat
                        let should_expand_repeat = {
                            let loc = self.ptr_provenance.expr_to_term[&expr.hir_id]
                                .get_lv()
                                .into_iter()
                                .collect::<HashSet<&Loc<Name>>>();
                            let ty = self.rewrite_type(
                                &Type::from_ty(ctx, ctx.typeck_results().expr_ty(expr)),
                                loc.clone(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            );
                            (is_zero_initializer(elem)
                                && self.struct_info.can_generate_default(&ty)
                                && self.contains_references(&ty))
                            .then(|| ty)
                        };
                        if let Some(Type::Array(elem_ty, _)) = should_expand_repeat {
                            // if this expression is just creating a default value, replace it with "Default::default"

                            // println!("expanding {}", elem_ty);
                            let elem_init =
                                self.struct_info.zero_initializer(&elem_ty, |ty, loc| {
                                    self.rewrite_type(
                                        &ty,
                                        Some(loc).iter().collect(),
                                        &mut vec![],
                                        &mut LifetimeGen::implicit_only(),
                                    )
                                });
                            // println!("element initializer: {}", elem_init);
                            // note: issues with globals!
                            self.make_suggestion(
                                ctx,
                                expr.span,
                                "expand repeated array of default values".to_owned(),
                                format!("[{}]", format!("{}, ", elem_init).repeat(size)),
                            );
                        } else {
                            self.rewrite_expr(ctx, elem, rewrite_ctx.reset_parent())
                        }
                    },
                };

                if self.is_ptr_arith(expr.hir_id) {
                    self.wrap_array_lit(ctx, expr);
                }
            },
            ExprKind::Call(callee, args) => {
                // log::warn!("rewrite_expr::ExprKind::Call {:?}", &callee.kind);
                if let ExprKind::Path(qpath) = &callee.kind {
                    if let QPath::Resolved(_, p) = qpath {
                        // println!("{}", p.segments[0].ident.as_str().to_string());
                        let segs = p.segments;
                        for seg in segs {
                            // log::warn!("++++++ExprKind::Call {:?}", seg.ident.as_str());
                            if seg.ident.as_str().contains("atomic_cxchg") {
                                if !matches!(
                                    &callee,
                                    Expr {
                                        kind: ExprKind::Path(_),
                                        ..
                                    }
                                ) {
                                    self.rewrite_expr(ctx, callee, RewriteCtx::unknown());
                                }
                                return;
                            }
                        }
                    }
                }
                // Note: We pass MutCtx::None for rewriting the callee because
                // calling a *function pointer* does not require mutable access,
                // as all function pointers implement the `Fn` trait.
                let ptr_arith_args = if matches!(
                    &callee,
                    Expr {
                        kind: ExprKind::Path(_),
                        ..
                    }
                ) {
                    self.rewrite_ptr_arith(
                        ctx,
                        expr.hir_id,
                        expr,
                        RewriteCtx::not(),
                        None,
                        &mut ptr_arith_handled,
                    )
                } else {
                    // rewrite the callee if it is not a direct function call
                    self.rewrite_expr(ctx, callee, RewriteCtx::not());
                    None
                };

                already_borrowed_in_temp = matches!(ptr_arith_args, Some((_, true)));

                // extract parameter locations for calls to non-built-in
                // functions
                let callee_loc = self.ptr_provenance.expr_to_term[&callee.hir_id]
                    .get_lv()
                    .unwrap();
                let mut param_locs = self
                    .ptr_provenance
                    .project_lambdas(callee_loc, Some(args.len()))
                    .0;
                if param_locs.is_empty() {
                    param_locs.resize_with(args.len(), Default::default);
                }

                // get callee type to extract arity and varargs
                let callee_sig = if let Type::Fn(sig) =
                    Type::from_ty(ctx, ctx.typeck_results().expr_ty_adjusted(callee))
                {
                    sig
                } else {
                    unreachable!();
                };
                // log::warn!("++++++ callee_sig : {:?}", callee_sig);

                let mut is_rewritten_free = false;
                // Whether to force mutability in the arguments.
                let mut force_mut = false;

                // If this is a call to transmute, rewrite the source
                // and the target types
                if let Loc::Var(name) = callee_loc {
                    if name.ends_with("::free") {
                        if !self.ptr_provenance.is_expr_poisoned(args[0].hir_id) {
                            // this is a call to free that can be removed, we keep the expression inside, as it may have side effects
                            self.make_suggestion(
                                ctx,
                                callee.span,
                                "remove call to free".to_owned(),
                                "".to_owned(),
                            );
                            is_rewritten_free = true;
                        } else {
                            log::warn!(
                                "poisons at the argument of free: {:?}",
                                self.ptr_provenance.expr_poisons(args[0].hir_id)
                            );
                        }
                    } else if *name == *TRANSMUTE_FN {
                        let in_limit_study = LIMIT_STUDY.load(Ordering::Relaxed);
                        let type_of_expr = |e, adjusted| {
                            let typeck = ctx.typeck_results();
                            Type::from_ty(
                                ctx,
                                if adjusted {
                                    typeck.expr_ty_adjusted(e)
                                } else {
                                    typeck.expr_ty(e)
                                },
                            )
                        };
                        let get_loc =
                            |e: &Expr| self.ptr_provenance.expr_to_term[&e.hir_id].get_lv();
                        let rewrite_type_of_expr = |ty, associated_expr: &Expr| {
                            self.rewrite_type(
                                ty,
                                get_loc(associated_expr).into_iter().collect(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            )
                        };
                        let orig_source_type = type_of_expr(&args[0], true);
                        let orig_target_type = type_of_expr(expr, false);
                        log::debug!(
                            "transmute poisons: {:?}",
                            self.ptr_provenance.poisons(get_loc(expr).unwrap())
                        );

                        let (source_type, target_type, transmute_fn) = if in_limit_study {
                            let source_type = rewrite_type_of_expr(&orig_source_type, &args[0]);
                            let target_type = {
                                let t = rewrite_type_of_expr(&orig_target_type, expr);
                                match t {
                                    Type::Ref(m, l, box inner @ Type::Array(..))
                                        if !NO_PTR_ARITH_REWRITE.load(Ordering::Relaxed) =>
                                    {
                                        Type::Ref(m, l, Box::new(Type::OptionT(Box::new(inner))))
                                    },
                                    _ => t,
                                }
                            };

                            force_mut = matches!(source_type, Type::Ptr(Mutability::Mut, _));
                            // record this type rewrite
                            let fat_span = FatSpan::from_span(callee.span, ctx.sess().source_map());
                            let source_loc = get_loc(&args[0]).cloned();
                            let target_loc = get_loc(expr).cloned();
                            self.span_info.insert_rewritten_type(
                                fat_span.clone(),
                                orig_source_type,
                                source_loc,
                            );
                            self.span_info.insert_rewritten_type(
                                fat_span,
                                orig_target_type,
                                target_loc,
                            );
                            (source_type, target_type, "trans")
                        } else {
                            (orig_source_type, orig_target_type, TRANSMUTE_FN.as_ref())
                        };

                        // the actual rewrite
                        self.make_suggestion(
                            ctx,
                            callee.span,
                            "rewrite call to transmute".to_owned(),
                            format!("{}::<{}, {}>", transmute_fn, source_type, target_type),
                        );
                    }
                }

                // rewrite the arguments
                process_ptr_arith_args(
                    ptr_arith_args.map(|(args, _)| args),
                    || args.iter(),
                    |i, e| {
                        let is_param_owned = param_locs
                            .get(i)
                            .iter()
                            .map(|ls| ls.into_iter())
                            .flatten()
                            .any(|l| self.ptr_provenance.is_loc_owned(l));
                        let arg_mut_ctx = if is_param_owned {
                            MutCtx::Move
                        } else {
                            // get the type
                            let arg_ty = ctx.typeck_results().expr_ty_adjusted(e);
                            if callee_sig.c_variadic && i >= callee_sig.param_types.len() {
                                MutCtx::Not
                            } else if arg_ty.is_mutable_ptr() || force_mut {
                                MutCtx::Mut
                            } else if arg_ty.is_any_ptr() {
                                // Variadic functions don't care about type
                                // safety so we can get away with using const
                                // pointers.
                                MutCtx::Not
                            } else {
                                MutCtx::Unknown
                            }
                        };
                        let arg_ctx = RewriteCtx {
                            m: arg_mut_ctx,
                            in_free: is_rewritten_free,
                            match_parent: None,
                        };
                        self.rewrite_expr(ctx, e, arg_ctx);
                    },
                );
            },
            ExprKind::MethodCall(_callee, callee_span, args, _span) => {
                // rewrite: is_null, null, null_mut
                let callee_def_id = ctx
                    .typeck_results()
                    .type_dependent_def_id(expr.hir_id)
                    .unwrap();
                let callee_name = Name::from(get_def_qname(ctx, callee_def_id));
                // check and rewrite pointer methods, if the receiver is not poisoned
                let mut ptr_method_rewritten = false;
                if let Some(new_method) = PTR_METHOD_REWRITES.get(&callee_name) {
                    if !self.is_poisoned(args[0].hir_id) || self.is_ptr_arith(args[0].hir_id) {
                        ptr_method_rewritten = true;
                        self.make_suggestion(
                            ctx,
                            callee_span.clone(),
                            "rewrite pointer method".to_owned(),
                            new_method.clone(),
                        );
                    }
                }

                let ptr_arith_args = if !ptr_method_rewritten {
                    self.rewrite_ptr_arith(
                        ctx,
                        expr.hir_id,
                        expr,
                        rewrite_ctx.reset_parent(),
                        None,
                        &mut ptr_arith_handled,
                    )
                } else {
                    None
                };
                let is_arith_rewrite = ptr_arith_args.is_some();
                already_borrowed_in_temp = matches!(ptr_arith_args, Some((_, true)));

                // rewrite the arguments

                // TODO-MC: check the callee argument types to decide the mutable context
                process_ptr_arith_args(
                    ptr_arith_args.map(|p| p.0),
                    || args.iter(),
                    |i, e| {
                        let mutbl = if i == 0 && ptr_method_rewritten {
                            MutCtx::Not
                        } else if i == 0 && is_arith_rewrite {
                            log::trace!(
                                "using rewrite context = {:?} for {:?} at {:?}",
                                rewrite_ctx,
                                callee_name,
                                e.span
                            );
                            rewrite_ctx.m
                        } else {
                            let ty = Type::from_ty(ctx, ctx.typeck_results().expr_ty_adjusted(e));
                            // check if the expression is supposed to be a
                            // mutable reference, this matters for the
                            // method receivers as they need not be marked
                            // to be referenced.
                            if let Type::Ref(mutbl, _, _) = ty {
                                match mutbl {
                                    Mutability::Mut => MutCtx::Mut,
                                    Mutability::Not => MutCtx::Not,
                                }
                            } else if (matches!(ty, Type::Ptr(..))
                                && self.ptr_provenance.is_expr_poisoned(expr.hir_id))
                                || (ty.is_known_copyable() && !matches!(ty, Type::Ptr(..)))
                            {
                                // This is a raw pointer we will not
                                // rewrite, and it is cloneable, so we
                                // can treat it as immutable.
                                MutCtx::Not
                            } else {
                                MutCtx::Unknown
                            }
                        };
                        self.rewrite_expr(ctx, e, RewriteCtx::from_mc(mutbl));
                    },
                );
            },
            ExprKind::Tup(elems) => elems
                .iter()
                .for_each(|e| self.rewrite_expr(ctx, e, RewriteCtx::unknown())),
            ExprKind::Binary(op, lhs, rhs) => {
                //assert!(rewrite_ctx.m != MutCtx::Mut, "unexpected mutable context at {:?}", expr.span);
                let adjusted_lhs_ty = ctx.typeck_results().expr_ty_adjusted(lhs);
                let ty = Type::from_ty(ctx, adjusted_lhs_ty);
                let limit_study_exception = LIMIT_STUDY.load(Ordering::Relaxed)
                    && matches!(
                        op.node,
                        BinOpKind::Lt | BinOpKind::Gt | BinOpKind::Le | BinOpKind::Ge
                    );
                if (limit_study_exception || op.node == BinOpKind::Eq || op.node == BinOpKind::Ne)
                    && !(matches!(ty, Type::Ptr(..)) && self.is_poisoned(lhs.hir_id))
                {
                    let eq_check = match ty {
                        Type::Ptr(..) => {
                            // rewrite reference equality
                            let cmp_fn = match op.node {
                                BinOpKind::Eq => "_ref_eq(",
                                BinOpKind::Ne => "_ref_ne(",
                                _ if limit_study_exception => "_ref_eq(",
                                _ => unreachable!(),
                            };
                            Some((cmp_fn, ", ", ")"))
                        },
                        Type::Ref(_, _, box Type::OptionT(box Type::Fn(..))) => {
                            // rewrite function pointer equality to handle HRTB
                            // errors
                            Some(("(", ").map(|f| f as usize) == (", ").map(|f| f as usize)"))
                        },
                        _ => None,
                    };

                    if let Some((pre_check, in_between, post_check)) = eq_check {
                        self.make_suggestion(
                            ctx,
                            lhs.span.shrink_to_lo(),
                            "rewrite ptr equality check 1".to_string(),
                            pre_check.to_string(),
                        );

                        self.make_suggestion(
                            ctx,
                            op.span,
                            "rewrite ptr equality check 2".to_string(),
                            in_between.to_string(),
                        );

                        self.make_suggestion_after(
                            ctx,
                            rhs.span.shrink_to_hi(),
                            "rewrite ptr equality check 3".to_string(),
                            post_check.to_string(),
                        );
                    }
                } else if [
                    BinOpKind::Lt,
                    BinOpKind::Le,
                    BinOpKind::Gt,
                    BinOpKind::Ge,
                    BinOpKind::Eq,
                    BinOpKind::Ne,
                ]
                .iter()
                .any(|n| n == &op.node)
                {
                    let typeck = ctx.typeck_results();

                    if self.is_ptr_arith(lhs.hir_id)
                        && self.is_ptr_arith(rhs.hir_id)
                        && typeck.expr_ty_adjusted(lhs).is_unsafe_ptr()
                        && typeck.expr_ty_adjusted(rhs).is_unsafe_ptr()
                    {
                        let cmp_fn = match op.node {
                            BinOpKind::Lt => "lt",
                            BinOpKind::Le => "le",
                            BinOpKind::Gt => "gt",
                            BinOpKind::Ge => "ge",
                            BinOpKind::Eq => "eq",
                            BinOpKind::Ne => "ne",
                            _ => unreachable!(),
                        };

                        self.make_suggestion(
                            ctx,
                            expr.span.shrink_to_lo(),
                            "ptr_arith: rewrite ptr comparison (lo)".into(),
                            format!("crate::__laertes_array::compare_{}(&", cmp_fn),
                        );
                        self.make_suggestion(
                            ctx,
                            op.span,
                            "ptr_arith: rewrite ptr comparison (mid)".into(),
                            ", &".into(),
                        );
                        self.make_suggestion_after(
                            ctx,
                            expr.span.shrink_to_hi(),
                            "ptr_arith: rewrite ptr comparison (hi)".into(),
                            ")".into(),
                        );
                    }
                }
                self.rewrite_expr(ctx, lhs, RewriteCtx::not());
                self.rewrite_expr(ctx, rhs, RewriteCtx::not());
            },
            ExprKind::Unary(UnOp::Deref, inner) => {
                // need to rewrite the inner expression first because the edits clash
                let inner_ctx = RewriteCtx::from_mc(if rewrite_ctx.m == MutCtx::Assignee {
                    MutCtx::Mut
                } else {
                    rewrite_ctx.m
                });

                // check if the inner expression can be made a
                // reference, and make sure that it is originally a
                // pointer (check original type)
                let adjusted_ty = ctx.typeck_results().expr_ty_adjusted(inner);
                if !self.is_poisoned(inner.hir_id) && adjusted_ty.is_unsafe_ptr() {
                    self.rewrite_expr(ctx, inner, inner_ctx);
                    // immutable references are copyable so we don't insert
                    // borrow around them, put parentheses in this case.
                    let unwrap_snippet = ").unwrap()".to_string();

                    // add `(..).unwrap()` to extract the reference out of the pointer
                    self.make_suggestion(
                        ctx,
                        inner.span.shrink_to_lo(),
                        "unwrap Option<&T> before dereference".to_owned(),
                        "(".to_string(),
                    );
                    self.make_suggestion_after(
                        ctx,
                        inner.span.shrink_to_hi(),
                        "unwrap Option<&T> before dereference".to_owned(),
                        unwrap_snippet,
                    );
                } else if let Some((args, is_tmp_ref)) = self.rewrite_ptr_arith(
                    ctx,
                    inner.hir_id,
                    inner,
                    inner_ctx,
                    Some(expr),
                    &mut ptr_arith_handled,
                ) {
                    args.into_iter()
                        .for_each(|a| self.rewrite_expr(ctx, a, inner_ctx));
                    already_borrowed_in_temp = is_tmp_ref;
                } else if self.is_poisoned(inner.hir_id) {
                    self.rewrite_expr(ctx, inner, inner_ctx);
                    // We are dereferencing a raw pointer, if the
                    // result is borrowed then we need to re-borrow
                    // even when the mutability context is
                    // MutCtx::Assignee
                    raw_pointer_deref = true;
                } else {
                    self.rewrite_expr(ctx, inner, inner_ctx);
                }
            },
            ExprKind::Unary(_, inner) => {
                // assert!(rewrite_ctx.m != MutCtx::Mut);
                self.rewrite_expr(ctx, inner, RewriteCtx::not())
            },
            ExprKind::Lit(_) => {},
            ExprKind::Cast(inner, _ty)
                if matches!(get_constant_value(inner), Some(LitKind::Int(0, _))) =>
            {
                // rewrite `0 as * T` as null pointers
                // (`null_mut`/`null`) if the pointer is poisoned, and
                // rewrite it as `None` if it is not
                let cast_ty = ctx.typeck_results().expr_ty(expr);
                if matches!(cast_ty.kind(), rustc_middle::ty::TyKind::RawPtr(_)) {
                    // rewrite only if the relevant type has a known size
                    // (is not an external type), and is not an argument
                    // to an extern function (this is an issue with vararg
                    // functions where type inference is impossible).
                    let loc = self.ptr_provenance.expr_to_term[&expr.hir_id]
                        .get_lv()
                        .into_iter()
                        .collect::<HashSet<&Loc<Name>>>();
                    if !self
                        .ptr_provenance
                        .expr_has_poison(expr.hir_id, PoisonKind::ExternCallParam)
                        && !flows_into_raw
                    {
                        if self.is_poisoned(expr.hir_id) && !self.is_ptr_arith(expr.hir_id) {
                            // get the pointee type
                            let rewritten_type = self.rewrite_type(
                                &Type::from_ty(ctx, cast_ty),
                                loc.clone(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            );
                            let (mutbl, pointee_ty) = if let Type::Ptr(mutbl, new_ty) =
                                rewritten_type
                            {
                                (mutbl, new_ty)
                            } else {
                                unreachable!(
                                    "the new type should be poisoned so it should be a raw pointer: {:?}",
                                    rewritten_type,
                                )
                            };
                            // standard library call to make this non-mut
                            let null_call = format!(
                                "(0 as * {} {})",
                                match mutbl {
                                    Mutability::Mut => "mut",
                                    Mutability::Not => "const",
                                },
                                pointee_ty
                            );
                            self.make_suggestion(
                                ctx,
                                expr.span,
                                "rewrite 0 cast to pointer type as a null ptr call".to_string(),
                                null_call.to_string(),
                            );
                        } else {
                            // the pointer is not poisoned, rewrite it as None
                            let none_builder = if let Type::OptionT(new_ty) = self.rewrite_type(
                                &Type::from_ty(ctx, cast_ty),
                                loc.clone(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            ) {
                                format!("Option::<{}>::None", new_ty)
                            } else {
                                unreachable!("the new type should be surrounded with an Option")
                            };
                            self.make_suggestion(
                                ctx,
                                expr.span,
                                "rewrite null ptr as `None`".to_string(),
                                none_builder,
                            );
                            rewrote_null_ptr = true;
                        }
                    } else if !self
                        .ptr_provenance
                        .expr_has_poison(expr.hir_id, PoisonKind::ExternCallParam)
                        && flows_into_raw
                    {
                        // get the pointee type
                        let orig_type = Type::from_ty(ctx, cast_ty);
                        let rewritten_type = self.rewrite_type(
                            &orig_type,
                            loc.clone(),
                            &mut vec![],
                            &mut LifetimeGen::implicit_only(),
                        );
                        log::warn!("————expr————{:?}", expr);
                        let (mutbl, pointee_ty) = match rewritten_type.peel_option() {
                            Type::Boxed(box inner) => {
                                let mutbl = if let Type::Ptr(mutbl, _) = &orig_type {
                                    mutbl
                                } else {
                                    unreachable!(
                                        "the original type should be a pointer: {}",
                                        orig_type
                                    );
                                };
                                (mutbl, inner)
                            },
                            Type::Ptr(mutbl, box inner) | Type::Ref(mutbl, _, box inner) => {
                                (mutbl, inner)
                            },
                            _ => unreachable!(
                                "the new type should be a reference or a pointer: {}",
                                rewritten_type,
                            ),
                        };
                        let null_call = format!(
                            "(0 as * {} {})",
                            match mutbl {
                                Mutability::Mut => "mut",
                                Mutability::Not => "const",
                            },
                            pointee_ty
                        );
                        self.make_suggestion(
                            ctx,
                            expr.span,
                            "rewrite 0 cast to pointer type as a null ptr call".to_string(),
                            null_call.to_string(),
                        );
                    };
                }
            },
            ExprKind::Cast(inner, ty) => {
                // TODO-MC: reason about mutable context for both cast cases
                let _ptr_kind = self
                    .config
                    .ptr_kind
                    .get(
                        self.ptr_provenance.expr_to_term[&expr.hir_id]
                            .get_lv()
                            .unwrap(),
                    )
                    .cloned()
                    .unwrap_or(PtrKind::Borrowing);

                is_move = is_move
                    || self
                        .config
                        .move_flows
                        .contains(&SerializableHirId(inner.hir_id));

                // check if the inner expression is a malloc/calloc we can rewrite
                let expr_ty = ctx.typeck_results().expr_ty_adjusted(expr);
                let rewrote_whole_call = self.rewrite_malloc(
                    ctx,
                    inner,
                    Type::from_ty(ctx, expr_ty),
                    self.ptr_provenance.expr_to_term[&expr.hir_id]
                        .get_lv()
                        .unwrap(),
                    expr.span,
                );
                box_from_malloc = rewrote_whole_call == Ok(true);
                if !box_from_malloc {
                    // compute mutability from the type
                    let typ = Type::from_ty(ctx, expr_ty);
                    let mut_ctx = if typ.is_mut_ptr()
                        && matches!(rewrite_ctx.m, MutCtx::Not | MutCtx::Unknown)
                    {
                        MutCtx::Mut
                    } else {
                        rewrite_ctx.m
                    };
                    self.rewrite_expr(ctx, inner, rewrite_ctx.with_mc(mut_ctx));

                    // span for the ` as <ty>` part of the cast. It
                    // starts from the end of inner to the end of the
                    // whole expression:
                    //
                    // <inner> as <ty>
                    //        ^^^^^^^^
                    let cast_span = inner.span.shrink_to_hi().to(ty.span.shrink_to_hi());

                    // ref->ptr cast is inserted inside the trans call. So, we
                    // need to infer the locations current location flows to.
                    let loc = self
                        .ptr_provenance
                        .arg_or_init
                        .get(&rewrite_ctx.match_parent.unwrap_or(expr.hir_id))
                        .map_or_else(
                            // use the current location by default
                            || {
                                self.ptr_provenance.expr_to_term[&expr.hir_id]
                                    .clone()
                                    .into_lv()
                                    .into_iter()
                                    .collect::<HashSet<Loc<Name>>>()
                            },
                            |f| f.reify(&self.ptr_provenance),
                        );
                    let rewritten_type = self.rewrite_type(
                        &typ,
                        loc.iter().collect(),
                        &mut vec![],
                        &mut LifetimeGen::implicit_only(),
                    );

                    let inner_typ =
                        Type::from_ty(ctx, ctx.typeck_results().expr_ty_adjusted(inner));
                    match &typ {
                        Type::Ptr(..) => {
                            // rewrite the pointer ty to a reference if not
                            // poisoned and the expression was not a malloc/calloc
                            if (rewrote_whole_call != Err(())
                                || LIMIT_STUDY.load(Ordering::Relaxed))
                                && (!self.is_poisoned(inner.hir_id)
                                    || self.is_ptr_arith(inner.hir_id))
                            {
                                // remove the cast only if the types don't
                                // differ, rewrite to translate otherwise
                                let mut p_typ = &typ;
                                let mut inner_p_typ = &inner_typ;
                                // Peel nested pointers only at one level because Rust
                                // doesn't have automatic degradation from * mut * mut T
                                // to * const * const T etc. (We do it at the top level
                                // by inserting `borrow` calls, but we cannot do this
                                // for nested pointers especially if they correspond to
                                // arrays).
                                if let (Some(t), Some(u)) =
                                    (p_typ.get_pointee(), inner_p_typ.get_pointee())
                                {
                                    p_typ = t;
                                    inner_p_typ = u;
                                }
                                if p_typ == inner_p_typ || rewrite_ctx.in_free {
                                    self.make_suggestion_after(
                                        ctx,
                                        cast_span,
                                        "remove raw pointer casting".to_owned(),
                                        "".to_owned(),
                                    );
                                } else if LIMIT_STUDY.load(Ordering::Relaxed) {
                                    // The types don't match, rewrite to use
                                    // `trans`

                                    // If the inner expression is borrowed, then
                                    // we need to cast from/to borrowing
                                    // expressions, i.e. replace boxes.

                                    let mutbl = match rewrite_ctx.m {
                                        MutCtx::Mut | MutCtx::Unknown => Some(Mutability::Mut),
                                        MutCtx::Not => Some(Mutability::Not),
                                        _ => None,
                                    };
                                    let rewrite_ty_around_borrow = |t: Type| {
                                        if mutbl.is_some() {
                                            match t {
                                                Type::OptionT(box Type::Boxed(pointee)) => {
                                                    Type::OptionT(Box::new(Type::Ref(
                                                        mutbl.unwrap(),
                                                        Lifetime::from(""),
                                                        pointee,
                                                    )))
                                                },
                                                _ => t,
                                            }
                                        } else {
                                            t
                                        }
                                    };
                                    let new_ty = rewrite_ty_around_borrow(rewritten_type);
                                    let new_inner_ty = {
                                        let t = rewrite_ty_around_borrow(self.rewrite_type(
                                            &inner_typ,
                                            loc.iter().collect(),
                                            &mut vec![],
                                            &mut LifetimeGen::implicit_only(),
                                        ));
                                        if rewrite_ctx.m == MutCtx::Not && t.is_mut_ref() {
                                            t.as_const_ref()
                                        } else {
                                            t
                                        }
                                    };
                                    let trans_call = format!(
                                        "crate::laertes_rt::trans::<{}, {}>(",
                                        new_inner_ty, new_ty
                                    );
                                    log::trace!(
                                        "rewrite cast: {} as {} -> {}",
                                        typ,
                                        inner_typ,
                                        trans_call
                                    );
                                    self.make_suggestion(
                                        ctx,
                                        expr.span.shrink_to_lo(),
                                        "cast -> trans".to_owned(),
                                        trans_call,
                                    );
                                    self.make_suggestion_after(
                                        ctx,
                                        cast_span,
                                        "cast -> trans".to_owned(),
                                        ")".to_owned(),
                                    );
                                }
                            } else if self.is_poisoned(inner.hir_id) {
                                let ty_span = ty.span;
                                if let Type::Ptr(
                                    outer_mutbl,
                                    box Type::Ptr(inner_mutbl, pointee_ty),
                                ) = typ.clone()
                                {
                                    // this is a nested pointer, check if
                                    // the inner pointer is poisoned to
                                    // figure out whether we should
                                    // rewrite the cast `_ as ** T` to `_
                                    // *Option<& T>`
                                    let loc = self.ptr_provenance.expr_to_term[&expr.hir_id]
                                        .get_lv()
                                        .unwrap();
                                    if self
                                        .ptr_provenance
                                        .points_to(loc)
                                        .iter()
                                        .all(|l| !self.ptr_provenance.is_poisoned(l))
                                    {
                                        let new_ty = Type::Ptr(
                                            outer_mutbl,
                                            Box::new(Type::OptionT(Box::new(Type::Ref(
                                                inner_mutbl,
                                                UNDERSCORE.clone(),
                                                pointee_ty,
                                            )))),
                                        );
                                        self.make_suggestion_after(
                                            ctx,
                                            ty_span,
                                            "rewrite nested pointer".to_owned(),
                                            format!("{}", new_ty),
                                        );
                                    }
                                }
                            }
                        },
                        Type::Fn(_) => {
                            // Elide function pointer signatures
                            //
                            // TODO(maemre): Check that the inner and
                            // the outer type are structurally
                            // equivalent before making them safe, and
                            // insert `trans` otherwise.
                            self.make_suggestion_after(
                                ctx,
                                cast_span,
                                "remove fn pointer casting".to_owned(),
                                "".to_owned(),
                            );
                        },
                        _ if matches!(inner_typ, Type::Ptr(..) | Type::Fn(..))
                            && LIMIT_STUDY.load(Ordering::Relaxed)
                            && !self.is_poisoned(inner.hir_id) =>
                        {
                            let new_ty = self.rewrite_type(
                                &typ,
                                loc.iter().collect(),
                                &mut vec![],
                                &mut LifetimeGen::implicit_only(),
                            );
                            let new_inner_ty = {
                                let t = self.rewrite_type(
                                    &inner_typ,
                                    loc.iter().collect(),
                                    &mut vec![],
                                    &mut LifetimeGen::implicit_only(),
                                );
                                if rewrite_ctx.m == MutCtx::Not && t.is_mut_ref() {
                                    t.as_const_ref()
                                } else {
                                    t
                                }
                            };
                            let trans_call = format!(
                                "crate::laertes_rt::trans::<{}, {}>(",
                                new_inner_ty, new_ty
                            );
                            log::trace!("rewrite cast: {} as {} -> {}", typ, inner_typ, trans_call);
                            self.make_suggestion(
                                ctx,
                                expr.span.shrink_to_lo(),
                                "cast -> trans".to_owned(),
                                trans_call,
                            );
                            self.make_suggestion_after(
                                ctx,
                                cast_span,
                                "cast -> trans".to_owned(),
                                ")".to_owned(),
                            );
                        },
                        _ => {},
                    }
                }
            },
            ExprKind::DropTemps(inner) => self.rewrite_expr(ctx, inner, rewrite_ctx),
            ExprKind::Loop(body, _label, _source, _) => self.rewrite_block(ctx, body, rewrite_ctx),
            ExprKind::Match(scrutinee, arms, _source) => {
                block_expr = true;
                // this is hard to decide for Rust in general, all of
                // our pattern matches come from conditionals, so this
                // becomes immutable for us
                self.rewrite_expr(ctx, scrutinee, RewriteCtx::not());
                for arm in *arms {
                    // TODO: rewrite the patterns in match arms
                    if let Some(Guard::If(guard)) = arm.guard {
                        self.rewrite_expr(ctx, guard, RewriteCtx::not());
                    }
                    self.rewrite_expr(ctx, arm.body, rewrite_ctx.with_match_parent(expr.hir_id));
                }
            },
            ExprKind::Block(body, _label) => {
                block_expr = true;
                let sub_ctx =
                    rewrite_ctx.with_match_parent(rewrite_ctx.match_parent.unwrap_or(expr.hir_id));
                // log::warn!("++++++rewrite_expr - ExprKind::Block - body: {:?}", body);
                self.rewrite_block(ctx, body, sub_ctx)
            },
            ExprKind::Assign(lhs, rhs, _span) => {
                self.rewrite_expr(ctx, lhs, RewriteCtx::assignee());
                let rhs_ctx = if self.ptr_provenance.is_owned(lhs.hir_id) {
                    MutCtx::Move
                } else if Type::from_ty(ctx, ctx.typeck_results().expr_ty_adjusted(lhs))
                    .is_const_ptr()
                {
                    MutCtx::Not
                } else {
                    MutCtx::Unknown
                };
                self.rewrite_expr(ctx, rhs, RewriteCtx::from_mc(rhs_ctx));
            },
            ExprKind::AssignOp(_op, lhs, rhs) => {
                self.rewrite_expr(ctx, lhs, RewriteCtx::assignee());
                self.rewrite_expr(ctx, rhs, RewriteCtx::unknown());
            },
            ExprKind::Field(inner, _field) => {
                let ty = ctx.typeck_results().expr_ty_adjusted(expr);
                let inner_ctx = if rewrite_ctx.m == MutCtx::Assignee {
                    MutCtx::Assignee
                } else if ty.is_ref()
                    || (ty.is_unsafe_ptr() && !self.ptr_provenance.is_expr_poisoned(expr.hir_id))
                {
                    // this is a reference, we want a mutable
                    // borrow if the context is not Mut::Not
                    if rewrite_ctx.m == MutCtx::Unknown {
                        if ty.is_mutable_ptr() {
                            MutCtx::Mut
                        } else {
                            MutCtx::Not
                        }
                    } else {
                        rewrite_ctx.m
                    }
                } else {
                    // this is not a reference or a pointer
                    rewrite_ctx.m
                };
                // Some generated C code uses null pointers to
                // calculate field offsets, in that case we should not
                // rewrite the inner null pointer. A more Rust-y way
                // would be to rewrite it into use of pins like the
                // `field_offset` crate.
                let is_null_ptr_deref = if let ExprKind::Unary(UnOp::Deref, pointer) = &inner.kind {
                    matches!(get_constant_value(pointer), Some(LitKind::Int(0, _)))
                } else {
                    false
                };
                if !is_null_ptr_deref {
                    self.rewrite_expr(ctx, inner, RewriteCtx::from_mc(inner_ctx));
                }
            },
            ExprKind::Index(array_expr, index_expr) => {
                match self.rewrite_ptr_arith(
                    ctx,
                    array_expr.hir_id,
                    expr,
                    rewrite_ctx.reset_parent(),
                    None,
                    &mut ptr_arith_handled,
                ) {
                    None => {
                        self.rewrite_expr(ctx, array_expr, rewrite_ctx.reset_parent());
                        self.rewrite_expr(ctx, index_expr, RewriteCtx::not());
                    },
                    Some((args, t)) => {
                        args.into_iter()
                            .for_each(|a| self.rewrite_expr(ctx, a, rewrite_ctx.reset_parent()));
                        already_borrowed_in_temp = t;
                    },
                }
            },
            ExprKind::Path(_path) => {},
            ExprKind::AddrOf(_borrow_kind, mutbl, inner) => {
                // determine context based on mutability
                self.rewrite_expr(
                    ctx,
                    inner,
                    if *mutbl == Mutability::Mut {
                        RewriteCtx::assignee()
                    } else {
                        RewriteCtx::not()
                    },
                );

                // N.B. this cannot be owning
                if ctx.typeck_results().expr_ty_adjusted(expr).is_unsafe_ptr()
                    && !self.ptr_provenance.is_expr_poisoned(expr.hir_id)
                {
                    // this location is not poisoned, so we are borrowing the value inside, wrap it in Some(..)

                    self.make_suggestion(
                        ctx,
                        expr.span.shrink_to_lo(),
                        "raw->safe borrow, lhs".to_string(),
                        "Some(".to_string(),
                    );
                    self.make_suggestion_after(
                        ctx,
                        expr.span.shrink_to_hi(),
                        "raw->safe borrow, rhs".to_string(),
                        ")".to_string(),
                    );
                    // We already borrowed the value here in a
                    // temporary, so there is no need to wrap this in
                    // borrow/borrow_mut later
                    already_borrowed_in_temp = true;
                }
            },
            ExprKind::Break(_dest, value) => {
                // Assuming that the values yielded by break are never in a mutable context
                value.map(|e| self.rewrite_expr(ctx, e, RewriteCtx::not()));
            },
            ExprKind::Continue(_) => {},
            ExprKind::Ret(value) => {
                // assert!(rewrite_ctx.m != MutCtx::Mut);
                // TODO: determine the mutable context based on the
                // return value mutability, we may need to move values
                // here

                // Check if the return type is supposed to be owned
                let fn_name = Name::from(get_def_qname(
                    ctx,
                    ctx.typeck_results().hir_owner.to_def_id(),
                ));
                let mut_ctx = if self.ptr_provenance.is_loc_owned(&Loc::RetVal(fn_name)) {
                    MutCtx::Move
                } else if value.as_ref().map_or(false, |e| {
                    ctx.typeck_results().expr_ty_adjusted(e).is_mutable_ptr()
                }) {
                    MutCtx::Assignee
                } else {
                    MutCtx::Not
                };
                value.map(|e| self.rewrite_expr(ctx, e, RewriteCtx::from_mc(mut_ctx)));
            },
            ExprKind::InlineAsm(_) => {},     // mark as poison?
            ExprKind::LlvmInlineAsm(_) => {}, // mark as poison?
            ExprKind::Struct(_name, fields, rest) => {
                fields
                    .iter()
                    .for_each(|f| self.rewrite_expr(ctx, f.expr, rewrite_ctx.reset_parent()));
                rest.map(|e| self.rewrite_expr(ctx, e, rewrite_ctx.reset_parent()));
            },
            ExprKind::Err => panic!("the input program is not well-formed, at {:?}", expr.span),
            ExprKind::Yield(..) | ExprKind::Type(..) | ExprKind::Closure(..) | ExprKind::Box(_) => {
                panic!("expression kind not supported: {:?}", expr.kind)
            },
            ExprKind::If(cond, then_expr, Some(else_expr)) => {
                self.rewrite_expr(ctx, cond, RewriteCtx::not());
                self.rewrite_expr(ctx, then_expr, rewrite_ctx);
                self.rewrite_expr(ctx, else_expr, rewrite_ctx);
            },
            ExprKind::If(cond, then_expr, None) => {
                self.rewrite_expr(ctx, cond, RewriteCtx::not());
                self.rewrite_expr(ctx, then_expr, rewrite_ctx);
            },
            ExprKind::ConstBlock(_) => panic!("ConstBlock is not supported"),
            ExprKind::Let(_, _, _) => panic!("let is not supported"),
        }
        self.depth -= 1;

        let ty = ctx.typeck_results().expr_ty_adjusted(expr);

        // check for mutability adjustments because there may be
        // automated adjustments inserted to coerce a `* mut T` to
        // a `* const T`
        let is_mutable_ptr = ty.is_mutable_ptr() || {
            // here, we are checking the adjustments directly, another
            // alternative is to check the type before adjustment. we
            // should investigate if doing that is always safe for
            // future-proofing.
            let adjustments = ctx.typeck_results().expr_adjustments(expr);
            (
                // The most general coercion the compiler applies is `*mut T` -> `*const T`
                adjustments.len() == 1
                    && matches!(
                        adjustments[0].kind,
                        Adjust::Pointer(PointerCast::MutToConstPointer)
                    )
            ) || (
                // If the expression is an address-of expression like
                // `&mut e`, then the compiler may apply a sequence of
                // coercions to get a value of type `*const T`, as follows:
                //
                // 1. dereference the addr-of
                // 2. take the address again as *const T
                ctx.typeck_results().expr_ty(expr).is_mutable_ptr()
                    && adjustments.len() == 2
                    && matches!(adjustments[0].kind, Adjust::Deref(None))
                    && matches!(
                        adjustments[1].kind,
                        Adjust::Borrow(AutoBorrow::RawPtr(Mutability::Not))
                    )
            )
        };

        // inject borrows anywhere that they are needed
        if !block_expr {
            if ty.is_unsafe_ptr()
                && !self.is_poisoned(expr.hir_id)
                && flows_into_raw
                && (box_from_malloc || !matches!(expr.kind, ExprKind::Cast(..)))
            {
                assert!(
                    !self.is_ptr_arith(expr.hir_id),
                    "pointer arithmetic->raw pointer decay is not implemented yet!"
                );
                let cast_fn = match rewrite_ctx.m {
                    MutCtx::Move => Some("_move_to_ptr("), // Transfer ownership
                    MutCtx::Not => Some("_as_ptr(& "),
                    _ => {
                        if is_mutable_ptr {
                            Some("_as_mut_ptr(&mut ")
                        } else {
                            Some("_as_ptr(& ")
                        }
                    },
                };
                if let Some(cast_fn) = cast_fn {
                    self.make_suggestion(
                        ctx,
                        expr.span.shrink_to_lo(),
                        "cast to pointer".to_string(),
                        cast_fn.to_string(),
                    );
                    self.make_suggestion_after(
                        ctx,
                        expr.span.shrink_to_hi(),
                        "cast_to_pointer".to_string(),
                        ")".to_string(),
                    );
                }
            } else if ty.is_unsafe_ptr()
                && !self.is_poisoned(expr.hir_id)
                && !self.is_ptr_arith(expr.hir_id)
                && (box_from_malloc || !matches!(expr.kind, ExprKind::Cast(..)))
                && !is_move
            {
                // this is a raw ptr that is going to be rewritten
                // as a reference. rewrite it according to the
                // context
                if self.ptr_provenance.is_owned(expr.hir_id) || box_from_malloc {
                    // This is an owned pointer
                    match rewrite_ctx.m {
                        MutCtx::Assignee => {}, // Don't borrow the lhs of an assignment
                        MutCtx::Move => {},     // We are transferring ownership, don't do anything
                        MutCtx::Not => {
                            self.make_suggestion(
                                ctx,
                                expr.span.shrink_to_lo(),
                                "borrow box".to_string(),
                                "owned_as_ref(& ".to_string(),
                            );
                            self.make_suggestion_after(
                                ctx,
                                expr.span.shrink_to_hi(),
                                "borrow box".to_string(),
                                ")".to_string(),
                            );
                        },
                        _ => {
                            self.make_suggestion(
                                ctx,
                                expr.span.shrink_to_lo(),
                                "borrow box".to_string(),
                                "owned_as_mut(&mut ".to_string(),
                            );
                            self.make_suggestion_after(
                                ctx,
                                expr.span.shrink_to_hi(),
                                "borrow box".to_string(),
                                ")".to_string(),
                            );
                        },
                    }
                } else if rewrite_ctx.m == MutCtx::Not
                    || !matches!(expr.kind, ExprKind::Call(..) | ExprKind::MethodCall(..))
                {
                    // do not re-borrow on casts or temporaries
                    if is_mutable_ptr && rewrite_ctx.m == MutCtx::Not && !already_borrowed_in_temp {
                        // reborrow Option<&mut T> -> Option<&T>
                        self.make_suggestion(
                            ctx,
                            expr.span.shrink_to_lo(),
                            "reborrow".to_string(),
                            "borrow(& ".to_string(),
                        );
                        self.make_suggestion_after(
                            ctx,
                            expr.span.shrink_to_hi(),
                            "reborrow".to_string(),
                            ")".to_string(),
                        );
                    } else if is_mutable_ptr
                        && (rewrite_ctx.m != MutCtx::Assignee ) // TODO: reason about inserting raw_pointer_deref here.
                        && !already_borrowed_in_temp
                    {
                        self.make_suggestion(
                            ctx,
                            expr.span.shrink_to_lo(),
                            "reborrow".to_string(),
                            "borrow_mut(&mut ".to_string(),
                        );
                        self.make_suggestion_after(
                            ctx,
                            expr.span.shrink_to_hi(),
                            "reborrow".to_string(),
                            ")".to_string(),
                        );
                    } else if !is_mutable_ptr
                        && ((rewrite_ctx.m != MutCtx::Unknown && rewrite_ctx.m != MutCtx::Assignee)
                            || raw_pointer_deref)
                    {
                        // reborrow Option<&T>
                        self.make_suggestion(
                            ctx,
                            expr.span.shrink_to_lo(),
                            "reborrow".to_string(),
                            "(".to_string(),
                        );
                        self.make_suggestion_after(
                            ctx,
                            expr.span.shrink_to_hi(),
                            "reborrow".to_string(),
                            ").clone()".to_string(),
                        );
                    }
                }
            } else if ty.is_unsafe_ptr()
                && self.is_ptr_arith(expr.hir_id)
                && !already_borrowed_in_temp
                && !rewrote_null_ptr
                && !is_move
            {
                if rewrite_ctx.m == MutCtx::Not {
                    // TODO: this condition fires in too many places
                    self.make_suggestion(
                        ctx,
                        expr.span.shrink_to_lo(),
                        "reborrow".to_string(),
                        "crate::__laertes_array::borrow(& ".to_string(),
                    );
                    self.make_suggestion_after(
                        ctx,
                        expr.span.shrink_to_hi(),
                        "reborrow".to_string(),
                        ")/*borrow*/".to_string(),
                    );
                } else if is_mutable_ptr
                    && rewrite_ctx.m != MutCtx::Assignee
                    && rewrite_ctx.m != MutCtx::Move
                {
                    let borrow_fn = if self.ptr_provenance.is_refcell(expr.hir_id) {
                        // borrow refcells immutably, even in mutable contexts
                        "crate::__laertes_array::borrow(& "
                    } else {
                        "crate::__laertes_array::borrow_mut(&mut "
                    };
                    self.make_suggestion(
                        ctx,
                        expr.span.shrink_to_lo(),
                        "reborrow".to_string(),
                        borrow_fn.to_string(),
                    );
                    self.make_suggestion_after(
                        ctx,
                        expr.span.shrink_to_hi(),
                        "reborrow".to_string(),
                        ")/*borrow*/".to_string(),
                    );
                }
            }
        }
        self.depth -= 1;
    }

    // true: rewrote the call
    // false: not malloc
    // Err(()): did not rewrite the call or poisoned
    fn rewrite_malloc(
        &self,
        ctx: &LateContext,
        inner: &Expr,
        ty: Type,
        loc: &Loc<Name>,
        span_to_overwrite: Span,
    ) -> Result<bool, ()> {
        // checks the outer pointer type and rewrites the call with `Box::new`
        let rewrite_call = |message| {
            if let Type::Ptr(_, inner_ty) = &ty {
                // rewrite inner type to figure out the type to allocate
                let type_to_allocate = self.rewrite_type(
                    inner_ty,
                    self.ptr_provenance.points_to(loc),
                    &mut vec![],
                    &mut LifetimeGen::implicit_only(),
                );
                let default_snippet = self.default_value(&type_to_allocate);
                if self.struct_info.can_generate_default(&type_to_allocate) {
                    log::warn!("the type used for default check is {:?}", type_to_allocate);

                    // Choose between box and customslice based on whether the result is used in pointer arithmetic
                    let (call_open, call_close) = if self.is_ptr_arith(inner.hir_id) {
                        (
                            "crate::__laertes_array::CustomSlice::boxed_from_vec(vec![",
                            "])",
                        )
                    } else {
                        ("Box::new(", ")")
                    };

                    self.make_suggestion(
                        ctx,
                        span_to_overwrite,
                        message,
                        format!(
                            "Some({}{}{})",
                            call_open,
                            default_snippet.unwrap(),
                            call_close,
                        ),
                    );
                    true
                } else {
                    log::error!(
                        "could not rewrite malloc at {:?} because could not generate default value for the allocated type {}",
                        span_to_overwrite,
                        ty
                    );
                    false
                }
            } else {
                log::error!(
                    "call to malloc is cast to a non-pointer type {}, at {:?}",
                    ty,
                    span_to_overwrite
                );
                false
            }
        };

        if self.is_poisoned(inner.hir_id) && !self.is_ptr_arith(inner.hir_id) {
            return Err(());
        }

        if let ExprKind::Call(
            Expr {
                kind: ExprKind::Path(callee_path),
                hir_id,
                ..
            },
            args,
        ) = &inner.kind
        {
            let callee_segments = qpath_to_segments(ctx, callee_path, *hir_id)
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>();
            if true {
                // callee_segments.len() == 2 && callee_segments[0] == local_crate_name(ctx) {
                match callee_segments[callee_segments.len() - 1].as_str() {
                    "malloc" => {
                        // TODO: match the argument size_of type and rewrite
                        assert_eq!(args.len(), 1);
                        if !is_size_of(ctx, &args[0])
                            && !(LIMIT_STUDY.load(Ordering::Relaxed)
                                && NO_PTR_ARITH_REWRITE.load(Ordering::Relaxed))
                        {
                            log::error!("cannot rewrite malloc, inner expression: {:?}", args[0]);
                            return Err(());
                        }
                        if rewrite_call("rewrite malloc".to_owned()) {
                            Ok(true)
                        } else {
                            Err(())
                        }
                    },
                    "calloc" => {
                        // TODO: match the argument size_of type for double-checking
                        assert_eq!(args.len(), 2);
                        // some programs mix up the size and the count
                        // arguments of calloc, so we need to test for
                        // both permutations
                        if ((is_size_of(ctx, &args[0])
                            && matches!(get_constant_value(&args[1]), Some(LitKind::Int(1, _))))
                            || (is_size_of(ctx, &args[1])
                                && matches!(
                                    get_constant_value(&args[0]),
                                    Some(LitKind::Int(1, _))
                                )))
                            || (LIMIT_STUDY.load(Ordering::Relaxed)
                                && NO_PTR_ARITH_REWRITE.load(Ordering::Relaxed))
                        {
                            if rewrite_call("rewrite calloc".to_owned()) {
                                Ok(true)
                            } else {
                                log::error!(
                                    "cannot rewrite calloc, the inner rewrite failed, at {:?}",
                                    inner.span
                                );
                                Err(())
                            }
                        } else {
                            log::error!(
                                "cannot rewrite calloc, it is not called with arguments like (size_of<T>, 1) or (1, size_of<T>), at {:?}",
                                inner.span
                            );
                            Err(())
                        }
                    },
                    _ => Ok(false),
                }
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn rewrite_block(&mut self, ctx: &LateContext<'_>, block: &Block<'_>, rewrite_ctx: RewriteCtx) {
        let fn_name = get_def_qname(ctx, ctx.typeck_results().hir_owner.to_def_id());
        // log::warn!("++++++ rewrite_block : fn_name - {:?}", fn_name);
        block.stmts.iter().for_each(|s| {
            // log::warn!("++++++ block.stmts: {:?}", s);
            match &s.kind {
                StmtKind::Local(let_stmt) => {
                    let let_ty = Type::from_ty(ctx, ctx.typeck_results().pat_ty(let_stmt.pat));
                    if let PatKind::Binding(BindingAnnotation::Unannotated, _, name, _) =
                        &let_stmt.pat.kind
                    {
                        // log::warn!("+++---fn rewrite_block --- name: {:?}", name);
                        if name.as_str().starts_with("fresh") {
                            self.make_suggestion(
                                ctx,
                                let_stmt.pat.span.shrink_to_lo(),
                                "make fresh variable mutable".to_owned(),
                                "mut ".to_owned(),
                            );
                        }
                    }
                    if matches!(let_stmt.source, LocalSource::Normal) && let_stmt.ty.is_some() {
                        if true {
                            // rewrite the type (we support this only if the let
                            // binds a single variable without qualifiers like
                            // `ref` or has an initialization statement).  this
                            // is necessary if this value is never used (in the
                            // sense that the variable is overriden before its
                            // first use, so there is a def-def anomaly and the
                            // compiler wouldn't have enough information to
                            // derive the pointee type). in the future, we can
                            // focus this using a liveness analysis to see if
                            // this definition appears in any def-use chain.
                            let loc = match &let_stmt.pat.kind {
                                PatKind::Binding(_, _, name, _) => {
                                    Some(Loc::Var(Name::from(format!("{}::{}", fn_name, name))))
                                },
                                _ => let_stmt
                                    .init
                                    .as_ref()
                                    .and_then(|e| {
                                        self.ptr_provenance.expr_to_term[&e.hir_id].get_lv()
                                    })
                                    .cloned(),
                            };

                            if loc.is_some() {
                                let new_ty = self.rewrite_type(
                                    &let_ty,
                                    loc.iter().collect(),
                                    &mut vec![],
                                    &mut LifetimeGen::implicit_only(),
                                );
                                self.make_suggestion(
                                    ctx,
                                    let_stmt.ty.unwrap().span,
                                    "rewrite the type of the let statement".to_owned(),
                                    format!("{}", new_ty),
                                );
                            } else {
                                // we don't have a location for the let statement
                                // (no initialization expression, and complex
                                // binding). remove the old type and trust the
                                // compiler to infer the correct type.
                                self.make_suggestion(
                                    ctx,
                                    let_stmt.ty.unwrap().span,
                                    "remove the type of the let statement".to_owned(),
                                    "_".to_owned(),
                                );
                            }
                            // record this type rewrite
                            self.span_info.insert_rewritten_type(
                                FatSpan::from_span(
                                    let_stmt.ty.unwrap().span,
                                    ctx.sess().source_map(),
                                ),
                                let_ty.clone(),
                                loc,
                            );
                        }
                    }
                    let loc = if let PatKind::Binding(_, _, name, _) = &let_stmt.pat.kind {
                        Some(Loc::Var(Name::from(format!("{}::{}", fn_name, name))))
                    } else {
                        None
                    };
                    let rhs_ctx = if loc.map_or(false, |l| self.ptr_provenance.is_loc_owned(&l)) {
                        MutCtx::Move
                    } else if let_ty.is_const_ptr() {
                        MutCtx::Not
                    } else {
                        MutCtx::Unknown
                    };
                    let_stmt
                        .init
                        .iter()
                        .for_each(|e| self.rewrite_expr(ctx, e, RewriteCtx::from_mc(rhs_ctx)));
                },
                StmtKind::Item(..) => {},
                StmtKind::Expr(e) => self.rewrite_expr(ctx, e, RewriteCtx::unknown()),
                StmtKind::Semi(e) => self.rewrite_expr(ctx, e, RewriteCtx::not()),
            }
        });
        block
            .expr
            .iter()
            .for_each(|e| self.rewrite_expr(ctx, e, rewrite_ctx));
    }

    fn process_fn(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        fn_decl: &FnDecl<'_>,
        body: &Body<'_>,
        generics: &Generics<'_>,
        fn_header: FnHeader,
        header_span: Span,
    ) {
        if let Some(new_sig) = self.new_signatures.get(&name) {
            // make sure that we are not overwriting any generics
            assert!(
                generics
                    .params
                    .iter()
                    .all(|p| { matches!(p.kind, GenericParamKind::Lifetime { .. }) }),
                "function {} has non-lifetime parameters, at {:?}",
                name,
                generics.span
            );

            // add lifetime params
            if !new_sig.lifetime_quals.is_empty() {
                let generics_str =
                    String::from("<") + &new_sig.lifetime_quals.iter().join(", ") + ">";
                self.make_suggestion(
                    ctx,
                    generics.span,
                    "add lifetime parameters to fn".to_owned(),
                    generics_str,
                );
            }

            // add lifetime bounds
            if !new_sig.lifetime_bounds.is_empty() {
                let lifetime_bounds_str = String::from(" where ")
                    + &new_sig
                        .lifetime_bounds
                        .iter()
                        .map(|(longer, shorter)| format!("{}: {}", longer, shorter))
                        .join(", ");
                self.make_suggestion(
                    ctx,
                    generics.where_clause.span,
                    "add lifetime bounds to fn".to_owned(),
                    lifetime_bounds_str,
                );
            }

            // annotate types (ptrs & structs) in parameters
            for (i, param) in body.params.iter().enumerate() {
                // rewrite each type, irregardless of the pattern,
                // unless the parameter is a function pointer
                if i >= new_sig.param_types.len() {
                    break;
                }
                if matches!(new_sig.param_types[i], Type::OptionT(box Type::Fn(..))) {
                    // continue;
                }
                self.make_suggestion(
                    ctx,
                    param.ty_span,
                    "rewrite parameter type".to_owned(),
                    format!("{}", new_sig.param_types[i]),
                );
            }

            // rewrite the return type only if it is explicit (i.e.,
            // it is not `()`).
            if let FnRetTy::Return(ret_ty) = fn_decl.output {
                self.make_suggestion_after(
                    ctx,
                    ret_ty.span,
                    "rewrite return type".to_owned(),
                    format!("{}", *new_sig.ret_type),
                );
            }
        }
        // Do not rewrite extern stub bodies
        if name.contains("laertes_rt")
            || name.contains("xmlNanoFTPCheckResponse")
            || name.contains("xmlNanoFTPCloseConnection")
            || name.contains("xmlNanoFTPList")
            || name.contains("xmlNanoFTPGet")
        //    || name.contains("xmlNewRMutex")
        //    || name.contains("xmlNewMutex")
        {
            return;
        }

        // recursively process the body (maybe in the lint?) to
        // rewrite types, remove casts, rewrite nulls to none, and
        // rewrite derefs
        //
        // also adapt arguments in calls inside (only ptr->ref direction)
        let mut_ctx = if self.ptr_provenance.is_loc_owned(&Loc::RetVal(name.clone())) {
            MutCtx::Move
        } else if ctx
            .typeck_results()
            .expr_ty_adjusted(&body.value)
            .is_mutable_ptr()
        {
            MutCtx::Assignee
        } else {
            MutCtx::Not
        };
        // log::warn!("+++---EXPR: {:?}", &body.value);
        self.rewrite_expr(ctx, &body.value, RewriteCtx::from_mc(mut_ctx));

        let can_remove_unsafe = !self.fn_has_unsafety_we_cannot_handle(ctx, &name, fn_decl);

        // check if we can remove `unsafe`
        if REMOVE_UNSAFE.load(Ordering::Relaxed)
            && fn_header.unsafety == Unsafety::Unsafe
            && can_remove_unsafe
        {
            self.make_suggestion(
                ctx,
                header_span,
                "remove `unsafe` from fn header".to_owned(),
                Self::safe_header_snippet(fn_header),
            );
        }
    }
}

impl LintPass for RewritePass {
    fn name(&self) -> &'static str {
        "RewritePass"
    }
}

impl<'tcx> LateLintPass<'tcx> for RewritePass {
    fn check_mod(
        &mut self,
        ctx: &LateContext<'tcx>,
        m: &'tcx Mod<'tcx>,
        span: Span,
        hir_id: HirId,
    ) {
        // Here, we skip annotating modules that are defined in the
        // same file as the crate. A better approach would find if the
        // module spans the whole file and insert the helper
        // functions/imports in the correct place right before the
        // `}` that closes the module.

        let mod_name = get_hir_qname(ctx, hir_id);
        let helper_span = if mod_name.as_str() == (*CRATE_NAME.lock().unwrap()).as_ref() {
            span.shrink_to_hi()
        } else {
            let hi_span = m.inner.shrink_to_hi();
            let beginning_of_source_file = ctx
                .sess()
                .source_map()
                .lookup_source_file(m.inner.lo())
                .start_pos;
            if Some(beginning_of_source_file) == *CRATE_FILE_POS.lock().unwrap() {
                // skip annotating a module if it is not on its own separate file
                println!(
                    "{} {} with helpers. the source file pos: {:?} -- crate pos: {:?}",
                    "skipping annotating".green().bold(),
                    mod_name,
                    beginning_of_source_file,
                    *CRATE_FILE_POS.lock().unwrap()
                );
                return;
            }
            hi_span
        };
        self.make_suggestion(
            ctx,
            helper_span,
            format!(
                "add helpers to the beginning of the module `{}`",
                mod_name.as_str()
            ),
            "\nuse crate::laertes_rt::*;".to_string(),
        );

        let mut flag_guard = HELPER_FLAG.lock().unwrap();
        if !*flag_guard {
            self.make_suggestion(
                ctx,
                helper_span,
                "add slice helpers to the end of the crate".into(),
                include_str!("../refslice.rs").into(),
            );
            *flag_guard = true;
        }
    }

    fn check_item(&mut self, ctx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if item.span.in_derive_expansion() {
            let attrs = ctx.tcx.hir().attrs(item.hir_id());
            for attr in attrs {
                // println!("{}", attr.name_or_empty().to_ident_string());
                self.check_attribute(ctx, attr);
            }
        }
        let name = Name::from(get_hir_qname(ctx, item.hir_id()));
        // if name.as_ref().contains("xml"){
        //     return;
        // }
        match &item.kind {
            ItemKind::Enum(_, _)
            | ItemKind::Struct(_, _)
            | ItemKind::Union(_, _)
            | ItemKind::TyAlias(_, _) => {
                // Handled in check_item_post
            },
            ItemKind::Static(ty, _, _) => {
                // insert necessary lifetime variables (specifically, 'static everywhere)
                let resolved_type = self.struct_info.resolve_type(&Type::from_hir_ty(ctx, ty));
                let loc = Loc::Var(name.clone());
                let ty_with_lifetimes = self.rewrite_type(
                    &resolved_type,
                    Some(&loc).into_iter().collect(),
                    &mut vec![],
                    &mut LifetimeGen::static_only(),
                );

                // convert all free lifetime variables to 'static
                let ty_with_statics = ty_with_lifetimes.sub_free_lifetime_vars(
                    &HashMap::default(),
                    Some(&*better::types::STATIC_LIFETIME),
                );
                log::warn!("new type for global {}: {}", name, ty_with_statics);

                self.make_suggestion(
                    ctx,
                    ty.span,
                    "re-write global variable's type".to_owned(),
                    format!("{}", ty_with_statics),
                );
                self.global_types.insert(name, ty_with_statics);
            },
            _ => {}, // ignore other item kinds
        }
    }

    fn check_item_post(&mut self, ctx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        self.remove_derive = false;
        let name = Name::from(get_hir_qname(ctx, item.hir_id()));
        match &item.kind {
            ItemKind::Enum(_enum_def, _generics) => {
                todo!("processing enums is not implemented");
            },
            ItemKind::Struct(data, _generics) => {
                // if name.as_ref().contains("xml"){
                //     return;
                // }
                let only_impl_default = self
                    .struct_info
                    .occurs_in_external_apis
                    .contains(&Node::Struct(name.clone()));
                self.rewrite_struct(
                    ctx,
                    name,
                    item.ident,
                    data.fields(),
                    item.span,
                    only_impl_default,
                );
                let attrs = ctx.tcx.hir().attrs(item.hir_id());
                for attr in attrs {
                    // println!("{}", attr.name_or_empty().to_ident_string());
                    self.check_attribute(ctx, attr);
                }
            },
            ItemKind::Union(_fields, _generics) => {
                // Don't rewrite union definitions
            },
            ItemKind::TyAlias(ty, _generics) => {
                // if name.as_ref().contains("xml"){
                //     return;
                // }
                // rewrite pointer-containing type aliases/typedefs
                // like structs
                self.rewrite_typedef(ctx, name, item.ident.span, ty);
                // log::warn!("RL————check_item_post: name {:?}", name);
                // if name.contains("Func") {
                //    log::warn!("Don't rewrite typedef pointer to function");
                // }
                // else{
                //     self.rewrite_typedef(ctx, name, item.ident.span, ty);
                // }
            },
            ItemKind::Static(_ty, _, _) => {
                // handled in check_item()
            },
            _ => {}, // ignore other item kinds
        }
    }

    fn check_body_post(&mut self, ctx: &LateContext<'tcx>, body: &'tcx Body<'tcx>) {
        let hir_map = ctx.tcx.hir();
        let owner_id = hir_map.body_owner(body.id());
        assert_eq!(
            body.generator_kind, None,
            "async generator bodies are not supported!"
        );
        if let BodyOwnerKind::Static(_) = hir_map.body_owner_kind(owner_id) {
            // rewrite the body of globals
            assert!(
                body.params.is_empty(),
                "Expected a body with no parameters for a global. First parameter is at {:?}",
                body.params[0].span
            );
            let global_name = Name::from(get_def_qname(
                ctx,
                hir_map.body_owner_def_id(body.id()).to_def_id(),
            ));
            let _unqual_name = global_name.as_ref().rsplit_once("::").unwrap().1;
            log::warn!("global_name: {:?}", global_name.as_ref());
            let default_value_expr = self.default_value(&self.global_types[&global_name]);
            // if in limit study, separate the initializer to a function
            if let Some(_default) = default_value_expr.as_ref() {
                // self.make_suggestion(
                //     ctx,
                //     body.value.span.shrink_to_lo(),
                //     "off-load global initializers to a context where boxes are permitted"
                //         .to_owned(),
                //     format!(
                //         "{}; unsafe fn laertes_init_{}() {{\n{} = ",
                //         default, unqual_name, unqual_name
                //     ),
                // );
            }
            self.rewrite_expr(ctx, &body.value, RewriteCtx::assignee());
            if default_value_expr.is_some() {
                // self.make_suggestion_after(
                //     ctx,
                //     body.value.span.shrink_to_hi(),
                //     "off-load global initializers to a context where boxes are permitted"
                //         .to_owned(),
                //     ";}//".to_owned(),
                // );
            }
        }
    }

    fn check_foreign_item(&mut self, ctx: &LateContext<'tcx>, item: &'tcx ForeignItem<'tcx>) {
        // Rewrite foreign item types to remove typedefs
        let rewrite_type_in_extern = |ty: &rustc_hir::Ty| {
            let resolved_type = self.struct_info.resolve_type(&Type::from_hir_ty(ctx, ty));
            self.make_suggestion(
                ctx,
                ty.span,
                "rewrite type in extern declaration".to_owned(),
                resolved_type.to_string(),
            )
        };

        match &item.kind {
            ForeignItemKind::Fn(fn_decl, _param_names, _generics) => {
                fn_decl.inputs.iter().for_each(rewrite_type_in_extern);
                if let FnRetTy::Return(ret) = fn_decl.output {
                    rewrite_type_in_extern(ret);
                }
            },
            ForeignItemKind::Static(ty, _) => {
                rewrite_type_in_extern(ty);
            },
            ForeignItemKind::Type => {},
        }
    }

    fn check_fn_post(
        &mut self,
        ctx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        hir_id: HirId,
    ) {
        let name = Name::from(get_hir_qname(ctx, hir_id));
        if name.as_ref().ends_with("::main") {
            if LIMIT_STUDY.load(Ordering::Relaxed) {
                self.make_suggestion(
                    ctx,
                    body.value.span,
                    "in limit study, so removing the body of Rust main fn".to_owned(),
                    "{}".to_owned(),
                );
            } else {
                log::info!("Skipping main function at {:?}", span);
            }
            return;
        }

        match kind {
            FnKind::ItemFn(ident, generics, header, visibility) => {
                // log::warn!("------fn name()------: {:?}", name);
                if !name.as_ref().contains("::bitfields")
                    && !name.as_ref().ends_with("::get_bits")
                    && !name.as_ref().ends_with("::set_bits")
                {
                    // the header is between the visibility and the
                    // function name (the `extern .. fn` part of the
                    // signature `pub extern .. fn foo`)
                    let header_span = visibility.span.between(ident.span);
                    self.process_fn(ctx, name, decl, body, generics, header, header_span);
                }
            },
            FnKind::Method(..) if is_synthetic_fn(decl, body) => {
                log::info!("Skipping synthetic method {} at {:?}", name, span)
            },
            FnKind::Method(..) => {
                log::warn!("Method name: {:?}", name);
                // skip the bitfield helpers we added
                if name.as_ref().contains("::bitfields")
                // || name.as_ref().contains("::xmlschemastypes")
                {
                    todo!("methods are not processed yet: {:?}", decl);
                }
            },
            FnKind::Closure => unimplemented!("closures are not supported"),
        }
    }

    fn check_attribute(
        &mut self,
        ctx: &LateContext<'tcx>,
        attr: &'tcx better::rustc_ast::ast::Attribute,
    ) {
        // remove the attributes related to the structs that are removed
        if !attr.is_doc_comment() {
            if self.remove_derive && attr.has_name(sym::automatically_derived) {
                let begin_span = ctx
                    .sess()
                    .source_map()
                    // .span_extend_to_prev_char(attr.span, '\n')
                    .span_extend_to_prev_char(attr.span, '\n', false) // accept_newlines: false
                    .shrink_to_lo();
                self.make_suggestion(
                    ctx,
                    begin_span,
                    "comment out derive".to_owned(),
                    "// ".to_owned(),
                );
                self.remove_derive = false;
            }
        }
    }

    fn check_crate(&mut self, _: &LateContext<'tcx>) {
        // Reset all edit offsets and suggestions
        *EDIT_OFFSETS.lock().unwrap() = EditOffsets::default();
        RUSTFIX_SUGGESTIONS.lock().unwrap().clear();
    }

    fn check_crate_post(&mut self, _ctx: &LateContext<'tcx>) {
        // 新版工具链无法实现

        // self.make_suggestion(
        //     ctx,
        //     krate.item.span.shrink_to_hi(),
        //     "add slice helpers to the end of the crate".into(),
        //     include_str!("../refslice.rs").into(),
        // );

        // analysis::replace::<SpanInfo>(Box::new(std::mem::take(&mut self.span_info)));

        // Compute the data pertaining to edits
        EDIT_OFFSETS.lock().unwrap().compute_cumulative_offsets();
    }
}

pub fn main() {
    // 1. provenance & call graph
    // 2. struct dependency
    // 3. struct use in API calls args (TODO)
    // 4. re-write ptrs in struct fields, using 1, 2, 3 (unless used by ptr arith)
    //    - make everything Option
    //    - decide: owned first vs borrow first
    //    - convert to raw ptrs at API boundaries in calls
    // 5. re-write function declarations by introducing refs for ptrs & structs
    //    - using 1, 4
    // 6. re-write malloc to return Box<T>
    //    - using 1
    //    - the later parts will fix ptrs from malloc
    //    - may need to taint these boxes so they won't be put in reference (non-owned) variables/fields on later passes
    //    -
    // 7. re-write function bodies
    //    - glue code to convert refs<->ptrs
    //    - adding unwrap() before defer
    //    - rewriting null checks (p == null -> p.empty(), and other variants)
    //      - may build a local refactoring tool for this
    //      - other instances of null will become None, if they are compared to references

    // This is our logger
    env_logger::init();
    // Initialize rustc's logger as well
    rustc_driver::init_rustc_env_logger();

    // TODO(maemre): Catch internal compiler errors for better diagnostics
    let matches = clap_app!(create_initial_program =>
                            (about: "Creates the program with initial lifetimes")
                            (@arg rollback: -r --rollback "Rollback the files if the compilation fails")
                            (@arg dry_run: --("dry-run") "Dry run, do not apply fixes")
                            (@arg print_suggestions: --("print-suggestions") "Print suggestions for rewriting the program before applying them")
                            (@arg print_constraints: --("print-constraints") "Print data flow constraints as they are added")
                            (@arg print_taints: --("print-taints") "Print taints from the taint analysis after all additional solving")
                            (@arg print_immediate_flows: --("print-immediate-flows") "Print immediate data flows used for inserting reference->pointer casts")
                            (@arg print_owned: --("print-owned") "Print owned from the taint analysis after all additional solving")
                            (@arg print_errors: -i --("print-errors") "Intercept and print error messages in JSON format")
                            (@arg merge_field_lifetimes: --("merge-field-lifetimes") "Use a single lifetime for all struct fields.")
                            (@arg iterative_fixes: -f --("iterative-fixes") "Iteratively fix the program, this implies --intercept-errors")
                            (@arg load_config: --("load-config") +takes_value "Load given serialized configuration as the initial configuration, rather than bottom.")
                            (@arg store_config: --("store-config") +takes_value "Store the configuration to given file. The file is overwritten after each iteration.")
                            (@arg promote_refslice: --("promote-refslice") "Allow promoting slices to slices of RefCells.")
                            (@arg limit_study: --("limit-study") "Ignore the global and cast poisons and rewrite casts to conduct our limit study")
                            (@arg directional: --("directional") "Use directional analysis and insert casts.")
                            (@arg no_ptr_arith_rewrite: --("i-promise-no-ptr-arith") "There is no pointer arithmetic in the input program")
                            (@arg emulate_lifetime_only: --("emulate-lifetime-only") "Disable additional kinds of unsafety or pointer types handled besides lifetimes.")
                            (@arg iter_limit: --("iter-limit") +takes_value "Run for given number of iterations")
                            (@arg no_ptr_ref_aliasing: --("no-ptr-ref-aliasing") "Force all casted pointers to be owned to prevent aliasing between pointers and references.")
                            (@arg compiler_args: <compiler_args>... "Arguments to pass to the compiler")
    ).setting(clap::AppSettings::TrailingVarArg)
        .get_matches();

    APPLY_FIXES.store(!matches.is_present("dry_run"), Ordering::Relaxed);
    DIRECTIONAL_ANALYSIS.store(matches.is_present("directional"), Ordering::Relaxed);
    NO_PTR_REF_ALIASING.store(matches.is_present("no_ptr_ref_aliasing"), Ordering::Relaxed);
    MERGE_FIELD_LIFETIMES.store(
        matches.is_present("merge_field_lifetimes"),
        Ordering::Relaxed,
    );
    PRINT_CONSTRAINTS.store(matches.is_present("print_constraints"), Ordering::Relaxed);
    POISON_SIGS_OF_FN_PTRS.store(
        matches.is_present("emulate_lifetime_only"),
        Ordering::SeqCst,
    );
    println!(
        "poison sigs of fn ptrs? {}",
        POISON_SIGS_OF_FN_PTRS.load(Ordering::SeqCst)
    );
    LIMIT_STUDY.store(matches.is_present("limit_study"), Ordering::Relaxed);
    NO_PTR_ARITH_REWRITE.store(
        matches.is_present("no_ptr_arith_rewrite"),
        Ordering::Relaxed,
    );
    EMULATE_LIFETIME_ONLY.store(
        matches.is_present("emulate_lifetime_only"),
        Ordering::Relaxed,
    );

    let print_taints = matches.is_present("print_taints");
    let print_immediate_flows = matches.is_present("print_immediate_flows");
    let print_owned = matches.is_present("print_owned");
    let _print_suggestions = matches.is_present("print_suggestions");
    let iterative_fixes = matches.is_present("iterative_fixes");
    let print_errors = matches.is_present("print_errors");
    let intercept_errors = iterative_fixes || print_errors;
    let load_config = matches.value_of("load_config");
    let store_config = matches.value_of("store_config");
    let promote_refslice = matches.is_present("promote_refslice");
    let iter_limit = matches
        .value_of("iter_limit")
        .map(|s| s.parse::<u32>().unwrap());

    let compiler_args = {
        let mut args = Vec::new();
        args.push("create-initial-program".to_string());
        args.extend(
            matches
                .values_of("compiler_args")
                .unwrap()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
        );
        args
    };

    println!(
        "Compiler arguments: {}",
        compiler_args.iter().map(|s| format!("'{}'", s)).join(" ")
    );

    // set up pointer provenance analysis for lifetime and ownership
    // analysis within our limitations.
    POISON_UNRELATED_TYPE_CASTS.store(true, Ordering::Relaxed);
    ANALYZE_GLOBAL_INITS.store(true, Ordering::Relaxed);
    COMPUTE_OWNERSHIP.store(true, Ordering::Relaxed);

    let cfg = better::Config {
        output_path: None,
        output_mode: OutputMode::Overwrite,
    };

    let iter_opts =
        better::compiler_interface::error_handling::ErrorHandlingOpts { promote_refslice };

    let file_io = FileIO::new(&cfg);

    // If we are loading a configuration, set it up before the analysis phases
    if let Some(config_file) = load_config {
        println!("Loading the initial configuration from {}", config_file);
        *CONFIG.write().unwrap() = better::ron::from_str(
            file_io
                .read_file(std::path::Path::new(config_file))
                .unwrap()
                .as_str(),
        )
        .unwrap();
    }

    let mut iteration = 0;
    let mut changed = ConfigChange::Unchanged;
    let mut success = false;

    loop {
        iteration += 1;
        println!("iteration {}", iteration);

        // Skip analysis steps if the pointer kinds have not changed
        if iteration == 1 || changed == ConfigChange::PtrKind {
            // do not reset the counters if we are skipping the analysis steps
            reset_lifetime_counter();
            reset_loc_counter();
            *CRATE_NAME.lock().unwrap() = Name::from("");
            let exit_code = run_compiler_with_setup(
                compiler_args.clone(),
                &vec![],
                vec![PtrProvenancePass::new],
                |_| {},
            )
            .0;

            if print_owned {
                println!("Locations marked as owned:");
                let taint_analysis = analysis::result::<PtrProvenanceAnalysis>().unwrap();
                // using BTreeMap to keep locations in order when printing
                let ordered_locs = taint_analysis
                    .owned
                    .iter()
                    .collect::<BTreeSet<&Loc<Name>>>();

                for loc in ordered_locs {
                    println!(" - {}", format!("{:?}", loc).yellow());
                }
                println!("Locations marked as refcell:");
                // using BTreeMap to keep locations in order when printing
                let ordered_rlocs = taint_analysis
                    .refcell
                    .iter()
                    .collect::<BTreeSet<&Loc<Name>>>();

                for loc in ordered_rlocs {
                    println!(" - {}", format!("{:?}", loc).green());
                }
            }

            if exit_code != 0 {
                println!(
                    "ERROR: The initial program does not compile: rustc exited with code {} on the initial program.",
                    exit_code
                );
                exit(exit_code);
            }

            println!("running struct info pass");

            // steps 1, 2, 3
            run_compiler_with_setup(
                compiler_args.clone(),
                &vec![],
                vec![StructInfoPass::new, SpanInfoPass::new],
                |_| {},
            );
        } else {
            println!("The pointer kinds haven't changed, skipping analysis");
        }

        // steps 4, 5, 6, and 7
        run_compiler_with_setup(
            compiler_args.clone(),
            &vec![],
            vec![RewritePass::new],
            |_| {},
        );

        // if print_suggestions {
        println!("{}", "Unsafe removal suggestions:".bold().green());

        for (file, suggestions) in RUSTFIX_SUGGESTIONS.lock().unwrap().iter() {
            println!("For file {}:", file.to_str().unwrap());

            for suggestion in suggestions.values().flatten() {
                let solution = &suggestion.solutions[0];
                println!("{}", solution.message);
                for replacement in &solution.replacements {
                    println!(" - replace {:?}", replacement.snippet.text);
                    println!("   with   `{}`", replacement.replacement);
                    println!(
                        "   at {} {}:{}-{}:{}",
                        replacement.snippet.file_name,
                        replacement.snippet.line_range.start.line,
                        replacement.snippet.line_range.start.column,
                        replacement.snippet.line_range.end.line,
                        replacement.snippet.line_range.end.column,
                    );
                }
            }
        }
        // }

        let taint_analysis = analysis::result::<PtrProvenanceAnalysis>().unwrap();

        if print_taints {
            println!("Poisoned locations:");
            // using BTreeMap to keep locations in order when printing
            let mut loc_to_poison = BTreeMap::<Loc<Name>, BTreeSet<PoisonKind>>::new();
            for (poison, locs) in &taint_analysis.poisons {
                for loc in locs {
                    if !matches!(loc, Loc::Fresh(..)) {
                        loc_to_poison
                            .entry(loc.clone())
                            .or_default()
                            .insert(*poison);
                    }
                }
            }

            for (loc, poisons) in loc_to_poison {
                println!("{} -> {:?}", format!("{:?}", loc).cyan(), poisons);
            }
        }
        if print_immediate_flows {
            println!("immediate data flows:");
            for (hir_id, flow_loc) in &taint_analysis.arg_or_init {
                if let Some(source) = taint_analysis
                    .expr_to_term
                    .get(hir_id)
                    .and_then(Term::get_lv)
                {
                    println!("{} -> {:?}", format!("{:?}", source).magenta(), flow_loc);
                }
            }
        }

        // TODO: move this to better::io
        let mut orig_files = HashMap::default();

        if !APPLY_FIXES.load(Ordering::Relaxed) {
            println!("--dry-run option is given, not applying fixes");
        } else {
            println!("{}", "Applying fixes".bold().green());

            for (file, mut suggestions) in RUSTFIX_SUGGESTIONS.lock().unwrap().drain() {
                // println!("Rewriting file {}:", file.to_str().unwrap());

                // 去掉replace ("", "BitfieldStruct", "")
                for (_key, values) in suggestions.iter_mut() {
                    values.retain(|suggestion| {
                        suggestion.solutions[0].replacements[0].snippet.text.1 != "BitfieldStruct"
                    });
                }

                let ordered_suggestions = RewritePass::merge_suggestions(suggestions);

                // remember and load the original source code
                let orig_source = orig_files
                    .entry(file.clone())
                    .or_insert_with_key(|f| file_io.read_file(f).unwrap());

                let fixed_source_code = {
                    // apply suggestions in an explicit loop rather than using
                    // `apply_suggestions` so that we can have better data to
                    // debug when rustfix fails because of overlapping
                    // suggestions.
                    let mut codefix = CodeFix::new(orig_source);
                    for suggestion in ordered_suggestions.values().flatten() {
                        if let Err(msg) = codefix.apply(suggestion) {
                            // find conflicting suggestions
                            let spans = suggestion
                                .solutions
                                .iter()
                                .flat_map(|s| &s.replacements)
                                .map(|s| s.snippet.range.clone())
                                .collect::<HashSet<std::ops::Range<usize>>>();

                            for (other_depth, other_suggestions) in ordered_suggestions.iter() {
                                for other_suggestion in other_suggestions {
                                    let mut other_spans = other_suggestion
                                        .solutions
                                        .iter()
                                        .flat_map(|s| &s.replacements)
                                        .map(|s| s.snippet.range.clone());
                                    if other_spans.any(|other| {
                                        spans
                                            .iter()
                                            .any(|s| (other.start <= s.end && s.start <= other.end))
                                    }) {
                                        println!(
                                            "{}: {:?} at depth {}",
                                            "conflicting suggestion".red(),
                                            other_suggestion.solutions,
                                            other_depth
                                        );
                                    }
                                }
                            }

                            panic!(
                                "Error when applying suggestion {:?}\n{:?}",
                                suggestion.solutions, msg
                            );
                        }
                    }
                    codefix.finish().unwrap()
                };
                file_io.write_file(&file, &fixed_source_code).unwrap();
            }

            let exit_code =
                run_compiler_with_setup(compiler_args.clone(), &vec![], vec![], |callbacks| {
                    // rustc_driver::init_rustc_env_logger();

                    if intercept_errors {
                        callbacks.redirect_errors_to(&*ERROR_BUFFER);
                        callbacks.config_cb = Some(setup_output);
                    }
                })
                .0;

            if exit_code == 0 {
                println!(
                    "DONE: {}",
                    "The compiler successfully compiles the code".green()
                );
                success = true;
                break;
            } else {
                if !iterative_fixes {
                    println!(
                        "DONE: {}",
                        "Compilation failed, please unroll the unsafe changes".red()
                    );
                }
                if print_errors {
                    let errors = ERROR_BUFFER.lock().unwrap();
                    println!(
                        "compiler errors:\n'{}'",
                        std::str::from_utf8(&errors).unwrap()
                    );
                }
            }
        }

        if !iterative_fixes {
            break;
        }

        let mut error_buffer = ERROR_BUFFER.lock().unwrap();
        let errors = std::str::from_utf8(&error_buffer).unwrap();
        let cfg = better::compiler_interface::error_handling::generate_fixes(
            errors,
            &iter_opts,
            &*CONFIG.read().unwrap(),
        );

        println!("{} {:?}", "New configuration:".green(), cfg);

        changed = CONFIG.write().unwrap().join(cfg);

        if changed == ConfigChange::Unchanged {
            // The configuration hasn't changed, we reached a fixpoint
            // and there are still compilation errors. This is a bug!
            println!(
                "{} The final configuration: {:#?}",
                "Reached a fixpoint while still having compiler errors:".red(),
                *CONFIG.read().unwrap()
            );
            break;
        }

        // store the configuration
        if let Some(config_file) = store_config.as_ref() {
            println!("{}", *config_file);
            file_io
                .write_file(
                    std::path::Path::new(*config_file),
                    better::ron::to_string(&*CONFIG.read().unwrap())
                        .unwrap()
                        .as_str(),
                )
                .unwrap();
        }

        if Some(iteration) == iter_limit {
            println!("{}", "Reached iteration limit, stopping.".yellow());
            break;
        }

        // restore the original files
        for (path, contents) in orig_files {
            file_io
                .write_file(path.as_path(), contents.as_ref())
                .unwrap();
        }

        // restore the globals
        error_buffer.clear();
        let mut flag_guard = HELPER_FLAG.lock().unwrap();
        *flag_guard = false;
    }

    // let call_graph = analysis::result::<CallGraph>().unwrap();
    // println!("{}\n", "fns used as fn pointers:".red());
    // call_graph
    //     .used_as_fn_pointer
    //     .iter()
    //     .for_each(|f| println!("{}", f));

    // println!("{}\n", "extern functions :".red());
    // call_graph.extern_fns.iter().for_each(|f| println!("{}", f));

    better::util::report_profiling_results();

    if !success {
        std::process::exit(1);
    }
}
