//! Pointer provenance analysis. This analysis is used for determining
//! the provenance of pointers, and whether to promote them to
//! references.
//!
//! The analysis is a form of set-based points-to analysis combined
//! with a taint analysis.
#![feature(option_result_contains)]
use crate::{
    analysis,
    analysis::commons::can_rewrite_allocation,
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
    rustc_span::{def_id::DefIndex, symbol::Ident, Span},
    serde::{de::*, Deserialize, Deserializer, Serialize, Serializer},
    solver::*,
    types,
    types::{get_constant_value, Type},
    util::{profile, HashMap, HashSet},
    Name,
};
use def_id::{DefId, LOCAL_CRATE};
use itertools::Itertools;
use rustc_span::def_id::LocalDefId;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::{Debug, Display},
    mem, panic,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
use SimpleTerm::*;
use Term::*;

use crate::solver::{equality_based::*, set_based};

/// Whether we should not allow aliasing between pointers and references
/// (enforced by moving/consuming references).
///
/// A better alternative is to create an unchecked RefCell variant for these
/// pointers.
pub static NO_PTR_REF_ALIASING: AtomicBool = AtomicBool::new(false);

/// Whether we removed all sources of pointer arithmetic before
/// running this tool, and not rewriting arrays to custom slices.
pub static NO_PTR_ARITH_REWRITE: AtomicBool = AtomicBool::new(false);

pub static POISON_MIXED_REFS: AtomicBool = AtomicBool::new(true);
/// Whether we should poison the signatures of functions that are used
/// as function pointers
pub static POISON_SIGS_OF_FN_PTRS: AtomicBool = AtomicBool::new(false);

/// Whether we should compute ownership analysis results
pub static COMPUTE_OWNERSHIP: AtomicBool = AtomicBool::new(true);

/// Whether we should poison pointers cast to unrelated types
pub static POISON_UNRELATED_TYPE_CASTS: AtomicBool = AtomicBool::new(true);

/// Whether we should analyze bodies of globals, this does not matter
/// for counting but it matters for rewriting programs that have
/// nontrivial initialization code for globals.
pub static ANALYZE_GLOBAL_INITS: AtomicBool = AtomicBool::new(true);

/// Whether we should print generated constraints
pub static PRINT_CONSTRAINTS: AtomicBool = AtomicBool::new(false);

/// Whether we are conducting the limit study and ignoring globals and
/// casts.
pub static LIMIT_STUDY: AtomicBool = AtomicBool::new(false);

/// Emulate the method from "Translating C to Safe Rust" by Emre et
/// al. (OOPSLA 2021).  This flag disables pointer arithmetic and function pointer rewrites.
pub static EMULATE_LIFETIME_ONLY: AtomicBool = AtomicBool::new(false);

/// Whether to use the subset-based (directional) analysis to propagate
/// unsafety derived from compiler errors.
pub static DIRECTIONAL_ANALYSIS: AtomicBool = AtomicBool::new(false);

fn mk_ref<V>(co: SimpleTerm<V>, contra: SimpleTerm<V>) -> Term<V> {
    C(Ctor(REF.clone(), vec![co], vec![contra]))
}

/// Create a lambda constructor to represent function pointers.
///
/// lambda(ret, args...) is invariant on both ret and args.
///
pub fn mk_lambda<V: Clone>(mut args: Vec<SimpleTerm<V>>, ret: SimpleTerm<V>) -> Term<V> {
    let arity = args.len();
    // args.reverse();
    // args.push(ret);
    // args.reverse();
    // C(Ctor(LAMBDA[arity].clone(), args.clone(), args.clone()))
    args.reverse();
    args.push(SimpleTerm::EmptySet);
    args.reverse();
    C(Ctor(LAMBDA[arity].clone(), vec![ret], args.clone()))
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
            (*name != *REF && !(name.starts_with("λ")) && *name != *FNDEF)
                || co.iter().any(mentions_types_s)
                || contra.iter().any(mentions_types_s)
        },
        S(s) => mentions_types_s(s),
    }
}

/// Returns whether there are non-arithmetic poisons in given set
pub fn non_arith_poison_in_set(mut poisons: HashSet<PoisonKind>) -> bool {
    if poisons.is_empty() {
        return false;
    }
    poisons.remove(&PoisonKind::PtrArith);
    poisons.remove(&PoisonKind::PtrArithSink);
    !poisons.is_empty()
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
    /// Whether this expression a pointer passed to free as an argument
    in_free: bool,
    rewritable_malloc: bool,
}

impl ExprCtx {
    /// Creates a new context with given is_callee, resets in_free
    pub fn with_callee(&self, is_callee: bool) -> Self {
        ExprCtx {
            is_callee,
            in_free: false,
            ..self.clone()
        }
    }
    /// Creates a new context with the same is_assignee, resets everything else
    pub fn keep_assignee(&self) -> Self {
        ExprCtx {
            is_assignee: self.is_assignee,
            ..ExprCtx::default()
        }
    }
    /// Creates a new context with given is_assignee, resets in_free
    pub fn with_assignee(&self, is_assignee: bool) -> Self {
        ExprCtx {
            is_assignee,
            in_free: false,
            ..self.clone()
        }
    }
    /// Creates a new context with given in_free, resets the rest of the context
    pub fn with_in_free(in_free: bool) -> Self {
        ExprCtx {
            in_free,
            is_assignee: false,
            is_callee: false,
            rewritable_malloc: false,
        }
    }
    pub fn with_rewritable_malloc(&self, rewritable_malloc: bool) -> Self {
        ExprCtx {
            rewritable_malloc,
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
    /// Source for values going to llvm inline assembly.
    InlineAsmSource,
    /// Sink for values going to llvm inline assembly.
    InlineAsmSink,
    /// Sink for mutability analysis. We need only a
    /// sink because we need to mark only `&mut`/`*mut` that flows
    /// into a deref that is used in a mutable context.
    MutSink,
    /// Source for mixing pointer arithmetic and addr-of
    MixedRefSource,
    /// Sink for mixing pointer arithmetic and addr-of
    MixedRefSink,
    /// Source for function pointer arguments/return values
    FnPtrSource,
    /// Sink for function pointer arguments/return values
    FnPtrSink,
    /// Source for pointers promoted to raw due to configuration change
    PromotedSource,
    /// Sink for pointers promoted to raw due to configuration change
    PromotedSink,
    // Casting to a different type or incompatible mutability
    CastSource,
    CastSink,
    /// Source for mem::transmute's return value
    TransmuteSource,
    /// Sink for mem::transmute's argument
    TransmuteSink,
    /// Source for string literals
    StringLitSource,
    // Globals
    GlobalSource,
    GlobalSink,
    // argv in main function
    ArgvSource,
    ArgvSink,
    /// Sink for volatile writes
    VolatileSink,
    /// Source for accessing unions
    UnionFieldSource,
    /// Sink for accessing unions
    UnionFieldSink,
}

impl PoisonKind {
    pub fn is_ptr_arith(&self) -> bool {
        *self == PoisonKind::PtrArith || *self == PoisonKind::PtrArithSink
    }
}

static POISON_SOURCES: [PoisonKind; 14] = [
    PoisonKind::PtrArith,
    PoisonKind::ExternCallReturn,
    PoisonKind::VoidSource,
    PoisonKind::MiscSource,
    PoisonKind::InlineAsmSource,
    PoisonKind::MixedRefSource,
    PoisonKind::FnPtrSource,
    PoisonKind::PromotedSource,
    PoisonKind::CastSource,
    PoisonKind::TransmuteSource,
    PoisonKind::StringLitSource,
    PoisonKind::GlobalSource,
    PoisonKind::ArgvSource,
    PoisonKind::UnionFieldSource,
];

static POISON_SINKS: [PoisonKind; 14] = [
    PoisonKind::PtrArithSink,
    PoisonKind::ExternCallParam,
    PoisonKind::VoidSink,
    PoisonKind::MiscSink,
    PoisonKind::InlineAsmSink,
    PoisonKind::MixedRefSink,
    PoisonKind::FnPtrSink,
    PoisonKind::PromotedSink,
    PoisonKind::CastSink,
    PoisonKind::TransmuteSink,
    PoisonKind::GlobalSink,
    PoisonKind::ArgvSink,
    PoisonKind::VolatileSink,
    PoisonKind::UnionFieldSink,
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
    /// Call to unsafe standard library functions
    UnsafeStdCall,
    /// This function is variadic or calls a variadic function
    VariadicFn,
}

/// All types of unsafe behavior a program may exhibit, this must be kept in sync with `UnsafeBehavior`
pub static ALL_UNSAFE_BEHAVIOR: [UnsafeBehavior; 9] = [
    UnsafeBehavior::ReadFromUnion,
    UnsafeBehavior::MutGlobalAccess,
    UnsafeBehavior::InlineAsm,
    UnsafeBehavior::ExternCall,
    UnsafeBehavior::RawPtrDeref,
    UnsafeBehavior::UnsafeCast,
    UnsafeBehavior::Alloc,
    UnsafeBehavior::UnsafeStdCall,
    UnsafeBehavior::VariadicFn,
];

#[derive(PartialEq, Eq, Clone, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    Synthetic(
        #[serde(serialize_with = "serialize_hir_id")]
        #[serde(deserialize_with = "deserialize_hir_id")]
        HirId,
    ),
    /// A location marking values returned immediately from a call to
    /// malloc per call site, we don't mark those values as void *
    /// immediately to keep the analysis precise
    Malloc(
        #[serde(serialize_with = "serialize_hir_id")]
        #[serde(deserialize_with = "deserialize_hir_id")]
        HirId,
    ),
    /// A freshly-generated location for variables to glue certain
    /// constraints
    Fresh(u32),
}

impl<T: Display> Debug for Loc<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Loc::*;
        match self {
            Var(x) => write!(f, "Var({})", x),
            RetVal(fun) => write!(f, "RetVal({})", fun),
            Param(fun, n) => write!(f, "Param({}, {})", fun, n),
            Access(s, fld) => write!(f, "Access({}, {})", s, fld),
            Synthetic(h) => write!(f, "Synthetic({})", h),
            Malloc(h) => write!(f, "Malloc({})", h),
            Fresh(n) => write!(f, "Fresh({})", n),
        }
    }
}

impl<T> Loc<T> {
    /// Returns true if this reference is directly derived from the program
    pub fn is_from_program(&self) -> bool {
        match self {
            Loc::Synthetic(_) | Loc::Malloc(_) | Loc::Fresh(_) => false,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SerializableHirId(
    #[serde(
        serialize_with = "serialize_hir_id",
        deserialize_with = "deserialize_hir_id"
    )]
    pub HirId,
);

// Custom serialization `HirId` using rustc's Encode/Decode mechanism
fn serialize_hir_id<S: Serializer>(hir_id: &HirId, serializer: S) -> Result<S::Ok, S::Error> {
    // Encode the HIR ID in an ad-hoc way: internal owner's def index
    // followed by local id.
    let encoded_hir_id = format!(
        "{},{}",
        u32::from(hir_id.owner.local_def_index),
        hir_id.local_id.as_u32()
    );
    serializer.serialize_str(encoded_hir_id.as_str())
}

fn deserialize_hir_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<HirId, D::Error> {
    deserializer.deserialize_str(HirIdVisitor)
}

struct HirIdVisitor;
impl<'de> Visitor<'de> for HirIdVisitor {
    type Value = HirId;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "json-encoded HIR ID")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: crate::serde::de::Error,
    {
        let (owner, local) = v.split_once(',').unwrap();
        Ok(HirId {
            owner: LocalDefId {
                local_def_index: DefIndex::from(owner.parse::<u32>().unwrap()),
            },
            local_id: ItemLocalId::from_u32(local.parse::<u32>().unwrap()),
        })
    }
}

/// Taint information related to a function. It is specialized for known
/// functions so we don't need to project out the λ constructors when they are
/// not needed.
#[derive(Copy, Clone)]
pub enum FnTaintInfo<'a, T> {
    /// A known, concrete function
    Known(&'a Name),
    /// A function pointer with associated location
    FnPtr(&'a Loc<T>),
}

impl<'a, T> FnTaintInfo<'a, T> {
    pub fn is_known_fn(&self) -> bool {
        use FnTaintInfo::*;
        match self {
            Known(..) => true,
            FnPtr(..) => false,
        }
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
            Loc::Fresh(n) => Loc::Fresh(n),
            Loc::Malloc(h) => Loc::Malloc(h),
        }
    }

    /// Renames type names inside this location using given function
    pub fn rename_types<F: FnMut(T) -> T>(self, fun: &mut F) -> Loc<T> {
        match self {
            Loc::Access(typename, field) => Loc::Access(fun(typename), field),
            Loc::Var(_)
            | Loc::RetVal(_)
            | Loc::Param(_, _)
            | Loc::Synthetic(_)
            | Loc::Fresh(_)
            | Loc::Malloc(_) => self,
        }
    }
}

/// A location that may need to be computed by projecting out some constructors.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum FlowLoc {
    /// A resolved location
    Plain(Loc<Name>),
    /// A function parameter that needs to be projected out
    ///
    /// The first number is arity, the second number is the index
    Param(Loc<Name>, Option<usize>, usize),
    // /// A return value that needs to be projected out
    // RetVal(Loc<Name>),
    /// A points-to set location (for nested pointers and arrays)
    PointsTo(Box<FlowLoc>),
}

impl FlowLoc {
    /// Checks if this location is owned by inspecting its subsets if it needs
    /// to be projected out
    pub fn is_owned(&self, ptr_provenance: &PtrProvenanceAnalysis) -> bool {
        let ref set_solver = ptr_provenance.set_constraints;
        assert!(set_solver.is_solved());

        match self {
            FlowLoc::Plain(l) => ptr_provenance.is_loc_owned(l),
            FlowLoc::Param(f, arity, i) => {
                let eq_owned = match ptr_provenance.project_lambdas(f, *arity).0.get(*i) {
                    Some(locs) => locs.iter().any(|loc| ptr_provenance.is_loc_owned(loc)),
                    None => false,
                };
                eq_owned
                // ptr_provenance.is_loc_owned(&Loc::Param(f.clone(), *i))
            },
            FlowLoc::PointsTo(f) => f.iter(ptr_provenance).into_iter().any(|l| {
                ptr_provenance
                    .points_to(&l)
                    .into_iter()
                    .any(|l| ptr_provenance.is_loc_owned(l))
            }),
        }
    }

    /// Checks if this location is poisoned. Projects lambdas to check
    /// for poisons if this is an argument.
    pub fn is_poisoned(&self, ptr_provenance: &PtrProvenanceAnalysis) -> bool {
        let ref set_solver = ptr_provenance.set_constraints;
        assert!(set_solver.is_solved());

        self.iter(ptr_provenance)
            .into_iter()
            .any(|l| ptr_provenance.is_poisoned(&l))
    }

    /// Reifies self to a set of locations by projecting λs and points to.
    pub fn reify(&self, ptr_provenance: &PtrProvenanceAnalysis) -> HashSet<Loc<Name>> {
        let ref set_solver = ptr_provenance.set_constraints;
        assert!(set_solver.is_solved());
        self.iter(ptr_provenance)
    }

    /// Renames types mentioned in this location by applying f
    pub fn rename_types<F: FnMut(Name) -> Name>(&mut self, f: &mut F) {
        match self {
            FlowLoc::Plain(ref mut l) => *l = l.clone().rename_types(f),
            FlowLoc::Param(..) => {},
            FlowLoc::PointsTo(inner) => inner.rename_types(f),
        }
    }

    /// Reifies self to an iterator of locations by projecting λs and points to sets.
    #[inline(always)]
    pub fn iter<'a>(&self, ptr_provenance: &'a PtrProvenanceAnalysis) -> HashSet<Loc<Name>> {
        let ref set_solver = ptr_provenance.set_constraints;
        assert!(set_solver.is_solved());

        match self {
            FlowLoc::Plain(l) => vec![l.clone()].into_iter().collect(),
            FlowLoc::Param(f, arity, i) => ptr_provenance
                .project_lambdas(f, *arity)
                .0
                .get(*i)
                .cloned()
                .into_iter()
                .flatten()
                .collect(),
            FlowLoc::PointsTo(f) => f
                .iter(ptr_provenance)
                .iter()
                .flat_map(|l| ptr_provenance.points_to(l).into_iter().map(Loc::clone))
                .collect(),
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
    /// Contains the IDs of the expressions that are passed to a function call
    /// or a local variable initializer. These expressions must have the
    /// same type as the parameter/local variable they are initializing (or have
    /// coercisons like borrows to do the type conversion).
    pub arg_or_init: HashMap<HirId, FlowLoc>,
    /// Contains the locations that are in global initializers
    pub in_global_init: HashSet<Loc<Name>>,
    /// Contains the locations marked as pointers requiring a RefCell promotion
    pub refcell: HashSet<Loc<Name>>,
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
    /// Locations of pointer casts that change mutability but not the
    /// underlying type.
    pub mutability_casts: HashSet<HirId>,
    /// Function signatures, we use these to extract extern function
    /// signatures so that we can poison values nested inside their
    /// arguments transitively by making sure that there are dummy
    /// locations for these calls.
    ///
    /// This is computed only for functions that appear as values
    /// inside expressions (this includes any called function).
    pub fn_sigs: HashMap<Name, types::FnSig>,
    /// Partial map from expression IDs to name of the struct type of given expression.
    pub maybe_expr_struct_type: HashMap<HirId, Name>,
    /// Whether we should emulate lifetime derivation only (no
    /// function pointer or pointer arithmetic rewrites).
    pub emulate_lifetime_only: bool,
    /// Remember dummy lambdas for each location so that we can find them when
    /// projecting lambdas
    pub dummy_lambdas: HashMap<Loc<Name>, (Vec<Loc<Name>>, Loc<Name>)>,
    /// Whether we need to solve the constraints and compute equivalence classes
    pub dirty: bool,
    /// Equivalence classes from the equality-based solver
    eq_classes: Option<HashMap<u32, HashSet<Loc<Name>>>>,
    /// Normal function arities, used for poisoning foreign function signatures
    /// and projecting lambdas in functions that are never called.
    fn_arity: HashMap<Name, usize>,
}

impl PtrProvenanceAnalysis {
    pub fn new() -> Self {
        let mut analysis = PtrProvenanceAnalysis {
            constraints: ConstraintSystem::new(),
            set_constraints: set_based::ConstraintSystem::new(),
            owners: HashMap::default(),
            expr_to_term: HashMap::default(),
            poisons: HashMap::default(),
            owned: HashSet::default(),
            in_global_init: HashSet::default(),
            arg_or_init: HashMap::default(),
            refcell: HashSet::default(),
            postponed_constraints: Vec::new(),
            postponed_taints: Vec::new(),
            typedefs_are_resolved: false,
            typedefs: HashMap::default(),
            mutability_casts: HashSet::default(),
            fn_sigs: HashMap::default(),
            maybe_expr_struct_type: HashMap::default(),
            emulate_lifetime_only: EMULATE_LIFETIME_ONLY.load(Ordering::Relaxed),
            dummy_lambdas: HashMap::default(),
            dirty: false,
            eq_classes: None,
            fn_arity: HashMap::default(),
        };

        for poison in POISON_SOURCES.iter() {
            analysis.poisons.insert(*poison, HashSet::default());
        }
        for poison in POISON_SINKS.iter() {
            analysis.poisons.insert(*poison, HashSet::default());
        }

        analysis
    }

    /// Return the points-to set of the given location. This computes `ref⁻¹(x)`
    /// effectively. We return two variables for the two arguments of
    /// `ref` (the covariant and the contravariant set) which collect
    /// different poison data in the subset-based variant. This
    /// function returns `None` for the points to sets that are not
    /// variables (the empty set and the universe).
    pub fn points_to<'a>(&'a self, p: &Loc<Name>) -> HashSet<&'a Loc<Name>> {
        // Compute the equality-based points-to info.
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

        // Also compute the set-based info (this may be expensive)
        if let Some(scc) = self.set_constraints.to_maybe_num(p) {
            for Ctor(name, co, contra) in self
                .set_constraints
                .lower_num(scc)
                .into_iter()
                .chain(self.set_constraints.upper_num(scc))
            {
                if *name != *REF {
                    continue;
                }
                assert_eq!(co.len(), 1);
                assert_eq!(contra.len(), 1);
                co[0]
                    .get_lv()
                    .into_iter()
                    .chain(contra[0].get_lv())
                    .for_each(|l| {
                        h.insert(self.set_constraints.pick_representative(*l));
                    });
            }
        }
        h
    }

    /// Add given data flow
    pub fn add_flow(&mut self, source: Term<Loc<Name>>, sink: Term<Loc<Name>>) {
        if (!self.typedefs_are_resolved) && (mentions_types(&source) || mentions_types(&sink)) {
            self.postponed_constraints.push(Constraint(source, sink));
            return;
        }
        self.add_flow_with_already_resolved_names(source, sink);
    }

    /// Add given data flow without typedef resolution. This should be used only
    /// when inserting constructors for functions to handle cases where a
    /// function and a typedef may share the same name, or when we know that all
    /// typedefs are resolved.
    fn add_flow_with_already_resolved_names(
        &mut self,
        source: Term<Loc<Name>>,
        sink: Term<Loc<Name>>,
    ) {
        if PRINT_CONSTRAINTS.load(Ordering::Relaxed) {
            log::info!("adding data flow {:?} -> {:?}", source, sink);
        }

        self.add_goal(Constraint(source, sink));
    }

    /// Add given subset-based constraint
    fn add_goal(&mut self, goal: Constraint<Loc<Name>>) {
        self.constraints.add_goal(goal.clone()).unwrap();
        self.set_constraints.add_goal(goal).unwrap();
        self.dirty = true;
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

        if self.emulate_lifetime_only {
            if poison == PoisonKind::PtrArith {
                self.add_poison(PoisonKind::MiscSource, loc.clone());
            } else if poison == PoisonKind::PtrArithSink {
                self.add_poison(PoisonKind::MiscSink, loc.clone());
            }
        }

        // add poison information to the equality solver, so it can be
        // propagated along data flow edges. we separate pointer arithmetic
        // poisons from the rest for this to handle mixed references.
        // for pointer arithmetic, we use the subset solver later on.
        self.constraints.add_poison(loc, poison);
    }

    /// Mark given location as an owned pointer, this is orthogonal to
    /// whether it is poisoned
    pub fn mark_as_owned(&mut self, loc: Loc<Name>) {
        self.owned.insert(loc);
    }

    /// Mark given location as a refcell pointer, orthogonal to its poisons
    pub fn mark_as_refcell(&mut self, loc: Loc<Name>) {
        self.refcell.insert(loc);
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
        let no_ptr_ref_aliasing = NO_PTR_REF_ALIASING.load(Ordering::Relaxed);
        let directional_analysis = DIRECTIONAL_ANALYSIS.load(Ordering::Relaxed);
        // load the promoted pointers from the configuration
        for (loc, kind) in &CONFIG.read().unwrap().ptr_kind {
            use PtrKind::*;
            match kind {
                Raw => {
                    // Use Promoted poisons when we do a directional analysis,
                    // use Misc poisons otherwise.
                    if directional_analysis {
                        self.add_poison(PoisonKind::PromotedSource, loc.clone());
                        self.add_poison(PoisonKind::PromotedSink, loc.clone());
                    } else {
                        self.add_poison(PoisonKind::MiscSource, loc.clone());
                        self.add_poison(PoisonKind::MiscSink, loc.clone());
                    }
                    if no_ptr_ref_aliasing {
                        self.mark_as_owned(loc.clone());
                    }
                },
                OwnedRefCell => {
                    self.mark_as_refcell(loc.clone());
                    self.mark_as_owned(loc.clone());
                },
                Owned => {
                    self.mark_as_owned(loc.clone());
                },
                RefCell => {
                    self.mark_as_refcell(loc.clone());
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
                    LV(loc) => LV(loc.rename_types(&mut resolve_type_name)),
                    s => s,
                };

                C(Ctor(
                    resolved_name,
                    co.into_iter().map(&mut resolve_simple_term).collect(),
                    contra.into_iter().map(&mut resolve_simple_term).collect(),
                ))
            },
            S(LV(loc)) => S(LV(loc.rename_types(&mut resolve_type_name))),
            S(_) => t,
        };
        self.typedefs_are_resolved = true;

        for Constraint(source, sink) in mem::take(&mut self.postponed_constraints) {
            self.add_flow(resolve_term(source), resolve_term(sink));
        }

        self.arg_or_init
            .values_mut()
            .for_each(|f| f.rename_types(&mut resolve_type_name));

        for (poison, loc) in mem::take(&mut self.postponed_taints) {
            self.add_poison(poison, loc.rename_types(&mut resolve_type_name));
        }
        // put back self.typedefs
        self.typedefs = typedefs;

        self.constraints.solve()?;

        profile("set constraint solving", || self.set_constraints.solve())?;

        if POISON_SIGS_OF_FN_PTRS.load(Ordering::Relaxed) {
            for (params, ret) in self
                .dummy_lambdas
                .values()
                .map(Clone::clone)
                .collect::<Vec<(Vec<Loc<Name>>, Loc<Name>)>>()
            {
                for p in params {
                    self.add_poison(PoisonKind::FnPtrSink, p);
                }
                self.add_poison(PoisonKind::FnPtrSource, ret);
            }
        }

        profile("computing poison sets via equality-based analysis", || {
            let eq_classes = self.constraints.compute_eq_classes();
            for (poison, locs) in self.poisons.iter_mut() {
                // skip misc poisons, they are propagated via subset-based analysis
                if matches!(
                    poison,
                    PoisonKind::PromotedSink
                        | PoisonKind::PromotedSource
                        | PoisonKind::InlineAsmSink
                        | PoisonKind::InlineAsmSource
                ) {
                    continue;
                }

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

            self.dirty = false;
            self.eq_classes = Some(eq_classes);

            // Poison the points-to set of all extern pointers as well, we
            // don't need to build the whole poison set because we already
            // use the equality constraints inside `Self::points_to()`.
            //
            // Do this with fewest number of dummy variables because the
            // flows added by `add_flow` are also seen by the set
            // constraint solver.
            //
            // This function propagates the poison using equality-based analysis.
            // It also adds the complementary poison to all associated nodes as well.
            let mut propagate_poison_structurally = |poison: PoisonKind, complement: PoisonKind| {
                let solver = &mut self.constraints;
                let mut collect_roots = |set: &HashSet<Loc<Name>>| {
                    set.iter()
                        .map(|l| {
                            let num = solver.to_num(l);
                            (solver.find_mut(num), l.clone())
                        })
                        .collect::<HashMap<u32, Loc<Name>>>()
                };
                let roots = collect_roots(&self.poisons[&poison]);
                log::info!("# of roots for {:?}: {}", poison, roots.len());
                roots.values().for_each(|node| {
                    let dummy_for_ptsto = Loc::fresh();
                    self.add_flow(
                        node.clone().to_term(),
                        mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                    );
                    if poison != complement {
                        self.add_poison(complement, dummy_for_ptsto.clone());
                    }
                    self.add_poison(poison, dummy_for_ptsto);
                });
                let lambda_args = roots
                    .keys()
                    .flat_map(|root| self.constraints.ctor_map(*root))
                    .flatten()
                    .filter(|(name, _)| name.starts_with("λ"))
                    .flat_map(|(_, Ctor(_, co_args, contra_args))| {
                        let get_root_vars = |v: &Vec<SimpleTerm<u32>>| {
                            v.iter()
                                .flat_map(|st| st.maybe_lv())
                                .map(|x| self.constraints.to_var(x).unwrap().clone())
                                .collect::<Vec<Loc<Name>>>()
                        };
                        let mut arg_roots = get_root_vars(co_args);
                        arg_roots.extend(get_root_vars(contra_args));
                        arg_roots
                    })
                    .collect::<HashSet<Loc<Name>>>();

                for loc in lambda_args {
                    // TODO: if needed make this poison directional by
                    // remembering variance of each location and source/sink
                    // info
                    if poison != complement {
                        self.add_poison(complement, loc.clone());
                    }
                    self.add_poison(poison, loc);
                }

                for repr_lv in roots.values() {
                    let (param_locs, ret_loc) = self.project_lambdas_unsafe(repr_lv, None);
                    for param in param_locs.into_iter().map(|v| v.into_iter()).flatten() {
                        self.add_poison(complement, param);
                    }
                    for r in ret_loc {
                        self.add_poison(poison, r);
                    }
                }
            };

            use PoisonKind::*;
            propagate_poison_structurally(ExternCallParam, ExternCallReturn);
            propagate_poison_structurally(ExternCallReturn, ExternCallParam);
            propagate_poison_structurally(TransmuteSink, TransmuteSink);
            propagate_poison_structurally(TransmuteSource, TransmuteSource);
        });

        profile(
            "propagating inline assembly poisons via subset-based analysis",
            || {
                // propagate poisons through SCCs to keep the
                // graph traversal small.
                let mut worklist = {
                    let set_c = &mut self.set_constraints;
                    self.poisons[&PoisonKind::InlineAsmSource]
                        .iter()
                        .map(|l| set_c.to_num(l))
                        .collect::<Vec<u32>>()
                };
                let mut sccs = HashSet::default();
                // TODO: mutating the worklist is a hack because there is a
                // propagation bug in the set constraint solver.
                while let Some(next) = worklist.pop() {
                    // skip the item if it (and its subsets) have been already inserted
                    if !sccs.contains(&next) {
                        for s in self.set_constraints.supersets(next) {
                            worklist.push(*s);
                        }
                        sccs.insert(next);
                    }
                }
                sccs.iter().for_each(|scc| {
                    self.poisons
                        .get_mut(&PoisonKind::InlineAsmSource)
                        .unwrap()
                        .extend(self.set_constraints.num_to_var()[*scc as usize].clone())
                });
            },
        );

        log::info!("propagating inline assembly poisons via subset-based analysis done");

        profile(
            "propagating compiler error-derived poisons via subset-based analysis",
            || {
                // propagate poisons through SCCs to keep the
                // graph traversal small.
                let mut worklist = {
                    let set_c = &mut self.set_constraints;
                    self.poisons[&PoisonKind::PromotedSource]
                        .iter()
                        .map(|l| set_c.to_num(l))
                        .collect::<Vec<u32>>()
                };
                let mut sccs = HashSet::default();
                // TODO: mutating the worklist is a hack because there is a
                // propagation bug in the set constraint solver.
                while let Some(next) = worklist.pop() {
                    // skip the item if it (and its subsets) have been already inserted
                    if !sccs.contains(&next) {
                        for s in self.set_constraints.supersets(next) {
                            worklist.push(*s);
                        }
                        sccs.insert(next);
                    }
                }
                sccs.iter().for_each(|scc| {
                    self.poisons
                        .get_mut(&PoisonKind::PromotedSource)
                        .unwrap()
                        .extend(self.set_constraints.num_to_var()[*scc as usize].clone())
                });
            },
        );
        log::info!("propagating compiler error-derived poisons via subset-based analysis done");

        // Note: we don't propagate MiscSink because we inject casts at poison boundaries.

        profile("set constraint solving", || self.set_constraints.solve())?;

        let subsets = profile("computing subsets for ownership/poison propagation", || {
            self.set_constraints.compute_subsets()
        });
        log::info!("set constraint solving done");

        profile("propagating ownership", || {
            // propagate ownership information. we use SCCs to keep the
            // graph traversal small, although we add all relevant
            // variables to `self.owned` in the end.
            let worklist = {
                let set_c = &self.set_constraints;
                let owned = &self.owned;
                owned
                    .iter()
                    .flat_map(|l| set_c.to_maybe_num(l))
                    .collect::<HashSet<u32>>()
            };
            let mut owned_sccs = HashSet::default();
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
        log::info!("propagating ownership done");

        profile("propagating refcell promotion", || {
            // propagate RefCell promotion information.  similar to above code.
            let eq_refcell_clone_for_hack = self.refcell.clone();

            let worklist = {
                let set_c = &self.set_constraints;
                let refcell = &self.refcell;
                refcell
                    .iter()
                    .flat_map(|l| set_c.to_maybe_num(l))
                    .collect::<HashSet<_>>()
            };
            let mut refcell_sccs = HashSet::default();
            for next in worklist {
                if !refcell_sccs.contains(&next) {
                    for subset in &subsets[next as usize] {
                        refcell_sccs.insert(*subset);
                    }
                }
            }
            refcell_sccs.iter().for_each(|scc| {
                self.refcell
                    .extend(self.set_constraints.num_to_var()[*scc as usize].clone())
            });

            // promote refcell through equality analysis as a hack, we should get rid of this later
            let refcell_roots = eq_refcell_clone_for_hack
                .iter()
                .map(|loc| {
                    let n = self.constraints.to_num(loc);
                    self.constraints.find_mut(n)
                })
                .collect::<HashSet<u32>>();
            let mut eq_classes = self.constraints.compute_eq_classes();
            refcell_roots.into_iter().for_each(|root| {
                // we visit each root only once so we can move its eq class to self.refcell
                self.refcell.extend(eq_classes.remove(&root).unwrap());
            });
        });
        log::info!("propagating refcell promotion done");

        self.dirty = false;
        self.eq_classes = Some(self.constraints.compute_eq_classes());

        Ok(())
    }

    /// Project out the lambda constructors associated with this location in the
    /// equality-based graph without checking the dirty bit, this is not always safe.
    pub fn project_lambdas_unsafe(
        &mut self,
        loc: &Loc<Name>,
        // A known arity if this function is not variadic
        arity: Option<usize>,
    ) -> (Vec<HashSet<Loc<Name>>>, HashSet<Loc<Name>>) {
        let dirty = std::mem::replace(&mut self.dirty, false);
        let result = self.project_lambdas(loc, arity);
        self.dirty = dirty;
        return result;
    }

    /// Project out the lambda constructors associated with this location in the equality-based graph.
    pub fn project_lambdas(
        &self,
        loc: &Loc<Name>,
        // A known arity if this function is not variadic
        arity: Option<usize>,
    ) -> (Vec<HashSet<Loc<Name>>>, HashSet<Loc<Name>>) {
        let mut params: Vec<HashSet<Loc<Name>>> = Vec::new();
        let mut ret = HashSet::default();
        if let Some(ctor_map) = self
            .constraints
            .to_maybe_num(loc)
            .and_then(|n| self.constraints.ctor_map(n))
        {
            // find the function definitions
            for Ctor(_, co_args, contra_args) in ctor_map.get(&*FNDEF) {
                assert_eq!(co_args.len(), 1);
                assert!(contra_args.is_empty());
                match &co_args[0] {
                    LV(f_var) => {
                        // get the nullary constructors corresponding to function names
                        for f in self
                            .constraints
                            .ctor_map(*f_var)
                            .iter()
                            .map(|m| m.values())
                            .flatten()
                            .filter(|c| c.1.is_empty() && c.2.is_empty())
                            .map(|c| &c.0)
                        {
                            let mut insert_this_fn = |arity| {
                                if arity > params.len() {
                                    params.resize_with(arity, Default::default);
                                }
                                for i in 0..arity {
                                    params[i].insert(Loc::Param(f.clone(), i));
                                }

                                ret.insert(Loc::RetVal(f.clone()));
                            };
                            if let Some(n) = arity.or_else(|| {
                                self.fn_sigs
                                    .get(f)
                                    .and_then(|s| s.known_arity())
                                    .or_else(|| self.fn_arity.get(f).cloned())
                            }) {
                                insert_this_fn(n);
                            } else {
                                log::error!(
                                    "{} has no arity and it is not called anywhere. Not generating any parameter locations to project it.",
                                    f
                                );
                            }
                        }
                        // get the dummy lambdas
                        // TODO(maemre): do some caching when doing this!!
                        assert!(!self.dirty);
                        for marker in
                            &self.eq_classes.as_ref().unwrap()[&self.constraints.find(*f_var)]
                        {
                            if let Some((def_params, def_ret)) = self.dummy_lambdas.get(marker) {
                                if def_params.len() > params.len() {
                                    params.resize_with(def_params.len(), Default::default);
                                }
                                for (i, p) in def_params.iter().enumerate() {
                                    params[i].insert(p.clone());
                                }
                                ret.insert(def_ret.clone());
                            }
                        }
                    },
                    _ => unreachable!(),
                }
            }
        }
        (params, ret)
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

    pub fn is_any_owned<'a, I: IntoIterator<Item = &'a Loc<Name>>>(&self, locs: I) -> bool {
        locs.into_iter().any(|loc| self.owned.contains(loc))
    }

    pub fn is_loc_owned(&self, loc: &Loc<Name>) -> bool {
        self.owned.contains(loc)
    }

    pub fn is_refcell(&self, hir_id: HirId) -> bool {
        if let Some(S(LV(loc))) = self.expr_to_term.get(&hir_id) {
            self.refcell.contains(loc)
        } else {
            false
        }
    }

    pub fn is_loc_refcell(&self, loc: &Loc<Name>) -> bool {
        self.refcell.contains(loc)
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

    pub fn aggregate_poisons<'a, 'b, T: IntoIterator<Item = &'a Loc<Name>>>(
        &'b self,
        iter: T,
    ) -> HashSet<PoisonKind> {
        let mut poisons = HashSet::default();
        for loc in iter {
            let (src, snk) = self.poisons(loc);
            poisons.extend(src);
            poisons.extend(snk);
        }
        poisons
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

    pub fn expr_poisons(&self, hir_id: HirId) -> (HashSet<PoisonKind>, HashSet<PoisonKind>) {
        self.expr_to_term
            .get(&hir_id)
            .and_then(|t| t.get_lv())
            .map(|loc| {
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
            })
            .unwrap_or_default()
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

    /// Create dummy locations/free variables to match the structure
    /// of the given type so that the rest of the analysis can find
    /// relevant constructors (like lambdas) without type information.
    pub fn create_dummy_locs(&mut self, source_or_sink: Loc<Name>, ty: &Type, is_covariant: bool) {
        use Type::*;
        match ty {
            // basic types
            Never | Opaque | Unknown(..) | Bool | Char | Int(..) | Uint(..) | Float(..)
            | Struct(..) | Enum(..) | Union(..) | Extern(..) | Str => {},
            OptionT(box ty) => self.create_dummy_locs(source_or_sink, ty, is_covariant),
            // pointer types
            Array(box inner, _)
            | Slice(box inner)
            | Ptr(_, box inner)
            | Ref(_, _, box inner)
            | Boxed(box inner) => {
                let dummy_for_ptsto = Loc::fresh();
                if is_covariant {
                    self.add_flow(
                        source_or_sink.clone().to_term(),
                        mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                    );
                } else {
                    self.add_flow(
                        mk_ref(LV(dummy_for_ptsto.clone()), LV(dummy_for_ptsto.clone())),
                        source_or_sink.clone().to_term(),
                    );
                }
                self.create_dummy_locs(dummy_for_ptsto, inner, is_covariant);
            },
            Fn(sig) => {
                // TODO(maemre): varargs check and extra lambdas
                let mut param_terms = vec![];
                let ret_loc = Loc::fresh();
                for param_ty in &sig.param_types {
                    let param_loc = Loc::fresh();
                    self.create_dummy_locs(param_loc.clone(), param_ty, !is_covariant);
                    param_terms.push(LV(param_loc));
                }
                self.create_dummy_locs(ret_loc.clone(), &sig.ret_type, is_covariant);
                // record the location->parameter map
                let marker_loc = Loc::fresh();
                self.dummy_lambdas.insert(
                    marker_loc.clone(),
                    (
                        param_terms
                            .iter()
                            .map(|s| s.unwrap_lv().clone())
                            .collect::<Vec<Loc<Name>>>(),
                        ret_loc.clone(),
                    ),
                );
                self.add_flow(
                    C(Ctor(FNDEF.clone(), vec![LV(marker_loc.clone())], vec![])),
                    source_or_sink.clone().to_term(),
                );

                let lambda = mk_lambda(param_terms, LV(ret_loc));
                if is_covariant {
                    self.add_flow(lambda, source_or_sink.to_term());
                } else {
                    self.add_flow(source_or_sink.to_term(), lambda);
                }
            },
            // the unit type
            Tuple(inner) if inner.is_empty() => {},
            Tuple(_) => {
                todo!("explicit tuples are not implemented yet: {:?}", ty);
            },
            CustomSlice(..) | RefCell(..) => {
                unreachable!("unexpected smart pointer in the source program.")
            },
            Syntactic(_) => unreachable!("unexpected syntactic type"),
            App(_, _) => unreachable!("unexpected parametrized type in the source program."),
        }
    }

    /// Propagate poison info from functions passed to unions or extern APIs to
    /// their arguments (i.e., propagate the poisons that affect types that
    /// occur in types of poisoned values), ideally we should run this until we
    /// reach a fixpoint in case of having higher-order functions passed to
    /// extern APIs.
    pub fn propagate_occurrence_poisons_through_lambdas(&mut self) {
        for poison in [
            PoisonKind::UnionFieldSink,
            PoisonKind::UnionFieldSource,
            PoisonKind::ExternCallParam,
            PoisonKind::ExternCallReturn,
        ]
        .iter()
        {
            let poisons = &self.poisons;
            let eq_solver = &mut self.constraints;
            let lambda_args_to_poison = poisons[&poison]
                .iter()
                .map(|l| {
                    // find the root of each location and collapse into a set
                    let loc_num = eq_solver.to_maybe_num(l).unwrap();
                    eq_solver.find_mut(loc_num)
                })
                .collect::<HashSet<u32>>()
                .into_iter()
                .flat_map(|root| {
                    // get all the λ constructor parameters/return values
                    eq_solver
                        .ctor_map(root)
                        .iter()
                        .flat_map(|ctor_map| {
                            ctor_map
                                .iter()
                                .filter(|(name, _)| name.starts_with("λ"))
                                .flat_map(|(_, ctor)| {
                                    // the first ctor argument is the return
                                    // value, the rest is function parameters
                                    let ret = ctor.1[0].clone().maybe_lv();
                                    let args =
                                        ctor.2[1..].iter().flat_map(|s| s.clone().maybe_lv());
                                    ret.into_iter().chain(args).collect::<Vec<u32>>()
                                })
                        })
                        .collect::<HashSet<u32>>()
                })
                .into_iter()
                .map(|n| eq_solver.to_var(n).unwrap().clone())
                .collect::<Vec<Loc<Name>>>();

            for arg in lambda_args_to_poison {
                self.add_poison(*poison, arg);
            }
        }
    }

    /// Structurally traverses given type while projecting the associated
    /// location, and collects all locations corresponding to a return type
    /// inside `ty`.
    pub fn collect_return_locs(
        &self,
        locs: HashSet<&Loc<Name>>,
        ty: &Type,
        out: &mut HashSet<Loc<Name>>,
    ) {
        use types::Type::*;
        match ty {
            OptionT(box inner) => self.collect_return_locs(locs, inner, out),
            Array(box inner, _) | Ref(_, _, box inner) | Ptr(_, box inner) => {
                self.collect_return_locs(locs, inner, out)
            },
            Fn(sig) => {
                for loc in locs {
                    let (p, r) = self.project_lambdas(loc, sig.known_arity());

                    out.extend(r.iter().map(Loc::clone));
                    for (i, param_ty) in sig.param_types.iter().enumerate() {
                        self.collect_return_locs(
                            p.get(i).into_iter().flatten().collect(),
                            param_ty,
                            out,
                        );
                    }
                    self.collect_return_locs(r.iter().collect(), &*sig.ret_type, out);
                }
            },
            Tuple(inner) if inner.is_empty() => {},
            Struct(..) | Enum(..) | Union(..) => {},
            ty if ty.is_primitive() => {},
            _ => unimplemented!("{} {}", ty.ctor_string(), ty),
        }
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
    /// Functions that are used as function pointers, mapped to their signatures
    pub used_as_fn_pointer: HashMap<Name, types::FnSig>,
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
            used_as_fn_pointer: HashMap::default(),
        }
    }

    /// Add this function declaration to relevant maps
    pub fn add_fn_decl(&mut self, fn_name: Name) {
        self.unsafe_behavior.insert(fn_name, BTreeSet::new());
    }

    pub fn add_unsafe_behavior(&mut self, fn_name: &Name, ub: UnsafeBehavior) {
        // also increment the counter
        *self.ub_count.entry(ub).or_insert(0) += 1;

        if !self.unsafe_behavior.contains_key(fn_name) {
            self.unsafe_behavior
                .insert(fn_name.clone(), BTreeSet::new());
        }

        self.unsafe_behavior.get_mut(fn_name).unwrap().insert(ub);
    }

    pub fn unsafe_behavior(&self) -> &HashMap<Name, BTreeSet<UnsafeBehavior>> {
        &self.unsafe_behavior
    }

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
    pub fn add_call(&mut self, caller: Name, callee: Name, is_special: bool, unsafety: Unsafety) {
        // TODO: take a reference and avoid copying unless necessary

        let mut insert_call_now = true;

        if callee == *TRANSMUTE_FN {
            self.add_unsafe_behavior(&caller, UnsafeBehavior::UnsafeCast);
        } else if is_special
            && (callee.ends_with("::malloc")
                || callee.ends_with("::calloc")
                || callee.ends_with("::free"))
        {
            self.add_unsafe_behavior(&caller, UnsafeBehavior::Alloc);
        } else if (is_special || callee.as_ref().starts_with("core::"))
            && unsafety == Unsafety::Unsafe
        {
            // This is a special function that is unsafe
            self.add_unsafe_behavior(&caller, UnsafeBehavior::UnsafeStdCall);
        } else if !is_special && !self.defined_fns.contains_key(&callee) {
            // The callee is not a defined function, add this as a potentially extern call
            self.unresolved_calls.push((caller.clone(), callee.clone()));
            self.dirty = true;
            insert_call_now = false;
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
            call_graph.add_call(f, g, false, Unsafety::Normal);
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
    /// Whether we are inside a global variable's initialization code.
    pub in_global: bool,
    pub in_bitfield_helper: bool,
}

impl<'a, 'tcx> AnalysisCtx<'a, 'tcx> {
    fn new(fn_name: Name, ctx: &'a LateContext<'tcx>, in_global: bool) -> AnalysisCtx<'a, 'tcx> {
        let in_bitfield_helper = fn_name.contains("::bitfields::")
            || fn_name.ends_with("xmlschemastypes::get_bits")
            || fn_name.ends_with("xmlschemastypes::set_bits");
        AnalysisCtx {
            locals: HashMap::default(),
            fn_name,
            ctx,
            in_global,
            in_bitfield_helper,
        }
    }

    fn tcx(&self) -> &'a TyCtxt<'tcx> {
        &self.ctx.tcx
    }
}

#[derive(PartialEq, Eq, Debug)]
enum MallocKind {
    Malloc,
    Calloc,
}

impl MallocKind {
    fn from_fn_name(f: &Name) -> MallocKind {
        if f.ends_with("::malloc") {
            MallocKind::Malloc
        } else if f.ends_with("::calloc") {
            MallocKind::Calloc
        } else {
            unreachable!("Invalid allocation function: {}", f)
        }
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

    // TODO: hack
    /// Locations associated with AddrOf expressions
    addr_of_locs: HashMap<Loc<Name>, BTreeSet<Span>>,
    /// Locations of expressions of the form `&_ *e` mapped to
    /// locations of e. That is, the expressions of the form AddrOf(_,
    /// Deref(e)). Used for carrying poison data across when arrays
    /// are re-borrowed through Deref followed by AddrOf. The key is
    /// the location of AddrOf(_, Deref(e)), and the value is the
    /// location of e.
    reborrow_map: HashMap<Loc<Name>, Term<Loc<Name>>>,
    /// Locations of the malloc/calloc calls we can rewrite
    malloc_calls: HashMap<Loc<Name>, MallocKind>,
}

impl PtrProvenancePass {
    pub fn new() -> Box<LatePass> {
        Box::new(PtrProvenancePass {
            taint_analysis: PtrProvenanceAnalysis::new(),
            call_graph: CallGraph::new(),
            extern_arity: HashMap::default(),
            addr_of_locs: HashMap::default(),
            reborrow_map: HashMap::default(),
            malloc_calls: HashMap::default(),
        })
    }

    /// Returns data flow if this is an intrinsics that we inline during this analysis
    fn intrinsics_data_flow(fn_name: &Name) -> Option<&Vec<DataFlow>> {
        COMPILER_INTRINSICS
            .get(fn_name)
            .or_else(|| {
                let mut split = fn_name.splitn(2, "::");
                let _crate = split.next();
                let name = split.next();
                name.and_then(|n| INJECTED_INTRINSICS.get(&Name::from(n)))
            })
            .or_else(|| {
                LAERTES_HELPERS.iter().find_map(|(helper, flow)| {
                    if fn_name.ends_with(helper) {
                        Some(flow)
                    } else {
                        None
                    }
                })
            })
            .or_else(|| {
                if (fn_name.contains("laertes") && !fn_name.contains("laertes_xt"))
                    || ["core::", "std::", "alloc::"]
                        .iter()
                        .any(|p| fn_name.starts_with(p))
                {
                    log::warn!("potentially missing intrinsic: {}", fn_name);
                }

                None
            })
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
        block.expr.and_then(|e| {
            // propagate immediate flows before analyzing the body
            if let Some(f) = self.taint_analysis.arg_or_init.get(&block.hir_id).cloned() {
                self.taint_analysis.arg_or_init.insert(e.hir_id, f);
            }
            self.analyze_expr(&local_ctx, e, ExprCtx::default())
        })
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
        mut expr_ctx: ExprCtx,
    ) -> Option<Term<Loc<Name>>> {
        let expr_loc = Loc::Synthetic(expr.hir_id);
        let expr_term = expr_loc.clone().to_term();
        if !matches!(expr.kind, ExprKind::Cast(..) | ExprKind::Call(..)) {
            expr_ctx.rewritable_malloc = false;
        }
        let result = match &expr.kind {
            ExprKind::Box(_) => panic!("boxes are not supported"),
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
                    if let Some(f) = self.taint_analysis.arg_or_init.get(&expr.hir_id).cloned() {
                        self.taint_analysis
                            .arg_or_init
                            .insert(e.hir_id, FlowLoc::PointsTo(Box::new(f)));
                    }
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
                let callee_term = self.analyze_expr(
                    ctx,
                    fun,
                    ExprCtx {
                        is_assignee: false,
                        is_callee: true,
                        in_free: false,
                        rewritable_malloc: false,
                    },
                );
                let callee_name = match &callee_term {
                    Some(S(LV(Loc::Var(fn_name)))) => Some(fn_name.clone()),
                    _ => {
                        self.call_graph
                            .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::ExternCall);
                        None
                    },
                };

                if let Some(data_flows) = callee_name
                    .as_ref()
                    .and_then(|c| Self::intrinsics_data_flow(c))
                {
                    let callee_name = callee_name.as_ref().unwrap();
                    // this is a compiler intrinsic, create a
                    // synthetic node for this call, then create
                    // constraints for the data flow edges for
                    // this call

                    let arg_ctx = ExprCtx::with_in_free(callee_name.ends_with("::free"));

                    // analyze the arguments and collect their terms
                    let arg_locs: Vec<Option<Term<Loc<Name>>>> = args
                        .iter()
                        .map(|arg| self.analyze_expr(ctx, arg, arg_ctx))
                        .collect();

                    log::info!(
                        "intrinsic fn: {} with data flow {:?} at {:?}",
                        callee_name,
                        data_flows,
                        expr.span
                    );

                    for (source, target) in data_flows {
                        let mut get_term = |node: &DataFlowNode| match node {
                            DataFlowNode::RetVal => Some(expr_term.clone()),
                            DataFlowNode::Param(i) => arg_locs[*i].clone(),
                            DataFlowNode::PtsTo(box DataFlowNode::RetVal) => {
                                let pointer = &expr_term;
                                let dummy_for_ptsto = Loc::fresh();
                                self.taint_analysis.add_flow(
                                    pointer.clone(),
                                    mk_ref(
                                        LV(dummy_for_ptsto.clone()),
                                        LV(dummy_for_ptsto.clone()),
                                    ),
                                );
                                Some(dummy_for_ptsto.to_term())
                            },
                            DataFlowNode::PtsTo(box DataFlowNode::Param(i)) => {
                                let dummy_for_ptsto = Loc::fresh();
                                if let Some(pointer) = arg_locs[*i].as_ref() {
                                    self.taint_analysis.add_flow(
                                        pointer.clone(),
                                        mk_ref(
                                            LV(dummy_for_ptsto.clone()),
                                            LV(dummy_for_ptsto.clone()),
                                        ),
                                    );
                                }
                                Some(dummy_for_ptsto.to_term())
                            },
                            DataFlowNode::PtsTo(_) => unimplemented!(
                                "nested points-to nodes in data flow intrinsics are not implemented"
                            ),
                        };

                        if let (Some(source_term), Some(target_term)) =
                            (get_term(source), get_term(target))
                        {
                            // There are terms for both ends of
                            // this edge, add the corresponding
                            // constraint
                            self.taint_analysis.add_flow(source_term, target_term);
                        }
                    }

                    let is_transmute = *callee_name == *TRANSMUTE_FN;

                    if is_transmute && !LIMIT_STUDY.load(Ordering::Relaxed) {
                        log::warn!("special function: {}", callee_name);
                        self.taint_analysis
                            .add_poison(PoisonKind::TransmuteSource, expr_loc.clone());
                        let ret_type =
                            Type::from_ty(ctx.ctx, ctx.ctx.typeck_results().expr_ty_adjusted(expr));
                        self.taint_analysis
                            .create_dummy_locs(expr_loc.clone(), &ret_type, true);
                        if let Some(arg_loc) = arg_locs[0].clone().unwrap().into_lv() {
                            self.taint_analysis
                                .add_poison(PoisonKind::TransmuteSink, arg_loc);
                        }
                        // TODO(maemre): remove this and handle dereferences of
                        // transmute's outputs normally. Specifically, the
                        // interaction with pointer arithmetic.
                    }

                    Some(expr_term)
                } else {
                    // Remember the HIR IDs of the arguments
                    for (i, a) in args.iter().enumerate() {
                        self.taint_analysis.arg_or_init.insert(
                            a.hir_id,
                            FlowLoc::Param(
                                callee_term
                                    .as_ref()
                                    .and_then(|t| t.get_lv().cloned())
                                    .unwrap(),
                                // We support only arity for non-varargs functions
                                Some(args.len()),
                                i,
                            ),
                        );
                    }

                    let args = args
                        .iter()
                        .map(|arg| {
                            match self.analyze_expr(ctx, arg, ExprCtx::default()) {
                                Some(S(st)) => st,
                                Some(ctor) => {
                                    // create a dummy variable for this ctor's flow
                                    let dummy = Loc::fresh();
                                    self.taint_analysis.add_flow(ctor, dummy.clone().to_term());
                                    dummy.to_st()
                                },
                                None => EmptySet,
                            }
                        })
                        .collect::<Vec<SimpleTerm<Loc<Name>>>>();

                    if callee_name.is_some()
                        && VOLATILE_FNS.contains(callee_name.as_ref().unwrap())
                        && args[0].is_lv()
                    {
                        // the function requires a raw pointer as its first
                        // argument, this is used only for translations of
                        // 'volatile'
                        self.taint_analysis
                            .add_poison(PoisonKind::VolatileSink, args[0].unwrap_lv().clone());
                    }

                    // is this a special function we can handle?
                    let (is_special, is_malloc) =
                        callee_name.as_ref().map_or((false, false), |c| {
                            (
                                qual_fn_we_can_handle(&*c),
                                c.ends_with("::malloc") || c.ends_with("::calloc"),
                            )
                        });

                    let ret = if let Some(c) = callee_name.clone() {
                        if is_malloc {
                            // Create a tagged set variable for each call site
                            // of malloc if we can rewrite that call.
                            if expr_ctx.rewritable_malloc {
                                // Record this allocation site so that we can
                                // check if it is poisoned after solving the
                                // constraint system.
                                let l = Loc::Malloc(expr.hir_id);
                                self.malloc_calls
                                    .insert(l.clone(), MallocKind::from_fn_name(&c));
                                l
                            } else {
                                Loc::RetVal(c)
                            }
                        } else if is_special {
                            // do not let the special function return
                            // values flow into sinks, and return a unique
                            // variable for the call site instead
                            expr_loc
                        } else {
                            Loc::RetVal(c)
                        }
                    } else {
                        expr_loc
                    };

                    // Add call to the call graph, we don't resolve
                    // unknown functions or variables (e.g. closures) so
                    // the call graph is going to be unsound
                    callee_name.clone().map(|c| {
                        let unsafety = ctx
                            .ctx
                            .typeck_results()
                            .expr_ty_adjusted(fun)
                            .peel_refs()
                            .fn_sig(ctx.ctx.tcx)
                            .unsafety();

                        self.call_graph
                            .add_call(ctx.fn_name.clone(), c, is_special, unsafety);
                    });

                    if let Some(callee) = callee_name.clone() {
                        if !is_special
                            && is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                            && !LIMIT_STUDY.load(Ordering::Relaxed)
                        {
                            self.taint_analysis
                                .add_poison(PoisonKind::VoidSource, Loc::RetVal(callee));
                        }
                    }

                    if is_malloc {
                        // Mark this expression as owned, since it corresponds
                        // to an allocation
                        self.taint_analysis.mark_as_owned(ret.clone());
                    } else {
                        // connect callee ⊆ λ(ret; args)
                        //
                        // callee is on the lower because all assignments to fn
                        // pointers will flow into the fn pointer, which will
                        // flow into the call. the return values will flow into
                        // the return value of the call, and the arguments will
                        // flow into parameters of all callees because λ is
                        // contravariant over the parameters
                        if let Some(callee) = callee_term {
                            let call_lambda = mk_lambda(args, ret.clone().to_st());
                            self.taint_analysis.add_flow(callee, call_lambda);
                        }
                    }
                    Some(ret.to_term())
                }
            },
            ExprKind::MethodCall(_fun_with_generics, _, args, _) => {
                if let Some(callee_def_id) =
                    ctx.ctx.typeck_results().type_dependent_def_id(expr.hir_id)
                {
                    let callee_name = Name::from(get_def_qname(ctx.ctx, callee_def_id));

                    // Build the call graph
                    //
                    // TODO: we don't resolve trait methods, the
                    // initial C program is supposed to not generate
                    // them, we may need that when we introduce other
                    // approaches that generate trait-based calls.
                    self.call_graph.add_call(
                        ctx.fn_name.clone(),
                        callee_name.clone(),
                        qual_fn_we_can_handle(&callee_name),
                        ctx.ctx.tcx.fn_sig(callee_def_id).unsafety(),
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

                        log::info!(
                            "intrinsic method: {} with data flow {:?} at {:?}",
                            callee_name,
                            data_flows,
                            expr.span
                        );
                        log::info!("arg locs: {:?}", arg_locs);
                        log::info!("ret val: {:?}", expr_loc);

                        for (source, target) in data_flows {
                            let mut get_term = |node: &DataFlowNode| match node {
                                DataFlowNode::RetVal => Some(expr_term.clone()),
                                DataFlowNode::Param(i) => arg_locs[*i].clone(),
                                DataFlowNode::PtsTo(box DataFlowNode::RetVal) => {
                                    let pointer = &expr_term;
                                    let dummy_for_ptsto = Loc::fresh();
                                    self.taint_analysis.add_flow(
                                        pointer.clone(),
                                        mk_ref(
                                            LV(dummy_for_ptsto.clone()),
                                            LV(dummy_for_ptsto.clone()),
                                        ),
                                    );
                                    Some(dummy_for_ptsto.to_term())
                                },
                                DataFlowNode::PtsTo(box DataFlowNode::Param(i)) => {
                                    let dummy_for_ptsto = Loc::fresh();
                                    if let Some(pointer) = arg_locs[*i].as_ref() {
                                        self.taint_analysis.add_flow(
                                            pointer.clone(),
                                            mk_ref(
                                                LV(dummy_for_ptsto.clone()),
                                                LV(dummy_for_ptsto.clone()),
                                            ),
                                        );
                                    }
                                    Some(dummy_for_ptsto.to_term())
                                },
                                DataFlowNode::PtsTo(_) => unimplemented!(
                                    "nested points-to nodes in data flow intrinsics are not implemented"
                                ),
                            };

                            if let (Some(source_term), Some(target_term)) =
                                (get_term(source), get_term(target))
                            {
                                // There are terms for both ends of
                                // this edge, add the corresponding
                                // constraint
                                self.taint_analysis.add_flow(source_term, target_term);
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

                                log::info!(
                                    "tainted {:?} with ptr arith at {:?}",
                                    arg_loc,
                                    expr.span
                                );
                                self.taint_analysis
                                    .add_poison(PoisonKind::PtrArithSink, arg_loc)
                            });

                            if callee_name.ends_with("::offset") {
                                // Mark flowing to arguments through pointer
                                // arithmetic as well, to resolve move flows
                                // correctly.
                                if let Some(v) =
                                    self.taint_analysis.arg_or_init.get(&expr.hir_id).cloned()
                                {
                                    self.taint_analysis.arg_or_init.insert(args[0].hir_id, v);
                                }
                            }
                        } else if callee_name.starts_with("core::ptr")
                            && !callee_name.ends_with("::is_null")
                        {
                            log::error!(
                                "potential arith method: {} called at {:?}",
                                callee_name,
                                expr.span
                            );
                        }

                        expr_loc
                    } else {
                        // this is not an intrinsic function
                        for (i, arg) in args.iter().enumerate() {
                            // arg_i ⊆ param_i
                            if let Some(arg_term) = self.analyze_expr(ctx, arg, ExprCtx::default())
                            {
                                // remember the HIR ID of the argument
                                self.taint_analysis.arg_or_init.insert(
                                    arg.hir_id,
                                    FlowLoc::Plain(arg_term.get_lv().cloned().unwrap()),
                                );
                                self.taint_analysis
                                    .add_flow(arg_term, S(LV(Loc::Param(callee_name.clone(), i))));
                            }
                        }

                        if is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                            && !LIMIT_STUDY.load(Ordering::Relaxed)
                        {
                            self.taint_analysis.add_poison(
                                PoisonKind::VoidSource,
                                Loc::RetVal(callee_name.clone()).clone(),
                            );
                        }

                        Loc::RetVal(callee_name)
                    };

                    Some(loc.to_term())
                } else {
                    panic!("Cannot get the Def ID for method call node {:?}", expr)
                }
            },
            ExprKind::Tup(elems) if elems.is_empty() => Some(expr_term),
            ExprKind::Tup(elems) if elems.len() == 1 => {
                self.analyze_expr(ctx, &elems[0], ExprCtx::default())
            },
            ExprKind::Tup(elems) if elems.len() == 2 => {
                self.analyze_expr(ctx, &elems[0], ExprCtx::default());
                self.analyze_expr(ctx, &elems[1], ExprCtx::default())
            },
            ExprKind::Tup(_elems) => {
                todo!("explicit tuples are not implemented yet: {:?}", expr.span)
            },
            ExprKind::Binary(op, lhs, rhs) => {
                // TODO: check if ptr arithmetic (by checking operands), add
                // poison if so

                let l_loc = self.analyze_expr(ctx, lhs, ExprCtx::default());
                let r_loc = self.analyze_expr(ctx, rhs, ExprCtx::default());

                // If the two pointers are compared, then they must have the
                // same type, encode this by adding a bidirectional flow
                let comparison_in_no_arith_limit_study = NO_PTR_ARITH_REWRITE
                    .load(Ordering::Relaxed)
                    && matches!(
                        op.node,
                        BinOpKind::Lt | BinOpKind::Gt | BinOpKind::Le | BinOpKind::Ge
                    );
                if (matches!(op.node, BinOpKind::Eq | BinOpKind::Ne)
                    || comparison_in_no_arith_limit_study)
                    && ctx.ctx.typeck_results().expr_ty(lhs).is_any_ptr()
                    && ctx.ctx.typeck_results().expr_ty(rhs).is_any_ptr()
                {
                    if let (Some(l), Some(r)) = (l_loc.clone(), r_loc.clone()) {
                        self.taint_analysis.add_flow(l.clone(), r.clone());
                        self.taint_analysis.add_flow(r, l);
                    }
                }

                // Add constraints lhs ⊆ expr, rhs ⊆ expr
                if let Some(lhs_loc) = l_loc {
                    self.taint_analysis.add_flow(lhs_loc, expr_term.clone());
                }
                if let Some(rhs_loc) = r_loc {
                    self.taint_analysis.add_flow(rhs_loc, expr_term.clone());
                }

                Some(expr_term)
            },
            ExprKind::Unary(op, arg) => {
                let arg_term = self.analyze_expr(ctx, arg, expr_ctx.keep_assignee());
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
                    // arg ⊇ ref(expr; expr) if on the lhs
                    // arg ⊆ ref(expr; expr) if on the rhs
                    //
                    // TODO(maemre): reason about whether the term
                    // above should be equality or subset
                    let pointee = expr_term.clone().extract_simple();
                    let ref_term = mk_ref(pointee.clone(), pointee);
                    self.taint_analysis
                        .add_flow(ref_term.clone(), arg_term.clone().unwrap());
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
                            .add_poison(PoisonKind::StringLitSource, expr_loc.clone());
                    },
                    _ => {},
                }

                Some(expr_term)
            },
            ExprKind::Cast(sub, _ty) => {
                // We delete/transform casts. So if a value flows directly
                // through a cast to a function parameter, then we mark it here
                // make sure we don't over-apply move flows.
                if let Some(v) = self.taint_analysis.arg_or_init.get(&expr.hir_id).cloned() {
                    self.taint_analysis.arg_or_init.insert(sub.hir_id, v);
                }

                let ty = ctx.ctx.typeck_results().expr_ty(expr);
                let can_rewrite_malloc =
                    can_rewrite_allocation(None, ctx.ctx, &sub, Type::from_ty(ctx.ctx, ty));
                // type of the subexpression
                let sub_ty = ctx.ctx.typeck_results().expr_ty_adjusted(sub);
                let sub_result = self.analyze_expr(
                    ctx,
                    sub,
                    expr_ctx
                        .with_callee(false)
                        .with_rewritable_malloc(can_rewrite_malloc),
                );
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

                let disable_cast_poison = LIMIT_STUDY.load(Ordering::Relaxed) && !ctx.in_global;
                let mut add_void_poison = !expr_ctx.in_free;

                // Check if sub_ty and ty mismatch modulo mutability
                if POISON_UNRELATED_TYPE_CASTS.load(Ordering::Relaxed) && !disable_cast_poison {
                    let is_zero = |e| matches!(get_constant_value(e), Some(LitKind::Int(0, _)));
                    if (ty.is_unsafe_ptr() || sub_ty.peel_refs().is_unsafe_ptr()) && !(is_zero(sub))
                    // ignore casts from zero (they represent null ptr and get rewritten)
                    {
                        // Find the ultimate pointee types, peeling nested pointers
                        let mut pointee = ty;
                        let mut sub_pointee = sub_ty;
                        // Peel nested pointers only at one level because Rust
                        // doesn't have automatic degradation from * mut * mut T
                        // to * const * const T etc. (We do it at the top level
                        // by inserting `borrow` calls, but we cannot do this
                        // for nested pointers especially if they correspond to
                        // arrays).
                        if pointee.is_unsafe_ptr() && sub_pointee.is_unsafe_ptr() {
                            pointee = pointee.builtin_deref(true).unwrap().ty;
                            sub_pointee = sub_pointee.builtin_deref(true).unwrap().ty;
                        }

                        // If the pointees mismatch, poison this cast
                        let cast_pointee_ty = Type::from_ty(ctx.ctx, pointee);
                        let sub_pointee_ty = Type::from_ty(ctx.ctx, sub_pointee);
                        add_void_poison = !can_rewrite_malloc && add_void_poison;
                        if !can_rewrite_malloc {
                            if cast_pointee_ty != sub_pointee_ty {
                                // check if this is an argument to free()
                                if !(expr_ctx.in_free && cast_pointee_ty == *C_VOID_TYPE) {
                                    log::info!(
                                        "pointer mismatch in cast, adding poison: {:?} != {:?} at {:?} [in free: {}]",
                                        Type::from_ty(ctx.ctx, pointee),
                                        Type::from_ty(ctx.ctx, sub_pointee),
                                        expr.span,
                                        expr_ctx.in_free,
                                    );
                                    let dummy = Loc::fresh();
                                    self.taint_analysis
                                        .add_poison(PoisonKind::CastSource, cast_var.clone());
                                    self.taint_analysis.add_flow(
                                        sub_result.clone().unwrap(),
                                        dummy.clone().to_term(),
                                    );
                                    self.taint_analysis.add_poison(PoisonKind::CastSink, dummy);
                                }
                            } else if Type::from_ty(ctx.ctx, ty) != Type::from_ty(ctx.ctx, sub_ty) {
                                // The types match but mutability
                                // doesn't. This may create mutability
                                // errors when we peel away casts.
                                log::info!(
                                    "mutability mismatch in cast, recording the expression: {:?} != {:?} at {:?}",
                                    Type::from_ty(ctx.ctx, ty),
                                    Type::from_ty(ctx.ctx, sub_ty),
                                    expr.span
                                );
                                self.taint_analysis.mutability_casts.insert(expr.hir_id);
                            }
                        }
                    }
                }

                if add_void_poison && is_void_ptr(ctx.ctx, ty) && !disable_cast_poison {
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
                            .add_poison(PoisonKind::CastSource, dummy_for_ptsto);
                    }
                    Some(cast_var.to_term())
                } else if add_void_poison && is_void_ptr(ctx.ctx, sub_ty) && !disable_cast_poison {
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
                                .add_poison(PoisonKind::CastSource, dummy_for_ptsto);
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
            ExprKind::DropTemps(inner) => {
                self.analyze_expr(ctx, inner, ExprCtx::with_in_free(expr_ctx.in_free))
            },
            ExprKind::Loop(body, _label, _source, _span) => {
                self.analyze_block(ctx, body);
                None
            },
            ExprKind::Match(scrutinee, arms, _source) => {
                let maybe_scrutinee_term = self.analyze_expr(ctx, scrutinee, ExprCtx::default());
                let match_term = S(LV(Loc::Synthetic(expr.hir_id)));
                let immediate_flow = self
                    .taint_analysis
                    .arg_or_init
                    .get(&expr.hir_id)
                    .cloned()
                    .unwrap_or_else(|| FlowLoc::Plain(expr_loc.clone()));
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

                    // propagate immediate flows before analyzing the body
                    self.taint_analysis
                        .arg_or_init
                        .insert(arm.body.hir_id, immediate_flow.clone());

                    if let Some(arm_term) = self.analyze_expr(&extended_ctx, arm.body, expr_ctx) {
                        // arm_i ⊆ result
                        self.taint_analysis.add_flow(arm_term, match_term.clone());
                    }
                }

                Some(match_term)
            },
            ExprKind::Closure(_capture_by, _fn_decl, _body_id, _, _movability) => {
                if !is_laertes_helper(&ctx.fn_name) {
                    log::error!(
                        "closures are not implemented yet. closure in {} at {:?}",
                        ctx.fn_name,
                        expr.span
                    );
                }
                None
            },
            ExprKind::Block(block, _label) => {
                // propagate immediate flows before analyzing the body
                if let Some(f) = self.taint_analysis.arg_or_init.get(&expr.hir_id).cloned() {
                    self.taint_analysis.arg_or_init.insert(block.hir_id, f);
                }
                self.analyze_block(ctx, block)
            },
            ExprKind::Assign(lhs, rhs, _) => {
                let lhs_term = self.analyze_expr(
                    ctx,
                    lhs,
                    ExprCtx {
                        is_assignee: true,
                        is_callee: false,
                        in_free: false,
                        rewritable_malloc: false,
                    },
                );
                if let Some(lhs_term) = &lhs_term {
                    self.taint_analysis.arg_or_init.insert(
                        rhs.hir_id,
                        FlowLoc::Plain(lhs_term.get_lv().cloned().unwrap()),
                    );
                }
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
                // let adt_def = parent_ty.ty_adt_def().unwrap();
                if let Some(adt_def) = parent_ty.ty_adt_def() {
                    let def_id = adt_def.did;
                    let loc = Loc::Access(
                        Name::from(get_def_qname(ctx.ctx, def_id)),
                        Name::from(format!("{}", field)),
                    );

                    if adt_def.is_union() {
                        if !expr_ctx.is_assignee {
                            self.call_graph
                                .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::ReadFromUnion);
                        }
                        // mark this location as poisoned because we don't
                        // rewrite union variants
                        self.taint_analysis
                            .add_poison(PoisonKind::UnionFieldSink, loc.clone());
                        self.taint_analysis
                            .add_poison(PoisonKind::UnionFieldSource, loc.clone());
                    }

                    if !expr_ctx.in_free
                        && is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                        && !LIMIT_STUDY.load(Ordering::Relaxed)
                    {
                        self.taint_analysis
                            .add_poison(PoisonKind::VoidSource, loc.clone());
                    }

                    Some(loc.to_term())
                } else {
                    Some(expr_term)
                }
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
                        .add_flow(mk_ref(e.clone(), e.clone()), parent_loc.clone());
                    self.taint_analysis
                        .add_flow(parent_loc, mk_ref(e.clone(), e));
                }

                if !expr_ctx.in_free
                    && is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                    && !LIMIT_STUDY.load(Ordering::Relaxed)
                {
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
                    Res::Def(DefKind::Fn, _) => {
                        // this is a function that is used in a
                        // non-function context. Remember this
                        // function to freeze its function signature
                        // later on
                        let fn_name = Self::qpath_to_name(ctx, qpath, expr.hir_id);

                        let fn_sig = || {
                            if let Type::Fn(fn_sig) =
                                Type::from_ty(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                            {
                                fn_sig
                            } else {
                                unreachable!();
                            }
                        };

                        if !self.taint_analysis.fn_sigs.contains_key(&fn_name)
                            && !fn_name.contains("::bitfields::")
                            && !fn_name.ends_with("xmlschemastypes::get_bits")
                            && !fn_name.ends_with("xmlschemastypes::set_bits")
                        {
                            self.taint_analysis
                                .fn_sigs
                                .insert(fn_name.clone(), fn_sig());
                        }

                        if !expr_ctx.is_callee {
                            self.call_graph
                                .used_as_fn_pointer
                                .insert(fn_name.clone(), fn_sig());
                        }
                    },
                    _ => (),
                }

                if !expr_ctx.in_free
                    && is_void_ptr(ctx.ctx, ctx.ctx.typeck_results().expr_ty(expr))
                    && !LIMIT_STUDY.load(Ordering::Relaxed)
                {
                    self.taint_analysis
                        .add_poison(PoisonKind::VoidSource, path_lv.clone());
                }

                // return a unique expression for Option::None
                let term = match path_lv {
                    Loc::Var(name) if name.as_ref() == "core::option::Option::None" => expr_term,
                    _ => path_lv.to_term(),
                };
                Some(term)
            },
            ExprKind::AddrOf(_borrow_kind, mutbl, subexpr) => {
                // if we are taking a mutable borrow, then it can be
                // used for an assignment later on, so set the flag to true
                let subexpr_term = self.analyze_expr(
                    ctx,
                    subexpr,
                    ExprCtx::default().with_assignee(*mutbl == Mutability::Mut),
                );

                // Check if this is a re-borrow (`&mut *e` or `&*e`)
                if let ExprKind::Unary(UnOp::Deref, e) = subexpr.kind {
                    self.reborrow_map.insert(
                        expr_loc.clone(),
                        self.taint_analysis.expr_to_term[&e.hir_id].clone(),
                    );
                }

                self.addr_of_locs
                    .entry(expr_loc.clone())
                    .or_insert(BTreeSet::new())
                    .insert(expr.span);

                subexpr_term.map(|t| {
                    // add `ref(subexpr; subexpr) <> expr` and return
                    // `expr` so that we return a variable that can be
                    // checked against poisons

                    // TODO: choose based on lhs/rhs of assignment
                    self.taint_analysis.add_flow(
                        mk_ref(t.clone().extract_simple(), t.clone().extract_simple()),
                        expr_term.clone(),
                    );
                    self.taint_analysis.add_flow(
                        expr_term.clone(),
                        mk_ref(t.clone().extract_simple(), t.extract_simple()),
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

                let ret_loc = Loc::RetVal(ctx.fn_name.clone());
                self.taint_analysis
                    .arg_or_init
                    .insert(expr.hir_id, FlowLoc::Plain(ret_loc.clone()));
                if let Some(expr_term) = self.analyze_expr(ctx, expr, ExprCtx::default()) {
                    self.taint_analysis.add_flow(expr_term, S(LV(ret_loc)));
                }
                None
            },
            ExprKind::InlineAsm(_) => {
                // panic!("inline assembly is not supported")
                Some(expr_term)
            },
            ExprKind::LlvmInlineAsm(inline_asm) => {
                log::warn!(
                    "LLVM inline assembly is not supported. Pointer provenance results will be imprecise"
                );

                // poison input/output expressions
                let mut poison_expr = |e| {
                    if let Some(loc) = self
                        .analyze_expr(ctx, e, ExprCtx::default())
                        .and_then(|t| t.into_lv())
                    {
                        self.taint_analysis
                            .add_poison(PoisonKind::InlineAsmSource, loc.clone());
                        self.taint_analysis
                            .add_poison(PoisonKind::InlineAsmSink, loc.clone());
                    }
                };
                inline_asm.inputs_exprs.iter().for_each(&mut poison_expr);
                inline_asm.outputs_exprs.iter().for_each(&mut poison_expr);
                self.call_graph
                    .add_unsafe_behavior(&ctx.fn_name, UnsafeBehavior::InlineAsm);
                None
            },
            ExprKind::Struct(name, fields, None) => {
                let struct_name = Self::qpath_to_name(ctx, name, expr.hir_id);
                let field_terms = fields
                    .iter()
                    .map(|field| {
                        let field_name = Name::from(&*field.ident.as_str());
                        // also record the immediate flow to allow inserting casts
                        self.taint_analysis.arg_or_init.insert(
                            field.expr.hir_id,
                            FlowLoc::Plain(Loc::Access(struct_name.clone(), field_name.clone())),
                        );

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
            ExprKind::Repeat(elem, _n_times) => {
                // Propagate the taint from the repeated expression to the points-to set, like the `Array` case.
                if let Some(f) = self.taint_analysis.arg_or_init.get(&expr.hir_id).cloned() {
                    self.taint_analysis
                        .arg_or_init
                        .insert(elem.hir_id, FlowLoc::PointsTo(Box::new(f)));
                }
                if let Some(elem_term) = self.analyze_expr(ctx, elem, ExprCtx::default()) {
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

                    assert!(
                        !expr_ctx.is_assignee,
                        "Array repeat in assignee position: {:?}",
                        expr.span
                    );
                    self.taint_analysis.add_flow(
                        mk_ref(elem_var.clone(), elem_var.clone()),
                        expr_term.clone(),
                    );
                }
                Some(expr_term)
            },
            ExprKind::Yield(_, _) => panic!("yield is not supported"),
            ExprKind::Err => panic!("there is an error node in the HIR"),
            ExprKind::If(cond, then_expr, Some(else_expr)) => {
                let if_term = S(LV(Loc::Synthetic(expr.hir_id)));

                if let Some(cond_term) = self.analyze_expr(ctx, cond, ExprCtx::default()) {
                    self.taint_analysis.add_flow(cond_term, expr_term.clone());
                }

                if let Some(then_term) = self.analyze_expr(ctx, then_expr, ExprCtx::default()) {
                    // then_branch ⊆ result
                    self.taint_analysis.add_flow(then_term, expr_term.clone());
                }
                if let Some(else_term) = self.analyze_expr(ctx, else_expr, ExprCtx::default()) {
                    // else_branch ⊆ result
                    self.taint_analysis.add_flow(else_term, expr_term.clone());
                }
                // Some(expr_term)
                Some(if_term)
            },
            ExprKind::If(cond, then_expr, None) => {
                let if_term = S(LV(Loc::Synthetic(expr.hir_id)));

                if let Some(cond_term) = self.analyze_expr(ctx, cond, ExprCtx::default()) {
                    self.taint_analysis.add_flow(cond_term, expr_term.clone());
                }
                if let Some(then_term) = self.analyze_expr(ctx, then_expr, ExprCtx::default()) {
                    // then_branch ⊆ result
                    self.taint_analysis.add_flow(then_term, expr_term.clone());
                }
                // Some(expr_term)
                Some(if_term)
            },
            ExprKind::ConstBlock(_) => panic!("ConstBlock is not supported"),
            ExprKind::Let(_, _, _) => panic!("let is not supported"),
            // _ => unimplemented!(),
        };

        let ty = ctx.ctx.typeck_results().expr_ty(expr);
        if let Some(S(LV(lv))) = &result {
            self.taint_analysis.declare_owner(&lv, &ctx.fn_name);
            self.taint_analysis.in_global_init.insert(lv.clone());

            // Create dummy locations for function pointers outside of field
            // accesses and defined functions
            //
            // TODO: create locations more sparsely
            let dummy_is_created_elsewhere = match lv {
                Loc::Var(f) => !f.starts_with(ctx.fn_name.as_ref()),
                Loc::Access(_, _) | Loc::Param(_, _) | Loc::RetVal(_) => true,
                Loc::Synthetic(_) | Loc::Malloc(_) | Loc::Fresh(_) => false,
            };
            if !dummy_is_created_elsewhere
                && !ctx.fn_name.ends_with("::main")
                && !ctx.in_bitfield_helper
            {
                let typ = Type::from_ty(ctx.ctx, ty);
                if typ.is_fn() {
                    self.taint_analysis
                        .create_dummy_locs(lv.clone(), &typ, false);
                    self.taint_analysis
                        .create_dummy_locs(lv.clone(), &typ, true);
                }
            }
        }

        if let Some(term) = &result {
            // Repacking here wastefully creates a copy of the string
            // version.
            //
            // TODO(maemre): repack early and pass around u32 terms
            // inside analyze_expr.
            // log::warn!("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            // log::warn!("++++++ HIR_ID: {:?}, term: {:?}", expr.hir_id, term.clone());
            self.taint_analysis
                .bind_expr_to_term(expr.hir_id, term.clone());
        }

        if ty.is_adt() && !is_special_fn_in_benchmark(&ctx.fn_name) {
            if let Type::Struct(name) = Type::from_ty(ctx.ctx, ty) {
                self.taint_analysis
                    .maybe_expr_struct_type
                    .insert(expr.hir_id, name);
            }
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

                if let Some(pat_lv) = pat_term.as_ref().and_then(|l| l.get_lv()) {
                    // Also remember the connection between the initializer
                    // and the local variable
                    let_stmt.init.and_then(|init| {
                        self.taint_analysis
                            .arg_or_init
                            .insert(init.hir_id, FlowLoc::Plain(pat_lv.clone()))
                    });
                } else if pat_term.is_some() {
                    log::warn!(
                        "The pattern {:?} at {:?} does not have a single LV",
                        pat_term,
                        let_stmt.pat.hir_id
                    );
                }

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
        is_variadic: bool,
        in_global: bool, // whether we are in a global (static) variable
    ) {
        // add constraints for each parameter, then add the variables
        // inside params to Γ
        let mut ctx = AnalysisCtx::new(fn_name, ctx, in_global);

        let formal_params = (0..params.len())
            .map(|i| Loc::Param(ctx.fn_name.clone(), i).to_st())
            .collect::<Vec<SimpleTerm<Loc<Name>>>>();

        for (i, param) in params.iter().enumerate() {
            // analyze each pattern to extend locals
            let (param_term, new_ctx) = self.analyze_pattern(&ctx, &param.pat);
            // log::warn!("+++---param_term: {:?}", param_term);
            // if param_term.contains("::c2rust_asm_casts::AsmCast"){
            //     continue;
            // }
            ctx = new_ctx;
            // connect the parameter declared in the pattern to the formal parameter
            if let Some(param_loc) = param_term {
                // param term = paramᵢ
                self.taint_analysis
                    .add_flow(formal_params[i].clone().to_term(), param_loc.clone());
                self.taint_analysis
                    .add_flow(param_loc.clone(), formal_params[i].clone().to_term());
                // also add a dummy loc so that we can project λs if this
                // parameter contains a function pointer
                if let S(LV(p)) = param_loc {
                    if !ctx.in_bitfield_helper {
                        let ty = Type::from_ty(ctx.ctx, ctx.ctx.typeck_results().pat_ty(param.pat));
                        self.taint_analysis.create_dummy_locs(p.clone(), &ty, true);
                        self.taint_analysis.create_dummy_locs(p, &ty, false);
                    }
                }
            }
        }

        // connect λ(Param(f, i)..., RetVal(f)) ⊆ f, so that function pointers
        // work as usual
        if is_variadic {
            // for variadic functions, generate all possible λs for having up to 22 parameters

            let min_param_len = formal_params.len() - 1; // -1 because the last parameter names the vararg so it may be absent in a call
            let max_param_len = 22;
            for len in min_param_len..=max_param_len {
                let formal_params = (0..len)
                    .map(|i| Loc::Param(ctx.fn_name.clone(), i).to_st())
                    .collect::<Vec<SimpleTerm<Loc<Name>>>>();
                let lambda = mk_lambda(formal_params, Loc::RetVal(ctx.fn_name.clone()).to_st());
                self.taint_analysis
                    .add_flow(lambda, Loc::Var(ctx.fn_name.clone()).to_term());
            }
        }

        if !in_global {
            // Create a marker for this function so that we can project it out
            // to reason about function pointer equality. Specifically, we
            // insert '#fndef'(fn_name) ⊆ Fn_name (the first is a ctor, the
            // second is an LV)
            let dummy = Loc::fresh().to_st();
            self.taint_analysis.add_flow_with_already_resolved_names(
                C(Ctor(Name::from(ctx.fn_name.clone()), vec![], vec![])),
                dummy.clone().to_term(),
            );
            self.taint_analysis.add_flow(
                C(Ctor(FNDEF.clone(), vec![dummy], vec![])),
                Loc::Var(ctx.fn_name.clone()).to_term(),
            );
        }

        // insert the normal case even for variadic ones (in case the variadic fn has >22 formal params)
        let lambda = mk_lambda(formal_params, Loc::RetVal(ctx.fn_name.clone()).to_st());
        self.taint_analysis
            .add_flow(lambda, Loc::Var(ctx.fn_name.clone()).to_term());

        // if this is the main function, taint argv and ref⁻¹(argv)
        if is_main && !LIMIT_STUDY.load(Ordering::Relaxed) {
            let argv = Loc::Param(ctx.fn_name.clone(), 1);
            // create a variable for the points-to set of argv
            let argv_deref = Loc::fresh();
            self.taint_analysis.add_flow(
                mk_ref(argv_deref.clone().to_st(), argv_deref.clone().to_st()),
                argv.clone().to_term(),
            );

            self.taint_analysis
                .add_poison(PoisonKind::ArgvSource, argv.clone());
            self.taint_analysis.add_poison(PoisonKind::ArgvSink, argv);
            self.taint_analysis
                .add_poison(PoisonKind::ArgvSource, argv_deref.clone());
            self.taint_analysis
                .add_poison(PoisonKind::ArgvSink, argv_deref);
        }

        let mut inject_void = |loc: Loc<Name>| {
            self.taint_analysis
                .add_poison(PoisonKind::VoidSink, loc.clone());
            self.taint_analysis.add_poison(PoisonKind::VoidSource, loc);
        };

        // add `void *` poison to the parameters and the return value
        if !LIMIT_STUDY.load(Ordering::Relaxed) {
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
        }

        // analyze the body expression
        if let Some(rv) = self.analyze_expr(&ctx, &value, ExprCtx::default()) {
            self.taint_analysis
                .add_flow(rv, Loc::RetVal(ctx.fn_name).to_term());
        }
    }

    fn process_foreign_fn<'tcx>(
        &mut self,
        _ctx: &LateContext<'tcx>,
        fn_name: Name,
        fn_decl: &'tcx FnDecl<'tcx>,
    ) {
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
            // Inject extern arity to all lambdas referring to this function
            if fn_decl.c_variadic {
                // for varargs functions, create extra lambdas for
                // each arity (starting from len-1 because the last
                // input represent the varargs).
                for a in (fn_decl.inputs.len() - 1)..arity {
                    let formal_params = (0..a)
                        .map(|i| Loc::Param(fn_name.clone(), i).to_st())
                        .collect::<Vec<SimpleTerm<Loc<Name>>>>();
                    let lambda = mk_lambda(formal_params, Loc::RetVal(fn_name.clone()).to_st());
                    self.taint_analysis
                        .add_flow(lambda, Loc::Var(fn_name.clone()).to_term());
                }
            } else {
                let formal_params = (0..arity)
                    .map(|i| Loc::Param(fn_name.clone(), i).to_st())
                    .collect::<Vec<SimpleTerm<Loc<Name>>>>();
                let lambda = mk_lambda(formal_params, Loc::RetVal(fn_name.clone()).to_st());
                self.taint_analysis
                    .add_flow(lambda, Loc::Var(fn_name.clone()).to_term());
            }

            self.extern_arity.insert(fn_name, arity);
        }
    }

    fn add_extern_poison(&mut self, extern_fn_name: Name, arity: usize) {
        let sig = self.taint_analysis.fn_sigs.get(&extern_fn_name).cloned();
        for i in 0..arity {
            // add each parameter as a sink
            self.taint_analysis.add_poison(
                PoisonKind::ExternCallParam,
                Loc::Param(extern_fn_name.clone(), i),
            );
            // the condition below may fail for varargs functions
            sig.iter().for_each(|sig| {
                if i < sig.param_types.len() {
                    self.taint_analysis.create_dummy_locs(
                        Loc::Param(extern_fn_name.clone(), i),
                        &sig.param_types[i],
                        false,
                    );
                }
            });
        }
        sig.iter().for_each(|sig| {
            self.taint_analysis.create_dummy_locs(
                Loc::RetVal(extern_fn_name.clone()),
                &sig.ret_type,
                true,
            );
        });
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

        self.taint_analysis
            .fn_arity
            .insert(def_qname.clone(), decl.inputs.len());

        // do not analyze the injected intrinsics
        if is_laertes_helper(&def_qname) {
            return;
        }

        self.call_graph
            .defined_fns
            .insert(Name::from(&*unqual_name), def_qname.clone());

        if span.in_derive_expansion() {
            return;
        }

        // add this function to the relevant parts of call graph
        self.call_graph.add_fn_decl(def_qname.clone());
        if decl.c_variadic {
            self.call_graph
                .add_unsafe_behavior(&def_qname, UnsafeBehavior::VariadicFn);
        }

        let is_main = &*unqual_name == "main_0";
        self.analyze_body(def_qname, body, ctx, is_main, decl.c_variadic, false);
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

                // mark malloc/free as external functions in places
                // they may be used through function pointers, but not
                // in places where they are called directly.
                let ident_str = item.ident.as_str();
                let is_malloc_or_free =
                    ident_str == "malloc" || ident_str == "calloc" || ident_str == "free";
                if is_malloc_or_free || !qual_fn_we_can_handle(&name) {
                    let unqual_name = Name::from(&*ident_str);
                    if !self.call_graph.defined_fns.contains_key(&unqual_name) {
                        self.call_graph.extern_fns.insert(unqual_name);
                    }
                    self.process_foreign_fn(ctx, name, fn_decl);
                } else {
                }
            },
            Static(_, _) => {
                // This is an external static variable, poison it only
                // when computing lifetimes. It may be resolved by
                // ResolveImports so it is not poisoned there.
                if ANALYZE_GLOBAL_INITS.load(Ordering::Relaxed)
                    && !LIMIT_STUDY.load(Ordering::Relaxed)
                {
                    let def_id = DefId {
                        krate: LOCAL_CRATE,
                        index: ctx.tcx.hir().local_def_id(item.hir_id()).local_def_index,
                    };
                    let name = get_def_qname(ctx, def_id);
                    let loc = Loc::Var(name);
                    self.taint_analysis
                        .add_poison(PoisonKind::GlobalSource, loc.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::GlobalSink, loc.clone());
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
                        .add_poison(PoisonKind::GlobalSource, dummy_for_ptsto.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::GlobalSink, dummy_for_ptsto);
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
                let name = Name::from(get_def_qname(ctx, owner_def_id.to_def_id()));
                // Connect the global variable's location and the body
                let loc = Loc::Var(name.clone());
                self.taint_analysis
                    .arg_or_init
                    .insert(body.value.hir_id, FlowLoc::Plain(loc.clone()));
                // Use this to analyze only the body of global variable initializers.
                self.analyze_body(name.clone(), body, ctx, false, false, true);
                self.taint_analysis.add_flow(
                    self.taint_analysis.expr_to_term[&body.value.hir_id].clone(),
                    loc.to_term(),
                );
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
            Static(ty, Mutability::Mut, _) if !LIMIT_STUDY.load(Ordering::Relaxed) => {
                // mark this as a miscellaneous source/sink of unsafe data flow
                let path_lv = Loc::Var(name());
                self.taint_analysis
                    .add_poison(PoisonKind::GlobalSource, path_lv.clone());
                self.taint_analysis
                    .add_poison(PoisonKind::GlobalSink, path_lv.clone());
                // also taint all references this value holds
                if matches!(
                    ty.kind,
                    rustc_hir::TyKind::Ptr(_)
                        | rustc_hir::TyKind::Array(..)
                        | rustc_hir::TyKind::Rptr(..)
                ) {
                    // create a dummy variable for the pointee
                    let inner = Loc::fresh();
                    self.taint_analysis
                        .add_poison(PoisonKind::GlobalSource, inner.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::GlobalSink, inner.clone());
                    self.taint_analysis
                        .add_flow(mk_ref(LV(inner.clone()), LV(inner)), path_lv.to_term());
                }
                // TODO: taint the specific field dereferences as well
            },
            // typedef, map it to the struct type it represents, if it
            // represents a named type directly (rather than a pointer
            // or array for example)
            ItemKind::TyAlias(ty, generics) => {
                if !generics.params.is_empty() {
                    log::warn!("typedef has generics at {:?}", ty.span);
                }
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
                self.call_graph.extern_fns.insert(extern_fn.clone());
                self.add_extern_poison(extern_fn, arity);
            }
        }

        if self.taint_analysis.emulate_lifetime_only
            || POISON_SIGS_OF_FN_PTRS.load(Ordering::Relaxed)
        {
            for (f, sig) in &self.call_graph.used_as_fn_pointer {
                if self.call_graph.extern_fns.contains(f) || qual_fn_we_can_handle(f) {
                    continue;
                }
                let arity = *self
                    .taint_analysis
                    .fn_arity
                    .get(f)
                    .or_else(|| {
                        let unqual_name = Name::from(f.rsplit_once("::").unwrap().1);
                        self.call_graph
                            .defined_fns
                            .get(&unqual_name)
                            .and_then(|defined_fn| self.taint_analysis.fn_arity.get(&defined_fn))
                    })
                    .unwrap();
                for i in 0..arity {
                    self.taint_analysis
                        .add_poison(PoisonKind::FnPtrSource, Loc::Param(f.clone(), i));
                    // Create a dummy location and poison it if this is a nested pointer
                    let mut loc = Loc::Param(f.clone(), i);
                    // Using `get` because of varargs
                    let mut typ = sig.param_types.get(i);
                    while let Some(pointee) = typ.and_then(|t| t.get_pointee()) {
                        // Poison the points-to set by creating a dummy location
                        let pointee_loc = Loc::fresh();
                        self.taint_analysis.add_flow(
                            mk_ref(pointee_loc.clone().to_st(), pointee_loc.clone().to_st()),
                            loc.to_term(),
                        );
                        self.taint_analysis
                            .add_poison(PoisonKind::FnPtrSource, pointee_loc.clone());
                        loc = pointee_loc;
                        typ = Some(pointee);
                    }
                }
                self.taint_analysis
                    .add_poison(PoisonKind::FnPtrSink, Loc::RetVal(f.clone()));
            }
        }

        // Solve pointer provenance
        profile("constraint solving (TODO: only compute eq classes)", || {
            self.taint_analysis.solve().unwrap()
        });
        log::info!("constraint solving (TODO: only compute eq classes) done");

        // Merge signatures of functions used as function pointers
        let mut seen = HashSet::<Name>::default();
        let mut i = 0; //
        for (f, sig) in &self.call_graph.used_as_fn_pointer {
            log::warn!("+++++Merge signatures of functions used as function pointers+++++");
            log::warn!("num: {:?},  Fnsig: {:?}", i, sig);
            i = i + 1; //
            if seen.contains(f) {
                continue;
            }
            seen.insert(f.clone());
            let (params, ret) = self
                .taint_analysis
                .project_lambdas_unsafe(&Loc::Var(f.clone()), sig.known_arity());
            let taint_analysis = &mut self.taint_analysis;
            let mut unify_set = |set: HashSet<Loc<Name>>| {
                if let Some(p0) = set.iter().next().cloned() {
                    for p in set {
                        match &p {
                            Loc::Param(f, _) => seen.insert(f.clone()),
                            Loc::RetVal(f) => seen.insert(f.clone()),
                            _ => false,
                        };
                        taint_analysis.add_flow(p0.clone().to_term(), p.clone().to_term());
                        taint_analysis.add_flow(p.to_term(), p0.clone().to_term());
                    }
                }
            };
            params.into_iter().for_each(&mut unify_set);
            unify_set(ret);
        }

        // Connect poisoned allocations to return values of malloc/calloc
        if LIMIT_STUDY.load(Ordering::Relaxed) {
            let malloc_fn = self.call_graph.defined_fns.get(&Name::from("malloc"));
            let calloc_fn = self.call_graph.defined_fns.get(&Name::from("calloc"));
            for (loc, allocator) in self.malloc_calls.drain() {
                if self.taint_analysis.is_poisoned(&loc) {
                    let alloc_fn = match allocator {
                        MallocKind::Malloc => malloc_fn,
                        MallocKind::Calloc => calloc_fn,
                    };
                    // Link to the allocation function if it is defined by
                    // pseudo-safety
                    if let Some(alloc_fn) = alloc_fn {
                        self.taint_analysis
                            .add_flow(Loc::RetVal(alloc_fn.clone()).to_term(), loc.to_term());
                    }
                }
            }
        }
        log::info!("constraint solving start");
        // Solve pointer provenance
        profile("constraint solving", || {
            self.taint_analysis.solve().unwrap()
        });
        log::info!("constraint solving done");

        // Propagate poison info for arrays along reborrows.
        //
        // TODO(maemre): Once we implement decaying arrays to
        // references, revisit this code to make sure it does not
        // poison the re-borrows for decayed references.
        for (borrowing_loc, borrowed_term) in &self.reborrow_map {
            if self
                .taint_analysis
                .has_poison(borrowing_loc, PoisonKind::PtrArithSink)
            {
                self.taint_analysis
                    .add_flow(borrowed_term.clone(), borrowing_loc.clone().to_term());
            }
        }

        self.taint_analysis
            .propagate_occurrence_poisons_through_lambdas();

        profile("constraint solving (reborrow_map)", || {
            self.taint_analysis.solve().unwrap()
        });
        log::info!("constraint solving (reborrow_map) done");

        if POISON_MIXED_REFS.load(Ordering::Relaxed) {
            for (loc, _) in &self.addr_of_locs {
                if self
                    .taint_analysis
                    .has_poison(loc, PoisonKind::PtrArithSink)
                {
                    self.taint_analysis
                        .add_poison(PoisonKind::MixedRefSource, loc.clone());
                    self.taint_analysis
                        .add_poison(PoisonKind::MixedRefSink, loc.clone());
                }
            }
        }

        profile("constraint solving (addr_of_locs)", || {
            self.taint_analysis.solve().unwrap();
        });
        log::info!("constraint solving (addr_of_locs) done");

        // Clean up functions declared extern in one module then defined in another module
        let defined_fns = &self.call_graph.defined_fns;
        self.call_graph
            .extern_fns
            .retain(|f| !defined_fns.contains_key(f));

        // Compute the closure of the call graph
        self.call_graph.compute_closure();

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
                        missing
                            .clone()
                            .filter(|l| !matches!(l, Loc::Fresh(_)))
                            .for_each(|loc| {
                                println!("    - {:?}", loc);
                            });
                        let added = self.taint_analysis.poisons[&kind].difference(&set);
                        added
                            .clone()
                            .filter(|l| !matches!(l, Loc::Fresh(_)))
                            .for_each(|loc| {
                                println!("    + {:?}", loc);
                            });

                        if missing
                            .chain(added)
                            .find(|l| matches!(l, Loc::Fresh(_)))
                            .is_some()
                        {
                            println!("    # there are some fresh var differences");
                        }
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

        // Update the results by moving them out rather than cloning
        analysis::replace::<PtrProvenanceAnalysis>(Box::new(std::mem::replace(
            &mut self.taint_analysis,
            PtrProvenanceAnalysis::new(),
        )));
        analysis::replace::<CallGraph>(Box::new(std::mem::replace(
            &mut self.call_graph,
            CallGraph::new(),
        )));
    }
}
