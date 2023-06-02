use crate::{
    analysis::commons::get_def_qname,
    constants::*,
    lazy_static::lazy_static,
    rustc_ast::LitKind,
    rustc_hir,
    rustc_hir::*,
    rustc_lint::LateContext,
    rustc_middle::ty::{Ty, TyKind, *},
    util::HashMap,
    Atom,
};
/// This module contains a simplified representation of Rust's notion of types.
use itertools::Itertools;
use std::{
    collections::BTreeSet,
    fmt,
    fmt::{Debug, Display, Formatter},
    panic,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Mutex,
    },
};

pub use crate::Name;

lazy_static! {
    /// Lifetime counter for instantiating syntactic lifetimes obtained from the program
    static ref LIFETIME_COUNTER: AtomicU32 = AtomicU32::new(0);
    /// Current crate, needs to be updated by the lint passes
    pub static ref CRATE_NAME: Mutex<Name> = Mutex::new(Name::from(""));

    pub static ref UNDERSCORE: Lifetime = Name::from("'_");
    pub static ref STATIC_LIFETIME: Lifetime = Name::from("'static");
}

/// Whether to replace the crate name in externs
pub static CRATE_INDEPENDENT_EXTERN_NAMES: AtomicBool = AtomicBool::new(false);

pub fn reset_lifetime_counter() {
    LIFETIME_COUNTER.store(0, Ordering::SeqCst);
}

fn region_to_lifetime(r: Region<'_>) -> Option<Lifetime> {
    use RegionKind::*;

    // 定义了一个闭包，相当于一个匿名函数，接受的参数是b，通过match匹配，来确定返回值
    let bound_region_name = |b| match b {
        BoundRegionKind::BrAnon(number) => Name::from(format!("'{}", number)),
        BoundRegionKind::BrNamed(_, name) => Name::from(&*name.as_str()),
        BrEnv => panic!("TODO: handle anonymous regions passed to closures"),
    };

    // TODO: handle free region names appropriately
    match r {
        // ReEarlyBound(b) => Some(bound_region_name((*b).into())),
        ReEarlyBound(EarlyBoundRegion {
            def_id,
            index: _,
            name,
            ..
        }) => {
            let br_named = BoundRegionKind::BrNamed(*def_id, *name);
            Some(bound_region_name(br_named))
        },
        ReLateBound(_debruijn_index, b) => Some(bound_region_name((*b).kind)),
        ReFree(f) => Some(bound_region_name(f.bound_region)),
        ReVar(_) => panic!("region variables should not exist after type check"),
        RePlaceholder(_) => {
            panic!("higher-ranked region placeholders should not exist after type check")
        },
        ReEmpty(_) => {
            // this region is for data that is never accessed, we
            // return no lifetime for it
            None
        },
        ReStatic => Some(Name::from("'static")),
        ReErased => Some(Name::from("'_")),
    }
}

pub fn extract_lifetime_name(ln: &LifetimeName) -> Option<Name> {
    use LifetimeName::*;

    match ln {
        Error => None,
        // TODO: derive implicit lifetime constraints in function signatures too
        Implicit => Some(Name::from(format!(
            "'implicit_{}",
            LIFETIME_COUNTER.fetch_add(1, Ordering::SeqCst)
        ))),
        ImplicitObjectLifetimeDefault => None,
        Static => Some(Name::from("'static")),
        Underscore => {
            log::warn!("TODO: generate fresh name for underscores");
            Some(Name::from("'_"))
        },
        Param(param_name) => Some(Name::from(&*param_name.ident().name.as_str())),
    }
}

// Use symbols for lifetime variables for now
pub type Lifetime = Atom;

/// Function type signatures
#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct FnSig {
    pub unsafety: Unsafety,
    /// Qualified lifetime variables. The signature may use other,
    /// free, lifetime variables depending on its context.
    pub lifetime_quals: Vec<Lifetime>,
    /// Side-constraints of lifetimes. For example, if a function
    /// signature has side-constraint `'a : 'b` (`'a` outlives `'b`),
    /// then this vector contains `('a, 'b)`.
    pub lifetime_bounds: Vec<(Lifetime, Lifetime)>,
    pub param_types: Vec<Type>,
    pub ret_type: Box<Type>,
    pub c_variadic: bool,
}

impl FnSig {
    pub fn known_arity(&self) -> Option<usize> {
        if self.c_variadic {
            None
        } else {
            Some(self.param_types.len())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CustomSliceType {
    Ref(Lifetime, CustomSliceCell),
    RefMut(Lifetime),
    Boxed(CustomSliceCell),
    Array(CustomSliceCell, Option<usize>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CustomSliceCell {
    NoCell,
    RefCell,
}

impl CustomSliceType {
    pub fn for_ref(lifetime: Lifetime, mtbl: Mutability, cell: CustomSliceCell) -> Self {
        match (mtbl, cell) {
            (_, c @ CustomSliceCell::RefCell) | (Mutability::Not, c @ CustomSliceCell::NoCell) => {
                Self::Ref(lifetime, c)
            },
            (Mutability::Mut, CustomSliceCell::NoCell) => Self::RefMut(lifetime),
        }
    }

    pub fn for_owned(cell: CustomSliceCell) -> Self {
        Self::Boxed(cell)
    }

    pub fn slice_type(&self, item: Type) -> Type {
        let item = Box::new(self.cell().item_type(item));

        match self {
            Self::Ref(l, _) => Type::Ref(Mutability::Not, l.clone(), Box::new(Type::Slice(item))),
            Self::RefMut(l) => Type::Ref(Mutability::Mut, l.clone(), Box::new(Type::Slice(item))),
            Self::Boxed(..) => Type::Boxed(Box::new(Type::Slice(item))),
            Self::Array(_, l) => Type::Array(item, *l),
        }
    }

    pub fn ref_mutability(&self) -> Mutability {
        match self {
            Self::Ref(..) => Mutability::Not,
            Self::RefMut(..) => Mutability::Mut,
            Self::Boxed(..) | Self::Array(..) => panic!("Not a reference slice type!"),
        }
    }

    pub fn cell(&self) -> CustomSliceCell {
        match *self {
            Self::Ref(_, c) => c,
            Self::RefMut(..) => CustomSliceCell::NoCell,
            Self::Boxed(c) => c,
            Self::Array(c, _) => c,
        }
    }

    pub fn wrap_display<W: fmt::Write>(
        &self,
        f: &mut W,
        item: impl Fn(&mut W) -> fmt::Result,
    ) -> fmt::Result {
        match self {
            Self::Ref(lifetime, _) | Self::RefMut(lifetime) => {
                write!(f, "{}, ", lifetime)?;
                item(f)?;
                write!(
                    f,
                    ", &{} {} [",
                    lifetime,
                    self.ref_mutability().prefix_str()
                )?;
                self.cell().wrap_display(f, item)?;
                write!(f, "]")
            },
            Self::Boxed(cell) => {
                write!(f, "'static, ")?;
                item(f)?;
                write!(f, ", Box<[")?;
                cell.wrap_display(f, item)?;
                write!(f, "]>")
            },
            Self::Array(cell, len) => {
                write!(f, "'static, ")?;
                item(f)?;
                write!(f, ", [")?;
                cell.wrap_display(f, item)?;
                len.map(|l| write!(f, "; {}", l)).transpose()?;
                write!(f, "]")
            },
        }
    }
}

impl CustomSliceCell {
    fn item_type(&self, inner: Type) -> Type {
        match self {
            Self::NoCell => inner,
            Self::RefCell => Type::RefCell(Box::new(inner)),
        }
    }

    fn wrap_display<W: fmt::Write>(
        &self,
        f: &mut W,
        item: impl FnOnce(&mut W) -> fmt::Result,
    ) -> fmt::Result {
        match self {
            Self::NoCell => item(f),
            Self::RefCell => {
                write!(f, "::std::cell::RefCell<")?;
                item(f)?;
                write!(f, ">")
            },
        }
    }
}

/// Rust types that we care about, this is a watered-down version of
/// [`rustc_middle::ty::TyKind`] that does not contain references to [`TyCtxt`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    Bool,
    Char,
    Int(IntTy),
    Uint(UintTy),
    Float(FloatTy),
    Struct(Name),
    Enum(Name),
    Union(Name),
    Str,
    /// An [`Option`], we keep these separate from structs because
    /// we don't support generics in general but there are `Option`s.
    OptionT(Box<Type>),
    Tuple(Vec<Type>),
    /// An array type with an optional known size
    Array(Box<Type>, Option<usize>),
    Slice(Box<Type>),
    CustomSlice(CustomSliceType, Box<Type>),
    RefCell(Box<Type>),
    /// Function types, here `FnDef` and `FnPtr` from [`TyKind`] are
    /// merged. This does *not* represent closures.
    Fn(FnSig),
    /// Type of `!`, the bottom type.
    Never,
    /// Pointer types
    Ptr(Mutability, Box<Type>),
    /// Reference types
    Ref(Mutability, Lifetime, Box<Type>),
    /// Boxes, we treat boxes specially to represent owned fields
    Boxed(Box<Type>),
    /// The type that is not represented/unknown/not relevant to the analysis at hand
    Opaque,
    /// An unresolved named-type
    Unknown(Vec<Segment>),
    /// A syntactic type that is semantically unknown. This should not
    /// exist after processing struct definitions
    Syntactic(Vec<Segment>),
    /// A type-level application like `T<'a, 'b>`. We consider applying only lifetimes
    App(Box<Type>, Vec<Lifetime>),
    /// An external, unknown type
    Extern(Name),
}

/// Make a crate-independent path equivalent to the given path
fn mk_crate_independent(path: &Vec<Segment>) -> Vec<Segment> {
    let mut p = path.clone();
    let crate_segment = Segment::new(CRATE_NAME.lock().unwrap().clone());
    if p[0] == crate_segment {
        p[0].name = KW_CRATE.clone();
    }
    p
}

pub fn mk_crate_independent_qname(path: &Name) -> Name {
    let (root, rest) = path.as_ref().split_once("::").unwrap();
    if root == CRATE_NAME.lock().unwrap().as_ref() {
        Name::from(format!("crate::{}", rest))
    } else {
        path.clone()
    }
}

/// Checks if given expression has a constant integral value that is cast
/// to different types (like `1 as c_int as usize`), and get its value.
pub fn get_constant_value(expr: &Expr) -> Option<LitKind> {
    match &expr.kind {
        ExprKind::Lit(lit) => Some(lit.node.clone()),
        ExprKind::Cast(inner, _) => get_constant_value(inner),
        _ => None,
    }
}

impl Display for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Type::*;

        match self {
            Bool => write!(f, "bool"),
            Char => write!(f, "bool"),
            Int(ty) => write!(f, "{}", ty.name_str()),
            Uint(ty) => write!(f, "{}", ty.name_str()),
            Float(ty) => write!(f, "{}", ty.name_str()),
            Struct(name) => write!(f, "{}", mk_crate_independent_qname(name)),
            Enum(name) => write!(f, "{}", mk_crate_independent_qname(name)),
            Union(name) => write!(f, "{}", mk_crate_independent_qname(name)),
            Str => write!(f, "str"),
            OptionT(inner) => write!(f, "Option<{}>", inner),
            Tuple(elems) => write!(f, "({})", elems.iter().format(", ")),
            Array(inner, None) => write!(f, "[{}; ?]", inner),
            Array(inner, Some(size)) => write!(f, "[{}; {}]", inner, size),
            Slice(inner) => write!(f, "[{}]", inner),
            CustomSlice(ty, inner) => {
                write!(f, "crate::__laertes_array::CustomSlice<")?;

                ty.wrap_display(f, |f| write!(f, "{}", inner))?;

                write!(f, ">")
            },
            RefCell(inner) => write!(f, "::std::cell::RefCell<{}>", inner),
            Fn(sig) => {
                if !sig.lifetime_quals.is_empty() {
                    write!(
                        f,
                        "for <{}>",
                        sig.lifetime_quals
                            .iter()
                            .map(|l| {
                                // upper bounds for this lifetime variable
                                let upper_bounds = sig
                                    .lifetime_bounds
                                    .iter()
                                    .filter(|(lower, _)| lower == l)
                                    .map(|(_, u)| u)
                                    .join(" + ");
                                if upper_bounds == "" {
                                    l.to_string()
                                } else {
                                    format!("{}: {}", l, upper_bounds)
                                }
                            })
                            .join(", ")
                    )?;
                }
                if sig.unsafety == Unsafety::Unsafe {
                    write!(f, "unsafe extern \"C\" ")?;
                }
                write!(f, " fn")?;
                write!(f, "(")?;
                sig.param_types
                    .iter()
                    .for_each(|t| write!(f, "_: {},", t).unwrap());
                if sig.c_variadic {
                    write!(f, "...")?;
                }
                write!(f, ") -> {}", sig.ret_type)
            },
            Never => write!(f, "!"),
            Ptr(mtbl, inner) => write!(
                f,
                "* {} {}",
                if *mtbl == Mutability::Mut {
                    "mut"
                } else {
                    "const"
                },
                inner
            ),
            Ref(mtbl, lifetime, inner) => write!(f, "&{} {}{}", lifetime, mtbl.prefix_str(), inner),
            Boxed(inner) => write!(f, "Box<{}>", inner),
            Opaque => write!(f, "opaque ?"),
            Unknown(path) => write!(f, "{}", mk_crate_independent(&path).iter().format("::")),
            Syntactic(path) => write!(f, "{}", mk_crate_independent(&path).iter().format("::")),
            App(inner, args) => write!(f, "{}<{}>", inner, args.iter().format(", ")),
            Extern(name) => {
                if CRATE_INDEPENDENT_EXTERN_NAMES.load(Ordering::Relaxed) {
                    write!(f, "{}", mk_crate_independent_qname(name))
                } else {
                    write!(f, "{}", name)
                }
            },
        }
    }
}

impl Debug for Type {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// An owning version of rustc's resolved [`PathSegment`], lack of
/// references makes carrying values around much easier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment {
    pub name: Name,
    pub generic_args: Vec<Type>,
    pub lifetime_args: Vec<Lifetime>,
}

impl Segment {
    pub fn new(name: Name) -> Self {
        Segment {
            name: name,
            generic_args: vec![],
            lifetime_args: vec![],
        }
    }

    pub fn from_string(name: String) -> Self {
        Self::new(Name::from(name.as_str()))
    }

    pub fn from_path_segment(ctx: &LateContext<'_>, segment: &PathSegment<'_>) -> Self {
        let name = Name::from(&*segment.ident.name.as_str());
        let mut generic_args = vec![];
        let mut lifetime_args = vec![];

        if let Some(args) = &segment.args {
            assert!(
                args.bindings.is_empty(),
                "Type bindings are not supported. Type binding at: {:?}",
                segment.ident.span
            );

            for arg in args.args {
                match arg {
                    GenericArg::Lifetime(l) => {
                        lifetime_args.push(extract_lifetime_name(&l.name).unwrap());
                    },
                    GenericArg::Type(ty) => {
                        generic_args.push(Type::from_hir_ty(ctx, ty));
                    },
                    GenericArg::Const(_) => {
                        panic!("constant generic arguments are not supported");
                    },
                    GenericArg::Infer(_) => {
                        panic!("Infer generic arguments are not supported");
                    },
                }
            }
        }

        Segment {
            name,
            generic_args,
            lifetime_args,
        }
    }

    // pub fn to_string(&self) -> String {
    //     format!("{:?}", self)
    // }

    pub fn flatten(&self) -> Name {
        if self.generic_args.is_empty() && self.lifetime_args.is_empty() {
            self.name.clone()
        } else {
            Name::from(self.to_string())
        }
    }
}

impl Debug for Segment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fn write_args<T: Debug>(f: &mut Formatter<'_>, args: &[T]) -> fmt::Result {
            write!(
                f,
                "{}",
                args.iter().map(|arg| format!("{:?}", arg)).join(", ")
            )
        }

        write!(f, "{}", self.name)?;
        if self.generic_args.is_empty() && self.lifetime_args.is_empty() {
            return Ok(());
        }

        write!(f, "<")?;
        write_args(f, &self.lifetime_args)?;

        if !self.generic_args.is_empty() && !self.lifetime_args.is_empty() {
            // put a comma between lifetime and generic args
            write!(f, ", ")?;
        }

        write_args(f, &self.generic_args)?;
        write!(f, ">")
    }
}

impl Display for Segment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn qpath_to_segments<'tcx>(
    ctx: &LateContext<'_>,
    qpath: &QPath<'tcx>,
    hir_id: HirId,
) -> Vec<Segment> {
    use rustc_hir::def::Res::*;
    use QPath::*;

    let resolve_path_directly = || match qpath {
        Resolved(_self_ty, path) => path
            .segments
            .iter()
            .map(|segment| Segment::from_path_segment(ctx, segment))
            .filter(|s| !s.name.is_empty())
            .collect(),
        TypeRelative(self_ty, segment) => {
            // TODO: process self_ty properly, splitting generics
            vec![
                Segment::from_string(format!("{:?}", self_ty)),
                Segment::from_path_segment(ctx, segment),
            ]
        },
        LangItem(item, _) => {
            // TODO: process lang item names properly
            vec![Segment::from_string(format!("{}", item.name()))]
        },
    };

    match ctx.qpath_res(qpath, hir_id) {
        Def(_, def_id) => ctx
            .get_def_path(def_id)
            .iter()
            .map(|s| Segment::new(Name::from(&*s.as_str())))
            .filter(|s| !s.name.is_empty())
            .collect(),
        Local(_) | Err => resolve_path_directly(),
        PrimTy(prim) => vec![Segment::new(Name::from(prim.name_str()))],
        def => todo!("{:?}", def),
    }
}

impl Type {
    /// Create a type object from a HIR (syntactic) type. Using these
    /// types may require extra expansion and support, since these
    /// types are not normalized by type checking.
    pub fn from_hir_ty(ctx: &LateContext<'_>, ty: &rustc_hir::Ty<'_>) -> Self {
        use rustc_hir::TyKind;
        match &ty.kind {
            /*
            TyKind::Bool => Type::Bool,
            TyKind::Char => Type::Char,
            TyKind::Int(int_ty) => Type::Int(*int_ty),
            TyKind::Uint(uint_ty) => Type::Uint(*uint_ty),
            TyKind::Float(float_ty) => Type::Float(*float_ty),
            TyKind::Adt(_adt_def, _substitutions) => panic!("not implemented"),
            TyKind::Foreign(_def_id) => panic!("not implemented"),
            TyKind::Str => Type::Str,*/
            TyKind::Array(inner, size) => {
                let size_expr = &ctx.tcx.hir().body(size.body).value;
                // let source_map = ctx.sess().source_map();
                let size_value = get_constant_value(size_expr).and_then(|l| match l {
                    LitKind::Int(n, _) => Some(n as usize),
                    _ => None,
                });
                if size_value.is_none() {
                    log::error!("cannot represent array size: {:?}", size_expr);
                }
                Type::Array(Box::new(Type::from_hir_ty(ctx, inner)), size_value)
            },
            TyKind::Slice(inner) => Type::Slice(Box::new(Type::from_hir_ty(ctx, inner))),
            TyKind::Ptr(MutTy { ty, mutbl }) => {
                Type::Ptr(*mutbl, Box::new(Type::from_hir_ty(ctx, ty)))
            },
            TyKind::Rptr(lifetime, MutTy { ty, mutbl }) => Type::Ref(
                *mutbl,
                extract_lifetime_name(&lifetime.name)
                    .expect(&format!("expected lifetime at {:?}", ty.span)),
                Box::new(Type::from_hir_ty(ctx, ty)),
            ),
            TyKind::BareFn(fn_ty) => {
                let mut lifetime_bounds = Vec::new();

                let mut process_bounds = |lhs: &Name, generic_bounds: GenericBounds| {
                    for bound in generic_bounds {
                        match bound {
                            GenericBound::Outlives(rhs) => {
                                if let Some(rhs) = extract_lifetime_name(&rhs.name) {
                                    lifetime_bounds.push((lhs.clone(), rhs))
                                }
                            },
                            _ => panic!("Unsupported generic bound in function type {:?}", ty.span),
                        }
                    }
                };

                // verify & extract generics
                let lifetime_quals = fn_ty
                    .generic_params
                    .iter()
                    .map(|param| match &param.kind {
                        GenericParamKind::Lifetime { .. } => {
                            let param_name = Name::from(&*param.name.ident().name.as_str());

                            process_bounds(&param_name, &param.bounds);
                            param_name
                        },
                        _ => panic!(
                            "found non-lifetime generics parameter in function type {:?}",
                            ty.span
                        ),
                    })
                    .collect::<Vec<Lifetime>>();

                let param_types = fn_ty
                    .decl
                    .inputs
                    .iter()
                    .map(|ty| Type::from_hir_ty(ctx, ty))
                    .collect();

                let ret_type = Box::new(match fn_ty.decl.output {
                    FnRetTy::DefaultReturn(span) => {
                        log::info!(
                            "Return type in signature is not specified and type checking result is unavailable. Defaulting to `()` : {:?}",
                            span
                        );
                        Type::Tuple(vec![])
                    },
                    FnRetTy::Return(ty) => Type::from_hir_ty(ctx, ty),
                });

                Type::Fn(FnSig {
                    unsafety: fn_ty.unsafety,
                    lifetime_quals: lifetime_quals,
                    lifetime_bounds: lifetime_bounds,
                    param_types: param_types,
                    ret_type: ret_type,
                    c_variadic: fn_ty.decl.c_variadic,
                })
            },
            TyKind::TraitObject(..) => panic!("trait objects are not supported"),
            TyKind::Never => Type::Never,
            TyKind::Tup(fields) => {
                Type::Tuple(fields.iter().map(|ty| Type::from_hir_ty(ctx, ty)).collect())
            },
            TyKind::Path(qpath) => {
                let path = qpath_to_segments(ctx, qpath, ty.hir_id);
                let joined_path = path.iter().join("::");
                match &path[..] {
                    [name] if name == &Segment::new(BOOL.clone()) => Type::Bool,
                    [name] if name == &Segment::new(CHAR.clone()) => Type::Char,
                    [name] if name == &Segment::new(STR.clone()) => Type::Str,
                    _ if joined_path == "f128_internal::f128_t::f128" => F128_TYPE.clone(),
                    _ if joined_path == "core::option::Option" => {
                        if let QPath::Resolved(_, Path { segments, .. }) = qpath {
                            // extract the generic argument from the last segment
                            if let GenericArg::Type(inner_ty) =
                                &segments.last().unwrap().args.unwrap().args[0]
                            {
                                Type::OptionT(Box::new(Type::from_hir_ty(ctx, inner_ty)))
                            } else {
                                panic!(
                                    "the Option at {:?} does not have a single generic type argument",
                                    ty.span
                                );
                            }
                        } else {
                            panic!(
                                "could not get the generic argument of Option at {:?}",
                                ty.span
                            );
                        }
                    },
                    // TODO: specialize int, float, etc. types with
                    // best-effort syntactic matching
                    _ => Type::Syntactic(path),
                }
            },
            TyKind::OpaqueDef(_, _) => unimplemented!("opaque def: {:?}", ty.kind), //Opaque,
            TyKind::Typeof(_) => panic!("typeof is not supported"),
            TyKind::Infer => unimplemented!("type to infer at {:?}", ty.span), // Opaque,
            TyKind::Err => panic!("There is a type error in the program"),
        }
    }

    pub fn from_ty<'a, 'tcx>(ctx: &'a LateContext<'tcx>, ty: Ty<'tcx>) -> Self {
        let enclosing_body_expr = ctx.enclosing_body.map(|b| &ctx.tcx.hir().body(b).value);
        match ty.kind() {
            TyKind::Bool => Type::Bool,
            TyKind::Char => Type::Char,
            TyKind::Int(int_ty) => Type::Int(*int_ty),
            TyKind::Uint(uint_ty) => Type::Uint(*uint_ty),
            TyKind::Float(float_ty) => Type::Float(*float_ty),
            TyKind::Adt(adt_def, subs) if subs.non_erasable_generics().next().is_some() => {
                // There is at least one non-erasable generic argument
                let name = get_def_qname(ctx, adt_def.did);
                if name == "core::option::Option" {
                    // Special handling of option
                    Type::OptionT(Box::new(Type::from_ty(ctx, subs[0].expect_ty())))
                } else if name == "core::cell::RefCell" {
                    Type::RefCell(Box::new(Type::from_ty(ctx, subs[0].expect_ty())))
                } else if name == "alloc::boxed::Box" {
                    // Special handling of box
                    Type::Boxed(Box::new(Type::from_ty(ctx, subs[0].expect_ty())))
                } else if name.split_once("::").unwrap().1 == "__laertes_array::CustomSlice" {
                    let custom_slice_kind = match Type::from_ty(ctx, subs[2].expect_ty()) {
                        Type::Ref(Mutability::Mut, lifetime, _) => {
                            CustomSliceType::RefMut(lifetime)
                        },
                        Type::Ref(
                            Mutability::Not,
                            lifetime,
                            box Type::Slice(box Type::RefCell(..)),
                        ) => CustomSliceType::Ref(lifetime, CustomSliceCell::RefCell),
                        Type::Ref(Mutability::Not, lifetime, box Type::Slice(_)) => {
                            CustomSliceType::Ref(lifetime, CustomSliceCell::NoCell)
                        },
                        Type::Array(box Type::RefCell(..), len) => {
                            CustomSliceType::Array(CustomSliceCell::RefCell, len)
                        },
                        Type::Array(_, len) => CustomSliceType::Array(CustomSliceCell::NoCell, len),
                        Type::Boxed(box Type::RefCell(..)) => {
                            CustomSliceType::Boxed(CustomSliceCell::RefCell)
                        },
                        Type::Boxed(_) => CustomSliceType::Boxed(CustomSliceCell::NoCell),
                        inner_ty => todo!("not handling inner type for custom slice: {}", inner_ty),
                    };
                    Type::CustomSlice(
                        custom_slice_kind,
                        Box::new(Type::from_ty(ctx, subs[1].expect_ty())),
                    )
                } else {
                    panic!(
                        "type application is not implemented: {}, subs: {:?}",
                        name, subs
                    )
                }
            },
            TyKind::Adt(adt_def, _subs) => {
                let name = Name::from(get_def_qname(ctx, adt_def.did));

                if name.as_ref() == "f128_internal::f128_t::f128" {
                    F128_TYPE.clone()
                } else if adt_def.is_struct() {
                    Type::Struct(name)
                } else if adt_def.is_enum() {
                    Type::Enum(name)
                } else if adt_def.is_union() {
                    Type::Union(name)
                } else {
                    unimplemented!("ADT definition is not implemented: {:?}", adt_def)
                }
            },
            TyKind::Foreign(def_id) => Type::Extern(mk_crate_independent_qname(&Name::from(
                get_def_qname(ctx, *def_id),
            ))),
            TyKind::Str => Type::Str,
            TyKind::Array(inner, size) => {
                use crate::rustc_middle::mir::interpret::ConstValue;

                Type::Array(
                    Box::new(Type::from_ty(ctx, inner)),
                    match size.val {
                        ConstKind::Value(ConstValue::Scalar(s)) => {
                            Some(s.to_u64().unwrap() as usize)
                        },
                        _ => None,
                    },
                )
            },
            TyKind::Slice(inner) => Type::Slice(Box::new(Type::from_ty(ctx, inner))),
            TyKind::RawPtr(TypeAndMut { ty, mutbl }) => {
                Type::Ptr(*mutbl, Box::new(Type::from_ty(ctx, ty)))
            },
            TyKind::Ref(region, pointee_ty, mutbl) => Type::Ref(
                *mutbl,
                region_to_lifetime(region).unwrap(),
                Box::new(Type::from_ty(ctx, pointee_ty)),
            ),
            TyKind::FnDef(_def_id, _subs) => {
                // note: for now, we assume that there are no
                // qualifiers in the FnPtr types

                // TODO: make sure that we extract and wrap around qualifiers
                let sig = ty.fn_sig(ctx.tcx.clone()).skip_binder();
                // log::warn!("++++++TyKind::FnDef {:?}", sig);

                let param_types = sig
                    .inputs()
                    .iter()
                    .map(|ty| Type::from_ty(ctx, ty))
                    .collect();
                let ret_type = Box::new(Type::from_ty(ctx, sig.output()));
                Type::Fn(FnSig {
                    unsafety: sig.unsafety,
                    param_types,
                    ret_type,
                    lifetime_quals: Vec::new(),
                    lifetime_bounds: Vec::new(),
                    c_variadic: sig.c_variadic,
                })
            },
            TyKind::FnPtr(poly_sig) => {
                // note: for now, we assume that there are no
                // qualifiers in the FnPtr types

                // TODO: make sure that we extract and wrap around qualifiers
                let sig = poly_sig.skip_binder();

                let param_types = sig
                    .inputs()
                    .iter()
                    .map(|ty| Type::from_ty(ctx, ty))
                    .collect();
                let ret_type = Box::new(Type::from_ty(ctx, sig.output()));
                Type::Fn(FnSig {
                    unsafety: sig.unsafety,
                    param_types,
                    ret_type,
                    lifetime_quals: Vec::new(),
                    lifetime_bounds: Vec::new(),
                    c_variadic: sig.c_variadic,
                })
            },
            TyKind::Never => Type::Never,
            TyKind::Dynamic(_, _) => panic!("dynamic types are not supported"),
            TyKind::Closure(_, _) => panic!("closures are not supported"),
            TyKind::Generator(_, _, _) | TyKind::GeneratorWitness(_) => panic!(
                "generators and generator witnesses are not supported: {:?}",
                ty.kind()
            ),
            TyKind::Tuple(_) => {
                Type::Tuple(ty.tuple_fields().map(|t| Type::from_ty(ctx, t)).collect())
            },
            TyKind::Projection(_) => panic!(
                "projections or associated types are not supported: {:?}",
                ty
            ),
            TyKind::Opaque(_, _) => unimplemented!("{:?}", ty.kind()),
            TyKind::Param(_) => panic!(
                "generics are not supported: {:?} in {:?}",
                ty,
                enclosing_body_expr.map(|e| e.span)
            ),
            TyKind::Bound(_, _) => panic!("generics and traits are not supported"),
            TyKind::Placeholder(_) => unimplemented!("placeholder type"), //Opaque,
            TyKind::Infer(_) => unimplemented!("inferred type"),          //Opaque,
            TyKind::Error(_) => panic!("There is a type error in the program"),
        }
    }

    /// Collect all structs that occur in a this type
    pub fn collect_structs(&self) -> Vec<Name> {
        match self {
            Type::Struct(name) => vec![name.clone()],
            Type::OptionT(inner) => inner.collect_structs(),
            Type::Tuple(inner) => inner.iter().flat_map(|t| t.collect_structs()).collect(),
            Type::Array(inner, _) => inner.collect_structs(),
            Type::Slice(inner) => inner.collect_structs(),
            Type::Fn(sig) => {
                let mut result = Vec::new();
                sig.param_types
                    .iter()
                    .for_each(|t| result.append(&mut t.collect_structs()));
                result.append(&mut sig.ret_type.collect_structs());
                result
            },
            Type::Ptr(_, inner) => inner.collect_structs(),
            Type::Ref(_, _, inner) => inner.collect_structs(),
            Type::Boxed(inner) => inner.collect_structs(),
            Type::App(inner, _) => inner.collect_structs(),
            _ => vec![],
        }
    }

    /// Collect all structs that occur in a this type
    pub fn collect_lifetimes_into(&self, s: &mut BTreeSet<Lifetime>) {
        match self {
            Type::OptionT(inner) => inner.collect_lifetimes_into(s),
            Type::Tuple(inner) => inner.iter().for_each(|t| t.collect_lifetimes_into(s)),
            Type::Array(inner, _) => inner.collect_lifetimes_into(s),
            Type::Slice(inner) => inner.collect_lifetimes_into(s),
            Type::App(inner, lifetimes) => {
                s.extend(lifetimes.clone());
                inner.collect_lifetimes_into(s)
            },
            Type::Fn(sig) => {
                s.extend(sig.lifetime_quals.clone());
                sig.param_types
                    .iter()
                    .for_each(|t| t.collect_lifetimes_into(s));
                sig.ret_type.collect_lifetimes_into(s)
            },
            Type::Ptr(_, inner) => inner.collect_lifetimes_into(s),
            Type::Ref(_, lifetime, inner) => {
                s.insert(lifetime.clone());
                inner.collect_lifetimes_into(s);
            },
            Type::Boxed(inner) => inner.collect_lifetimes_into(s),
            _ => {},
        }
    }

    /// Make syntactic/unknown parts of this type unqualified (remove
    /// all but last segment from all names), and normalize C2RustUnnamed_..
    pub fn make_syntactic_unqual(&mut self) {
        use Type::*;
        match self {
            Never | Opaque | Extern(_) | Struct(_) | Enum(_) | Union(_) | Str | Bool | Char
            | Int(_) | Uint(_) | Float(_) => {},
            OptionT(box inner) => inner.make_syntactic_unqual(),
            Tuple(inner) => inner.iter_mut().for_each(|t| t.make_syntactic_unqual()),
            Array(box inner, _) => inner.make_syntactic_unqual(),
            Slice(box inner) => inner.make_syntactic_unqual(),
            CustomSlice(_, box inner) => inner.make_syntactic_unqual(),
            RefCell(box inner) => inner.make_syntactic_unqual(),
            Fn(sig) => {
                sig.param_types
                    .iter_mut()
                    .for_each(|t| t.make_syntactic_unqual());
                sig.ret_type.make_syntactic_unqual();
            },
            Ptr(_, box inner) => inner.make_syntactic_unqual(),
            Ref(_, _, box inner) => inner.make_syntactic_unqual(),
            Boxed(box inner) => inner.make_syntactic_unqual(),
            Unknown(segments) => {
                let mut last = segments.pop().unwrap();
                if last.name.as_ref().starts_with("C2RustUnnamed") {
                    last.name = Name::from("C2RustUnnamed");
                }
                segments.clear();
                segments.push(last);
            },
            Syntactic(segments) => {
                let mut last = segments.pop().unwrap();
                if last.name.as_ref().starts_with("C2RustUnnamed") {
                    last.name = Name::from("C2RustUnnamed");
                }
                segments.clear();
                segments.push(last);
            },
            App(box inner, _) => inner.make_syntactic_unqual(),
        }
    }

    /// Get pointee type if this is a pointer/box/reference
    pub fn get_pointee(&self) -> Option<&Type> {
        use Type::*;
        match self {
            OptionT(box inner) => inner.get_pointee(),
            Array(box inner, _) => Some(inner),
            Slice(box inner) => Some(inner),
            Ptr(_, box inner) => Some(inner),
            Ref(_, _, box inner) => Some(inner),
            Boxed(box inner) => Some(inner),
            App(box inner, _) => inner.get_pointee(),
            _ => None,
        }
    }

    /// Returns a string representing the type constructor/kind
    pub fn ctor_string(&self) -> &'static str {
        use Type::*;
        match self {
            Bool => "Bool",
            Char => "Char",
            Int(..) => "Int(..)",
            Uint(..) => "Uint(..)",
            Float(..) => "Float(..)",
            Struct(..) => "Struct(..)",
            Enum(..) => "Enum(..)",
            Union(..) => "Union(..)",
            Str => "Str",
            OptionT(..) => "OptionT(..)",
            Tuple(..) => "Tuple(..)",
            Array(..) => "Array(..)",
            Slice(..) => "Slice(..)",
            CustomSlice(..) => "CustomSlice(..)",
            RefCell(..) => "RefCell(..)",
            Fn(..) => "Fn(..)",
            Never => "Never",
            Ptr(..) => "Ptr(..)",
            Ref(..) => "Ref(..)",
            Boxed(..) => "Boxed(..)",
            Opaque => "Opaque",
            Unknown(..) => "Unknown(..)",
            Syntactic(..) => "Syntactic(..)",
            App(..) => "App(..)",
            Extern(..) => "Extern(..)",
        }
    }

    /// Substitute free lifetime variables. It tries the given map
    /// then the given default substitution.
    pub fn sub_free_lifetime_vars(
        &self,
        sub_map: &HashMap<Lifetime, Lifetime>,
        default_sub: Option<&Lifetime>,
    ) -> Type {
        use Type::*;
        let f = |t: &Type| t.sub_free_lifetime_vars(sub_map, default_sub);
        let fb = |t: &Box<Type>| Box::new(f(&**t));
        let sub_lv = |lv: &Lifetime| {
            sub_map
                .get(lv)
                .or(default_sub)
                .cloned()
                .unwrap_or(lv.clone())
        };
        match self {
            OptionT(inner) => OptionT(fb(inner)),
            Tuple(inner) => Tuple(inner.iter().map(f).collect()),
            Array(inner, size) => Array(fb(inner), size.clone()),
            Slice(inner) => Slice(fb(inner)),
            CustomSlice(slice_t, inner) => {
                use CustomSliceType::*;
                let new_slice_t = match slice_t {
                    Ref(lv, cell_kind) => Ref(sub_lv(lv), *cell_kind),
                    RefMut(lv) => RefMut(sub_lv(lv)),
                    Boxed(_) | Array(_, _) => slice_t.clone(),
                };
                CustomSlice(new_slice_t, fb(inner))
            },
            RefCell(inner) => RefCell(fb(inner)),
            Fn(sig) => {
                let mut result = sig.clone();
                // TODO: check for free variables here and refine the map & add a map for bound variables
                result.param_types.iter_mut().for_each(|t| *t = f(t));
                result.ret_type = fb(&result.ret_type);
                Fn(result)
            },
            Ptr(mutbl, inner) => Ptr(*mutbl, fb(inner)),
            Ref(mutbl, lv, inner) => Ref(*mutbl, sub_lv(lv), fb(inner)),
            Boxed(inner) => Boxed(fb(inner)),
            App(inner, lifetime_vars) => App(fb(inner), lifetime_vars.iter().map(sub_lv).collect()),
            Bool | Char | Int(..) | Uint(..) | Float(..) | Struct(..) | Enum(..) | Union(..)
            | Str | Never | Opaque | Unknown(..) | Syntactic(..) | Extern(..) => self.clone(),
        }
    }

    /// Is this type a constant pointer or reference (potentially wrapped in Option)
    pub fn is_const_ptr(&self) -> bool {
        use Type::*;
        match self {
            Ptr(Mutability::Not, _) => true,
            Ref(Mutability::Not, ..) | CustomSlice(CustomSliceType::Ref(..), ..) => true,
            OptionT(inner) => inner.is_const_ptr(),
            App(inner, _) => inner.is_const_ptr(),
            _ => false,
        }
    }

    /// Is this type a mutable pointer or reference (potentially wrapped in Option)
    pub fn is_mut_ptr(&self) -> bool {
        use Type::*;
        match self {
            Ptr(Mutability::Mut, _)
            | Ref(Mutability::Mut, ..)
            | CustomSlice(CustomSliceType::RefMut(..), ..) => true,
            OptionT(inner) => inner.is_mut_ptr(),
            App(inner, _) => inner.is_mut_ptr(),
            _ => false,
        }
    }

    /// Is this type a box potentially inside optionals
    pub fn is_box(&self) -> bool {
        match self {
            Type::Boxed(..) => true,
            Type::OptionT(inner) => inner.is_box(),
            Type::App(inner, _) => inner.is_box(),
            _ => false,
        }
    }

    /// Is this type an array, box, reference, or pointer potentially inside optionals
    pub fn is_ptr_like(&self) -> bool {
        matches!(
            self.peel_option_and_app(),
            Type::Array(..)
                | Type::Boxed(..)
                | Type::Ptr(..)
                | Type::Ref(..)
                | Type::CustomSlice(..)
        )
    }

    pub fn peel_array(&self) -> &Type {
        match self {
            Type::Array(box inner, _) => inner.peel_array(),
            _ => self,
        }
    }

    pub fn peel_option(&self) -> &Type {
        match self {
            Type::OptionT(box inner) => inner.peel_option(),
            _ => self,
        }
    }

    pub fn peel_option_and_app(&self) -> &Type {
        match self {
            Type::OptionT(box inner) => inner.peel_option_and_app(),
            Type::App(box inner, _) => inner.peel_option_and_app(),
            _ => self,
        }
    }

    /// Is this type an unsafe (raw) pointer
    pub fn is_unsafe_ptr(&self) -> bool {
        matches!(self, Type::Ptr(..))
    }

    /// Is this type a function pointer (potentially wrapped in Option)
    pub fn is_fn(&self) -> bool {
        match self {
            Type::OptionT(inner) => inner.is_fn(),
            Type::Fn(_) => true,
            _ => false,
        }
    }

    /// Is this type a mutable reference (potentially wrapped in Option)
    pub fn is_mut_ref(&self) -> bool {
        self.is_mut_ptr() && !matches!(self, Type::Ptr(..))
    }

    /// Convert this type to a constant reference if it is a mutable reference
    pub fn as_const_ref(self) -> Type {
        use Type::*;
        match self {
            Ptr(Mutability::Not, inner) => Ptr(Mutability::Not, inner),
            Ref(Mutability::Mut, l, inner) => Ref(Mutability::Not, l, inner),
            CustomSlice(CustomSliceType::RefMut(lv), inner) => {
                CustomSlice(CustomSliceType::Ref(lv, CustomSliceCell::NoCell), inner)
            },
            OptionT(inner) => OptionT(Box::new(inner.as_const_ref())),
            App(inner, args) => App(Box::new(inner.as_const_ref()), args),
            _ => self,
        }
    }

    /// Whether this is a (non-pointer) primitive type. A primitive
    /// type is a non-reference type that does not contain other types
    /// inside (either directly or indirectly as in structs). Or, it
    /// is an option containing a primitive.
    pub fn is_primitive(&self) -> bool {
        use Type::*;
        match self {
            Bool | Char | Int(..) | Uint(..) | Float(..) | Str | Never | Opaque => true,
            OptionT(box t1) => t1.is_primitive(),
            Unknown(name) if name.len() == 1 => PRIMITIVE_TYPES.contains(&name[0].name),
            _ => false,
        }
    }

    /// Is this type known to implement the Copy trait (without querying the
    /// compiler)
    pub fn is_known_copyable(&self) -> bool {
        use Type::*;
        match self {
            OptionT(box t1) => t1.is_known_copyable(),
            Fn(..) | Ptr(..) | Ref(Mutability::Not, _, _) => true,
            App(box inner, _) => inner.is_known_copyable(),
            s => s.is_primitive(),
        }
    }
}
