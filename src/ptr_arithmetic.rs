use crate::{ptr_provenance::PoisonKind, util::HashSet};
use lazy_static::lazy_static;
use rustc_hir::{def_id::DefId, Expr, ExprKind, QPath};
use rustc_lint::LateContext;
use rustc_middle::ty::TyKind;
use rustc_span::Span;
use std::fmt::Debug;

#[derive(Debug)]
pub struct PtrArithExpr<'tcx> {
    pub op: PtrArithOp,
    pub lhs: &'tcx Expr<'tcx>,
    pub rhs: Option<&'tcx Expr<'tcx>>,
}

#[derive(Debug, Clone, Copy)]
pub struct PtrArithOp {
    /// If possible, indicates if the original fn was a mutable variant
    pub is_mut: Option<bool>,
    pub ty: PtrArithOpType,
}

#[derive(Debug, Clone, Copy)]
pub enum PtrArithOpType {
    Add {
        mode: PointerAddMode,
        wrap: bool,
    },
    /// Safe indexing into a Rust slice.  Necessary due to potential rewrites of
    /// safe operations.
    AddSafe,
    OffsetFrom,
    AlignOffset,
    SliceAsPtr {
        is_range: bool,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum PointerAddMode {
    Signed,
    Add,
    Sub,
}

fn get_def_path_late(ctx: &LateContext, def_id: DefId) -> Vec<String> {
    ctx.get_def_path(def_id)
        .iter()
        .map(|seg| seg.to_string())
        .collect()
}

pub fn parse_path<I: IntoIterator<Item = S>, S: AsRef<str> + Debug>(
    fn_path: I,
) -> Option<PtrArithOp>
where
    I::IntoIter: Clone,
{
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ImplTy {
        ConstPtr,
        MutPtr,
        Slice,
        Vec,
    }

    fn cmp<
        I: Iterator<Item = S>,
        J: IntoIterator<Item = T>,
        S: AsRef<str> + Debug,
        T: AsRef<str> + Debug,
    >(
        it: &mut I,
        it2: J,
    ) -> bool
    where
        I: Clone,
    {
        let mut it_clone = it.clone();

        for t in it2 {
            let s = it_clone.next();

            log::trace!("{:?} ==? {:?}", s, t);
            match s {
                None => return false,
                Some(s) if s.as_ref() != t.as_ref() => return false,
                _ => (),
            }
        }

        *it = it_clone;

        true
    }

    let mut it = fn_path.into_iter();
    let mut impl_ty = None;

    for (parts, ty) in &[
        (
            &["core", "ptr", "const_ptr", "<impl *const T>"] as &[&str],
            ImplTy::ConstPtr,
        ),
        (&["core", "ptr", "mut_ptr", "<impl *mut T>"], ImplTy::MutPtr),
        (&["core", "slice", "<impl [T]>"], ImplTy::Slice),
        (&["alloc", "vec", "Vec"], ImplTy::Vec),
    ] {
        if cmp(&mut it, *parts) {
            impl_ty = Some(*ty);
            break;
        }
    }

    let impl_ty = match impl_ty {
        Some(i) => i,
        None => return None,
    };

    let name = match it.next() {
        Some(n) => n,
        None => return None,
    };

    if let Some(part) = it.next() {
        log::debug!("Extraneous path segment {:?}", part);
        return None;
    }

    let name = name.as_ref();

    match impl_ty {
        ImplTy::ConstPtr | ImplTy::MutPtr => [
            (
                "add",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Add,
                    wrap: false,
                },
            ),
            ("align_offset", PtrArithOpType::AlignOffset),
            (
                "offset",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Signed,
                    wrap: false,
                },
            ),
            ("offset_from", PtrArithOpType::OffsetFrom),
            (
                "sub",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Sub,
                    wrap: false,
                },
            ),
            (
                "wrapping_add",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Add,
                    wrap: true,
                },
            ),
            (
                "wrapping_offset",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Signed,
                    wrap: true,
                },
            ),
            (
                "wrapping_sub",
                PtrArithOpType::Add {
                    mode: PointerAddMode::Sub,
                    wrap: true,
                },
            ),
        ]
        .iter()
        .find_map(|(path, op)| {
            log::trace!("{:?} ==? {:?}", name, path);

            if *path == name {
                Some(PtrArithOp {
                    is_mut: Some(impl_ty == ImplTy::MutPtr),
                    ty: *op,
                })
            } else {
                None
            }
        }),
        ImplTy::Slice => [
            (
                "as_ptr",
                PtrArithOpType::SliceAsPtr { is_range: false },
                false,
            ),
            (
                "as_ptr_range",
                PtrArithOpType::SliceAsPtr { is_range: true },
                false,
            ),
            (
                "as_mut_ptr",
                PtrArithOpType::SliceAsPtr { is_range: false },
                true,
            ),
            (
                "as_mut_ptr_range",
                PtrArithOpType::SliceAsPtr { is_range: true },
                true,
            ),
        ]
        .iter()
        .find_map(|(path, op, is_mut)| {
            log::trace!("{:?} ==? {:?}", name, path);

            if *path == name {
                Some(PtrArithOp {
                    is_mut: Some(*is_mut),
                    ty: *op,
                })
            } else {
                None
            }
        }),
        ImplTy::Vec => [
            (
                "as_ptr",
                PtrArithOpType::SliceAsPtr { is_range: false },
                false,
            ),
            (
                "as_mut_ptr",
                PtrArithOpType::SliceAsPtr { is_range: false },
                true,
            ),
        ]
        .iter()
        .find_map(|(path, op, is_mut)| {
            log::trace!("{:?} ==? {:?}", name, path);

            if *path == name {
                Some(PtrArithOp {
                    is_mut: Some(*is_mut),
                    ty: *op,
                })
            } else {
                None
            }
        }),
    }
}

fn get_args<'tcx>(
    args: &'tcx [Expr<'tcx>],
) -> Option<(&'tcx Expr<'tcx>, Option<&'tcx Expr<'tcx>>)> {
    match args {
        [lhs] => Some((lhs, None)),
        [lhs, rhs] => Some((lhs, Some(rhs))),
        _ => None,
    }
}

/// Returns the pointer operation kind and operands for a Call expression
pub fn parse_call_late<'tcx>(
    ctx: &LateContext,
    fun: &Expr,
    args: &'tcx [Expr<'tcx>],
) -> Option<PtrArithExpr<'tcx>> {
    if let ExprKind::Path(QPath::Resolved(_, path)) = fun.kind {
        if let Some((lhs, rhs)) = get_args(args) {
            path.res.opt_def_id().and_then(|def_id| {
                parse_path(get_def_path_late(ctx, def_id)).map(|op| PtrArithExpr { op, lhs, rhs })
            })
        } else {
            None
        }
    } else {
        None
    }
}

/// Returns the pointer operation kind and operands for a MethodCall expression
pub fn parse_method_call_late<'tcx>(
    ctx: &LateContext,
    expr: &Expr,
    args: &'tcx [Expr<'tcx>],
) -> Option<PtrArithExpr<'tcx>> {
    assert!(matches!(expr.kind, ExprKind::MethodCall(..)));

    if let Some((lhs, rhs)) = get_args(args) {
        ctx.typeck_results()
            .type_dependent_def_id(expr.hir_id)
            .and_then(|def_id| {
                parse_path(get_def_path_late(ctx, def_id)).map(|op| PtrArithExpr { op, lhs, rhs })
            })
    } else {
        log::warn!(
            "Skipping arithmetic method call at {:?} due to argument mismatch",
            expr.span
        );

        None
    }
}

pub fn parse_index_late<'tcx>(
    ctx: &LateContext,
    array: &'tcx Expr<'tcx>,
    index: &'tcx Expr<'tcx>,
) -> Option<PtrArithExpr<'tcx>> {
    fn is_slice(kind: &TyKind, span: Span) -> bool {
        match kind {
            TyKind::Slice(_) | TyKind::Array(_, _) => true,
            TyKind::Ref(_, t, _) => is_slice(t.kind(), span),
            _ => {
                log::warn!(
                    "Skipping index expression at {:?} due to array type mismach",
                    span
                );
                false
            },
        }
    }

    if is_slice(
        ctx.typeck_results().expr_ty_adjusted(&array).kind(),
        array.span,
    ) {
        Some(PtrArithExpr {
            op: PtrArithOp {
                ty: PtrArithOpType::AddSafe,
                is_mut: None,
            },
            lhs: array,
            rhs: Some(index),
        })
    } else {
        None
    }
}

/// Returns the pointer operation kind, and the spans of the left- and right-hand operands
pub fn parse_expr_late<'tcx>(
    ctx: &LateContext,
    expr: &'tcx Expr<'tcx>,
) -> Option<PtrArithExpr<'tcx>> {
    match expr.kind {
        ExprKind::Call(fun, args) => parse_call_late(ctx, fun, args),
        ExprKind::MethodCall(_, _, args, _) => parse_method_call_late(ctx, expr, args),
        ExprKind::Index(array, index) => parse_index_late(ctx, array, index),
        _ => None,
    }
}

pub fn is_unique_poison((src, snk): (HashSet<PoisonKind>, HashSet<PoisonKind>)) -> bool {
    lazy_static! {
        static ref SOURCE: HashSet<PoisonKind> = vec![PoisonKind::PtrArith].into_iter().collect();
        static ref SINK: HashSet<PoisonKind> = vec![PoisonKind::PtrArithSink].into_iter().collect();
    }

    if src.is_empty() {
        snk == *SINK
    } else if src == *SOURCE {
        snk.is_empty() || snk == *SINK
    } else {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    macro_rules! hs {
        ($($tt:tt)*) => ({
            let hs: HashSet<_> = vec![$($tt)*].into_iter().collect();
            hs
        })
    }

    #[test]
    fn test_is_poison() {
        fn p(src: &HashSet<PoisonKind>, snk: &HashSet<PoisonKind>) -> bool {
            is_unique_poison((src.clone(), snk.clone()))
        }

        let empty = hs![];

        let bad_src = hs![PoisonKind::MiscSource];
        let good_src = hs![PoisonKind::PtrArith];
        let extra_src = hs![PoisonKind::PtrArith, PoisonKind::MiscSource];

        let bad_snk = hs![PoisonKind::MiscSink];
        let good_snk = hs![PoisonKind::PtrArithSink];
        let extra_snk = hs![PoisonKind::PtrArithSink, PoisonKind::MiscSink];

        assert!(!p(&empty, &empty));
        assert!(!p(&empty, &bad_snk));
        assert!(p(&empty, &good_snk));
        assert!(!p(&empty, &extra_snk));

        assert!(!p(&bad_src, &empty));
        assert!(!p(&bad_src, &bad_snk));
        assert!(!p(&bad_src, &good_snk));
        assert!(!p(&bad_src, &extra_snk));

        assert!(p(&good_src, &empty));
        assert!(!p(&good_src, &bad_snk));
        assert!(p(&good_src, &good_snk));
        assert!(!p(&good_src, &extra_snk));

        assert!(!p(&extra_src, &empty));
        assert!(!p(&extra_src, &bad_snk));
        assert!(!p(&extra_src, &good_snk));
        assert!(!p(&extra_src, &extra_snk));
    }
}
