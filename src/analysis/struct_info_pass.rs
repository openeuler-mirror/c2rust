//! This module contains the analysis pass for computing struct info and
//! propagating extern poisons along struct occurrence graph.

use crate::{
    analysis,
    analysis::commons::{Node, *},
    compiler_interface::*,
    constants::is_laertes_helper,
    ptr_provenance::*,
    rustc_hir,
    rustc_hir::{def_id::LOCAL_CRATE, intravisit::FnKind, Generics, *},
    rustc_lint::{LateContext, LateLintPass, LintPass},
    rustc_span::Span,
    types::{FnSig, Lifetime, *},
    util::HashSet,
};
use std::{panic, sync::atomic::Ordering};

/// A pass to discover points-to relations between structs and use of
/// structs and fields in different contexts.
pub struct StructInfoPass {
    info: StructInfo,
    ptr_provenance: PtrProvenanceAnalysis,
    /// Call graph built by pointer provenance
    call_graph: CallGraph,
    /// *Syntactic* function pointer types seen in the program, used
    /// for marking the types inside them as used in external APIs.
    fn_ptr_types: Vec<Type>,
    /// *Syntactic* extern variable types seen in the program, used
    /// for marking the types inside them as used in external APIs.
    extern_var_types: Vec<Type>,
    /// *Syntactic* types that are union variants, because we do not
    /// rewrite unions, we cannot rewrite any structs that occur
    /// within these types after resolving syntactic types.
    unresolved_union_variants: HashSet<Type>,
}

impl StructInfoPass {
    pub fn new() -> Box<LatePass> {
        Box::new(StructInfoPass {
            info: StructInfo::new(),
            ptr_provenance: analysis::result::<PtrProvenanceAnalysis>().unwrap(),
            call_graph: analysis::result::<CallGraph>().unwrap(),
            fn_ptr_types: Vec::new(),
            extern_var_types: Vec::new(),
            unresolved_union_variants: HashSet::default(),
        })
    }

    fn process_union(
        &mut self,
        ctx: &LateContext,
        name: Name,
        fields: &[FieldDef],
        generics: &Generics,
    ) {
        if !generics.params.is_empty() {
            panic!(
                "Cannot process unions with generics or lifetimes, they are not in our formalism: union `{}` at {:?}",
                name, generics.span
            )
        }

        // We don't rewrite unions, so remember the fields as
        // occurring inside unions to make the structs inside unions
        // also frozen.
        self.unresolved_union_variants
            .extend(fields.iter().map(|field| Type::from_hir_ty(ctx, field.ty)));

        let s = self.process_struct_or_union(ctx, &name, fields, generics);
        self.info.union_defs.insert(name, s);
    }

    fn process_struct(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        fields: &[FieldDef<'_>],
        generics: &Generics<'_>,
    ) {
        let s = self.process_struct_or_union(ctx, &name, fields, generics);
        self.info.struct_defs.insert(name, s);
    }

    // Build a Struct for a given union or struct
    fn process_struct_or_union(
        &mut self,
        ctx: &LateContext<'_>,
        name: &Name,
        fields: &[FieldDef<'_>],
        generics: &Generics<'_>,
    ) -> Struct {
        let mut lifetime_bounds = Vec::new();
        // types that start with '__' are internal names. Mark this struct as occurring in external APIs
        if !LIMIT_STUDY.load(Ordering::Relaxed)
            && name.rsplit_once("::").unwrap().1.starts_with("__")
        {
            self.info
                .occurs_in_external_apis
                .insert(Node::Struct(name.clone()));
        }

        let mut process_bounds = |lhs: &Name, generic_bounds: GenericBounds| {
            for bound in generic_bounds {
                match bound {
                    GenericBound::Outlives(rhs) => {
                        if let Some(rhs) = extract_lifetime_name(&rhs.name) {
                            lifetime_bounds.push((lhs.clone(), rhs))
                        }
                    },
                    _ => panic!("Unsupported generic bound in struct {}", name),
                }
            }
        };

        // verify & extract generics
        let lifetime_quals = generics
            .params
            .iter()
            .map(|param| match &param.kind {
                GenericParamKind::Lifetime { .. } => {
                    let param_name = Name::from(&*param.name.ident().name.as_str());

                    process_bounds(&param_name, &param.bounds);
                    param_name
                },
                _ => panic!("found non-lifetime generics parameter in struct {}", name),
            })
            .collect::<Vec<Lifetime>>();

        // extract bounds from side constraints
        for predicate in generics.where_clause.predicates {
            use WherePredicate::*;
            match predicate {
                RegionPredicate(pred) => {
                    if let Some(lhs) = extract_lifetime_name(&pred.lifetime.name) {
                        process_bounds(&lhs, &pred.bounds);
                    }
                },
                BoundPredicate(..) => {},
                _ => panic!(
                    "found unsupported where predicate in struct {} at {:?}",
                    name,
                    predicate.span()
                ),
            }
        }

        // process fields
        let fields = fields
            .iter()
            .map(|field| {
                let field_name = Name::from(&*field.ident.name.as_str());

                // Because typeck results are not available outside
                // bodies, we are using syntactic types to construct the
                // type of this field.
                let field_ty = Type::from_hir_ty(ctx, field.ty);

                (field_name, field_ty)
            })
            .collect();

        Struct {
            name: name.clone(),
            lifetime_quals: lifetime_quals,
            lifetime_bounds: lifetime_bounds,
            fields: fields,
        }
    }

    fn process_enum(&mut self, name: Name, _enum_def: &EnumDef<'_>, _generics: &Generics<'_>) {
        if !is_laertes_helper(&name) {
            todo!();
        }
    }

    fn process_typedef(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        ty: &rustc_hir::Ty<'_>,
        _generics: &Generics<'_>,
    ) {
        /*assert!(
            generics.params.is_empty(),
            "typedef has generics at {:?}",
            ty.span
        );*/
        self.info.type_defs.insert(name, Type::from_hir_ty(ctx, ty));
    }

    fn process_fn(
        &mut self,
        ctx: &LateContext<'_>,
        name: Name,
        fn_decl: &FnDecl<'_>,
        generics: &Generics<'_>,
        unsafety: Unsafety,
        is_foreign: bool,
    ) {
        let mut lifetime_bounds = Vec::new();

        // Extract existing lifetime bounds of a given lifetime from
        // the program
        let mut process_bounds = |lhs: &Name, generic_bounds: GenericBounds| {
            for bound in generic_bounds {
                match bound {
                    GenericBound::Outlives(rhs) => {
                        if let Some(rhs) = extract_lifetime_name(&rhs.name) {
                            lifetime_bounds.push((lhs.clone(), rhs))
                        }
                    },
                    _ => panic!("Unsupported generic bound in function {}", name),
                }
            }
        };

        // verify & extract generics
        let lifetime_quals = generics
            .params
            .iter()
            .map(|param| match &param.kind {
                GenericParamKind::Lifetime { .. } => {
                    let param_name = Name::from(&*param.name.ident().name.as_str());

                    process_bounds(&param_name, &param.bounds);
                    param_name
                },
                _ => panic!("found non-lifetime generics parameter in function {}", name),
            })
            .collect::<Vec<Lifetime>>();

        // extract bounds from side constraints
        for predicate in generics.where_clause.predicates {
            use WherePredicate::*;
            match predicate {
                RegionPredicate(pred) => {
                    if let Some(lhs) = extract_lifetime_name(&pred.lifetime.name) {
                        process_bounds(&lhs, &pred.bounds);
                    }
                },
                BoundPredicate(..) => {},
                _ => panic!(
                    "found unsupported where predicate in function {} at {:?}",
                    name,
                    predicate.span()
                ),
            }
        }

        let ret_type = match &fn_decl.output {
            FnRetTy::Return(ty) => Box::new(Type::from_hir_ty(ctx, ty)),
            FnRetTy::DefaultReturn(_) => {
                // since this function is not a closure, the default
                // return type is ()
                Box::new(Type::Tuple(vec![]))
            },
        };

        let param_types = fn_decl
            .inputs
            .iter()
            .map(|ty| Type::from_hir_ty(ctx, ty))
            .collect();

        let flavor = if is_foreign {
            FnFlavor::Extern
        } else if self.call_graph.used_as_fn_pointer.contains_key(&name) {
            FnFlavor::UsedAsFnPtr
        } else {
            FnFlavor::Normal
        };

        self.info.fn_sigs.insert(
            name,
            (
                FnSig {
                    unsafety: unsafety,
                    lifetime_quals: lifetime_quals,
                    lifetime_bounds: lifetime_bounds,
                    param_types: param_types,
                    ret_type: ret_type,
                    c_variadic: fn_decl.c_variadic,
                },
                flavor,
            ),
        );
    }
}

impl LintPass for StructInfoPass {
    fn name(&self) -> &'static str {
        "StructInfoPass"
    }
}

impl<'tcx> LateLintPass<'tcx> for StructInfoPass {
    fn check_item_post(&mut self, ctx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        // Get the name only when necessary.
        let name = || Name::from(get_hir_qname(ctx, item.hir_id()));

        match &item.kind {
            ItemKind::Enum(enum_def, generics) => {
                self.process_enum(name(), enum_def, generics);
            },
            ItemKind::Struct(data, generics) => {
                if !is_laertes_helper(&name()) {
                    self.process_struct(ctx, name(), data.fields(), generics);
                }
            },
            ItemKind::Union(data, generics) => {
                self.process_union(ctx, name(), data.fields(), generics);
            },
            ItemKind::TyAlias(ty, generics) => {
                self.process_typedef(ctx, name(), ty, generics);
            },
            _ => {}, // ignore other item kinds
        }
    }

    fn check_foreign_item_post(&mut self, ctx: &LateContext<'tcx>, item: &'tcx ForeignItem<'tcx>) {
        use ForeignItemKind::*;
        let name = || Name::from(get_hir_qname(ctx, item.hir_id()));

        match &item.kind {
            Fn(fn_decl, _param_names, generics) => {
                // process foreign function declarations
                self.process_fn(ctx, name(), fn_decl, generics, Unsafety::Unsafe, true);
            },
            Static(ty, _) => {
                // mark the type of this variable as used in extern APIs
                self.extern_var_types
                    .push(crate::types::Type::from_hir_ty(ctx, ty));
            },
            Type => {}, // skip foreign types, they will be marked unknown by the analysis
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
        // A function has a type, it also has parameters as part of
        // its body. For now, we do not touch parameters, but we may
        // need to modify them in later passes & we need to build a
        // local context out of variables that appear in parameter
        // patterns.

        // Get the name only when necessary.

        let name = || Name::from(get_hir_qname(ctx, hir_id));

        match kind {
            FnKind::ItemFn(_, generics, header, _) => {
                let name = name();
                // skip the bitfield helpers we added
                if !name.contains("::bitfields") && !is_laertes_helper(&name) {
                    self.process_fn(ctx, name, decl, generics, header.unsafety, false);
                }
            },
            FnKind::Method(..) if is_synthetic_fn(decl, body) => {
                log::info!("Skipping synthetic method {} at {:?}", name(), span)
            },
            FnKind::Method(..) => {
                let name = name();
                // skip the bitfield helpers we added
                // log::warn!("::bitfields-{:?}, ::xmlschemastypes-{:?}, is_laertes_helper-{:?}, ::default-{:?}, ::new-{:?}", !name.contains("::bitfields"), !name.contains("::xmlschemastypes"), !is_laertes_helper(&name), !name.ends_with("::default"), !name.ends_with("::new"));
                // if !name.contains("::bitfields")
                //     && !name.contains("::xmlschemastypes")
                //     && !is_laertes_helper(&name)
                //     && !name.ends_with("::default")
                //     && !name.ends_with("::new")
                // {
                //     todo!("methods are not processed yet: {:?}", decl);
                // }
                if name.contains("::bitfields")
                    // || name.contains("::xmlschemastypes")
                    || is_laertes_helper(&name)
                    || name.ends_with("::default")
                    || name.ends_with("::new")
                {
                    todo!("methods are not processed yet: {:?}", decl);
                }
            },
            FnKind::Closure => log::warn!("closures are not supported"),
        }
    }

    fn check_ty(&mut self, ctx: &LateContext<'tcx>, ty: &'tcx rustc_hir::Ty<'tcx>) {
        if matches!(ty.kind, TyKind::BareFn(..)) {
            // This is a function pointer, remember it.
            self.fn_ptr_types.push(Type::from_hir_ty(ctx, ty))
        }
    }

    fn check_crate(&mut self, ctx: &LateContext<'tcx>) {
        *CRATE_NAME.lock().unwrap() = Name::from(ctx.tcx.crate_name(LOCAL_CRATE).to_string());
    }

    fn check_crate_post(&mut self, _: &LateContext<'tcx>) {
        self.info.resolve_syntactic_types();

        // generate dummy locations for each struct field
        for (name, strukt) in &self.info.struct_defs {
            for (field_name, field_ty) in &strukt.fields {
                self.ptr_provenance.create_dummy_locs(
                    Loc::Access(name.clone(), field_name.clone()),
                    &field_ty,
                    true,
                );
            }
        }

        // Insert types used in unions as used in external types
        let info = &self.info;
        let occurs_in_union = self
            .unresolved_union_variants
            .iter()
            .flat_map(|t| info.resolve_type(t).collect_structs())
            .map(Node::Struct)
            .collect::<HashSet<Node>>();
        self.info.occurs_in_external_apis.extend(occurs_in_union);

        self.ptr_provenance
            .solve()
            .expect("Solving taint analysis failed");

        self.info.compute_struct_dependencies(&self.ptr_provenance);

        if POISON_SIGS_OF_FN_PTRS.load(Ordering::Relaxed) {
            self.extern_var_types
                .extend(self.fn_ptr_types.iter().map(Clone::clone));
        }

        self.info
            .compute_occurs_in_external_apis(&self.extern_var_types);
        log::debug!(
            "occurs in extern after prop: {:#?}",
            self.info
                .occurs_in_external_apis
                .iter()
                .collect::<std::collections::BTreeSet<&Node>>()
        );

        // Update analysis results
        analysis::replace::<StructInfo>(Box::new(std::mem::replace(
            &mut self.info.clone(),
            StructInfo::new(),
        )));
        analysis::replace::<PtrProvenanceAnalysis>(Box::new(std::mem::replace(
            &mut self.ptr_provenance,
            PtrProvenanceAnalysis::new(),
        )));
    }
}
