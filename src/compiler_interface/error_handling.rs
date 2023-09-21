//! Compiler error parsing and handling to generate fixes

use crate::{
    analysis,
    analysis::{commons::StructInfo, span::*},
    colored::*,
    config::*,
    ptr_provenance::{FlowLoc, Loc, PtrProvenanceAnalysis},
    rustc_ast::Mutability,
    types::{CustomSliceType, Lifetime, Name, Type},
    util::HashSet,
};
use regex::Regex;
use serde::Deserialize;

#[derive(Clone, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct Diagnostic {
    /// The primary error message.
    pub message: String,
    pub code: Option<DiagnosticCode>,
    /// "error: internal compiler error", "error", "warning", "note", "help".
    level: String,
    pub spans: Vec<DiagnosticSpan>,
    /// Associated diagnostic messages.
    pub children: Vec<Diagnostic>,
    /// The message as rustc would render it. Currently this is only
    /// `Some` for "suggestions", but eventually it will include all
    /// snippets.
    pub rendered: Option<String>,
}

impl Diagnostic {
    pub fn pretty_print(&self, level: usize) {
        let indentation = " ".repeat(level * 2);
        let error_code = if let Some(ref code) = self.code {
            format!("[{}]", code.code.red())
        } else {
            "[E???]: Unknown error code".to_owned()
        };
        println!("{}{}", indentation, error_code);
        println!("{}{}", indentation, self.message.blue().bold());
        for s in &self.spans {
            s.pretty_print(level);
        }
        for c in &self.children {
            c.pretty_print(level + 1);
        }
    }
}

#[derive(Clone, Deserialize, Debug, Hash, Eq, PartialEq)]
pub struct DiagnosticSpan {
    pub file_name: String,
    pub byte_start: u32,
    pub byte_end: u32,
    /// 1-based.
    pub line_start: usize,
    pub line_end: usize,
    /// 1-based, character offset.
    pub column_start: usize,
    pub column_end: usize,
    /// Is this a "primary" span -- meaning the point, or one of the points,
    /// where the error occurred?
    is_primary: bool,
    /// Source text from the start of line_start to the end of line_end.
    pub text: Vec<DiagnosticSpanLine>,
    /// Label that should be placed at this location (if any)
    label: Option<String>,
    /// If we are suggesting a replacement, this will contain text
    /// that should be sliced in atop this span. You may prefer to
    /// load the fully rendered version from the parent `Diagnostic`,
    /// however.
    pub suggested_replacement: Option<String>,
    pub suggestion_applicability: Option<Applicability>,
    /// Macro invocations that created the code at this span, if any.
    expansion: Option<Box<DiagnosticSpanMacroExpansion>>,
}

impl DiagnosticSpan {
    pub fn to_fat_span(&self) -> FatSpan {
        FatSpan {
            file_name: Name::from(self.file_name.as_str()),
            begin: self.byte_start as u32,
            // subtract 1 because FatSpan is an inclusive range.
            end: self.byte_end - 1 as u32,
        }
    }

    pub fn pretty_print(&self, level: usize) {
        println!(
            "{}Error label {:?} at {}:{}:{}-{}:{}",
            " ".repeat(level * 2),
            self.label,
            self.file_name,
            self.line_start,
            self.column_start,
            self.line_end,
            self.column_end
        );
        self.text.iter().for_each(|l| l.pretty_print(level));
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Deserialize, Hash, Eq)]
pub enum Applicability {
    MachineApplicable,
    HasPlaceholders,
    MaybeIncorrect,
    Unspecified,
}

#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Hash)]
pub struct DiagnosticSpanLine {
    pub text: String,

    /// 1-based, character offset in self.text.
    pub highlight_start: usize,

    pub highlight_end: usize,
}

impl DiagnosticSpanLine {
    // pretty print this span with highlighting
    pub fn pretty_print(&self, level: usize) {
        let indentation = " ".repeat(level);
        println!("{}{}", indentation, self.text);
        println!(
            "{}{}{}",
            indentation,
            " ".repeat(self.highlight_start - 1),
            "^".repeat(self.highlight_end - self.highlight_start)
                .bold()
                .red(),
        );
    }
}

#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Hash)]
struct DiagnosticSpanMacroExpansion {
    /// span where macro was applied to generate this code; note that
    /// this may itself derive from a macro (if
    /// `span.expansion.is_some()`)
    span: DiagnosticSpan,

    /// name of macro that was applied (e.g., "foo!" or "#[derive(Eq)]")
    macro_decl_name: String,

    /// span where macro was defined (if known)
    def_site_span: Option<DiagnosticSpan>,
}

#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Hash)]
pub struct DiagnosticCode {
    /// The code itself.
    pub code: String,
    /// An explanation for the code.
    explanation: Option<String>,
}

#[derive(Debug)]
pub struct ErrorHandlingOpts {
    /// Set to true to allow promoting slices to slices of RefCells.
    pub promote_refslice: bool,
}

/// Collect locations of all pointers/references/arrays that are strored in the
/// given struct (including the ones that occur transitively).
pub fn collect_ptr_locs(
    struct_info: &StructInfo,
    ptr_provenance: &PtrProvenanceAnalysis,
    typ: &Type,
    loc: HashSet<Loc<Name>>,
    result: &mut HashSet<Loc<Name>>,
) {
    use Type::*;

    let recurse_on_points_to = |inner, result| {
        let inner_locs = loc
            .iter()
            .flat_map(|l| ptr_provenance.points_to(l).into_iter().map(|l| l.clone()))
            .collect();
        collect_ptr_locs(struct_info, ptr_provenance, inner, inner_locs, result);
    };

    match typ {
        Ref(Mutability::Mut, _, _) => {
            result.extend(loc);
        },
        Ptr(mutbl, _) => {
            if matches!(mutbl, Mutability::Mut) || ptr_provenance.is_any_owned(loc.iter()) {
                result.extend(loc);
            }
        },
        App(box inner, _) | OptionT(box inner) => {
            collect_ptr_locs(struct_info, ptr_provenance, inner, loc, result)
        },
        Array(box inner, _) => {
            // let possible_ptr = inner.peel_array();
            recurse_on_points_to(inner, result);
        },
        CustomSlice(cs_type, inner) => {
            use CustomSliceType::*;
            match cs_type {
                Ref(..) | RefMut(..) | Boxed(..) => result.extend(loc),
                Array(_, _) => recurse_on_points_to(inner, result),
            }
        },
        Struct(struct_name) => {
            for (field, typ) in struct_info.struct_defs[struct_name].fields.iter() {
                collect_ptr_locs(
                    struct_info,
                    ptr_provenance,
                    typ,
                    Some(Loc::Access(struct_name.clone(), field.clone()))
                        .into_iter()
                        .collect(),
                    result,
                );
            }
        },
        Unknown(_) | Union(_) | Never | Fn(_) => {},
        _ if typ.is_primitive() => {},
        _ => unreachable!(),
    }
}

pub fn generate_fixes(
    compiler_errors: &str,
    opts: &ErrorHandlingOpts,
    old_config: &Configuration,
) -> Configuration {
    let ErrorHandlingOpts { promote_refslice } = *opts;

    let _promote_borrow_issue = || {};

    let refcell_kind = if promote_refslice {
        PtrKind::RefCell
    } else {
        PtrKind::Raw
    };

    let refcell_promoted_kind = |loc| {
        if let Some(old_kind) = old_config.ptr_kind.get(loc) {
            if refcell_kind <= *old_kind {
                // the previous kind already subsumes the refcell kind, promote to raw
                PtrKind::Raw
            } else {
                refcell_kind
            }
        } else {
            refcell_kind
        }
    };

    // parse the compiler errors using a serializable version of rustc
    // `Diagnostic`.
    let diagnostics = serde_json::Deserializer::from_str(compiler_errors).into_iter::<Diagnostic>();
    let mut cfg = Configuration::default();

    //-- Some constructs we need while processing all diagnostics
    // Borrow the edit offsets
    let edit_offsets = EDIT_OFFSETS.lock().unwrap();
    // Regexes for extracting lifetimes from error messages for missing lifetime constraints
    let lower_re =
        Regex::new(r"the lifetime `(?P<lifetime>'[a-zA-Z0-9_]+)` as defined .*").unwrap();
    let upper_re = Regex::new(
        r"...does not necessarily outlive the lifetime `(?P<lifetime>'[a-zA-Z0-9_]+)` as defined .*",
    )
    .unwrap();
    let lower_re_495 = Regex::new(
        r".*the lifetime cannot outlive the lifetime `(?P<lifetime>'[a-zA-Z0-9_]+)` as defined .*",
    )
    .unwrap();
    let upper_re_495 = Regex::new(
        r".*the lifetime must (also )?be valid for the lifetime `(?P<lifetime>'[a-zA-Z0-9_]+)` as defined .*",
    )
    .unwrap();
    let lifetime_arg_list =
        Regex::new(r"<(?P<lifetime_list>'[a-zA-Z0-9_]+(, '[a-zA-Z0-9_]+)*)>").unwrap();
    let lifetime_after_borrow = Regex::new(r"&(?P<lifetime>'[a-zA-Z0-9_]+)[^a-zA-Z0-9]").unwrap();
    let lifetime_constraint_re =
        Regex::new("`(?P<lower>'[a-zA-Z0-9]+): (?P<upper>'[a-zA-Z0-9]+)`").unwrap();
    //-- End of constructs we need while processing all diagnostics

    // helper lambda to get the location and lifetime
    // from the entry with the matching regex that has
    // a capture named lifetime
    fn get_matching_lifetime_and_loc<'a>(
        re: &'a Regex,
    ) -> Box<dyn Fn(&'a Diagnostic) -> Option<(Lifetime, FatSpan)> + 'a> {
        Box::new(move |d: &Diagnostic| {
            re.captures(d.message.as_ref())
                .and_then(|caps| caps.name("lifetime").map(|m| m.as_str()))
                .map(|lifetime| {
                    assert_eq!(d.spans.len(), 1);
                    (Lifetime::from(lifetime), d.spans[0].to_fat_span())
                })
        })
    }

    // helper function to extract a lifetime list enclosed in <>, and
    // lifetimes following a borrow (e.g. "&'a")
    let extract_lifetimes = |s: &str| {
        let mut lifetimes = lifetime_arg_list
            .captures_iter(s)
            .flat_map(|capture| {
                capture
                    .name("lifetime_list")
                    .unwrap()
                    .as_str()
                    .split(", ")
                    .map(|s| Lifetime::from(s))
            })
            .collect::<HashSet<Lifetime>>();
        lifetimes.extend(
            lifetime_after_borrow
                .captures_iter(s)
                .map(|capture| Lifetime::from(capture.name("lifetime").unwrap().as_str())),
        );
        lifetimes
    };

    // Span information for mapping program locations in a stable manner
    let span_info = analysis::result::<SpanInfo>().unwrap();
    // Use the pointer provenance results for mapping to a location
    let ptr_provenance = {
        let mut p = analysis::result::<PtrProvenanceAnalysis>().unwrap();
        p.set_constraints.solve().unwrap();
        p
    };
    // Use struct info to find fields of given struct to poison struct fields that are mutable/owned pointers
    let struct_info = analysis::result::<StructInfo>().unwrap();

    // Can we introduce a move flow at a given expression
    //
    // This is approximate, because we are also adding ownership to a few places
    let is_movable = |hir_id| {
        (!old_config.is_move(hir_id)) && {
            let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
            // check owned(loc) => owned(direct flow of loc)
            log::trace!(
                "checking movability HIR ID: {:?} loc: {:?} arg_or_init: {:?}",
                hir_id,
                loc,
                ptr_provenance.arg_or_init.get(&hir_id)
            );
            !ptr_provenance.is_loc_owned(loc)
                || ptr_provenance
                    .arg_or_init
                    .get(&hir_id)
                    .map_or(true, |f| f.is_owned(&ptr_provenance))
        }
    };

    // Try to promote the immediate use of a flow expression to be owned
    let try_promote_immediate_use = |hir_id, kind: PtrKind, cfg: &mut Configuration| {
        if let Some(f) = ptr_provenance.arg_or_init.get(&hir_id) {
            // try to promote the direct assignee of this expression
            // to the given kind
            let mut try_promote = |loc| {
                let already_has_kind = match kind {
                    PtrKind::Raw => ptr_provenance.is_poisoned(loc),
                    PtrKind::Owned => ptr_provenance.is_loc_owned(loc),
                    _ => unreachable!("unexpected pointer kind: {:?}", kind),
                };
                if !already_has_kind {
                    cfg.promote_ptr_kind(loc.clone(), kind);
                }
                !already_has_kind
            };
            match f {
                FlowLoc::Plain(loc) => try_promote(loc),
                FlowLoc::Param(f, arity, i) => {
                    log::info!(
                        "promoting parameters of many functions to be owned to allow moving an argument"
                    );

                    let mut promoted_all = true;
                    let mut promoted_at_least_one = false;
                    for loc in ptr_provenance
                        .project_lambdas(f, *arity)
                        .0
                        .get(*i)
                        .into_iter()
                        .flatten()
                    {
                        // TODO: proper analysis of all relevant called functions, this is a hack to limit the scope
                        if !matches!(loc, Loc::Param(_, j) if i == j) {
                            continue;
                        }
                        promoted_all = try_promote(loc) && promoted_all;
                        promoted_at_least_one = true;
                    }
                    if !promoted_at_least_one {
                        log::error!("cannot find a parameter for {:?}", f);
                    }
                    promoted_all && promoted_at_least_one
                },
                FlowLoc::PointsTo(f) => {
                    log::info!(
                        "promoting nested pointers in many functions to be owned to allow moving to a nested pointer location"
                    );

                    let mut promoted_all = true;
                    let mut promoted_at_least_one = false;
                    let p = &ptr_provenance;
                    for loc in f.iter(p) {
                        promoted_all = {
                            let already_has_kind = match kind {
                                PtrKind::Raw => ptr_provenance.is_poisoned(&loc),
                                PtrKind::Owned => ptr_provenance.is_loc_owned(&loc),
                                _ => unreachable!("unexpected pointer kind: {:?}", kind),
                            };
                            if !already_has_kind {
                                cfg.promote_ptr_kind(loc, kind);
                            }
                            !already_has_kind
                        } && promoted_all;
                        promoted_at_least_one = true;
                    }
                    if !promoted_at_least_one {
                        log::error!("cannot find a location for points_to({:?})", f);
                    }
                    promoted_all && promoted_at_least_one
                },
            }
        } else {
            false
        }
    };

    for diag in diagnostics {
        let diagnostic = diag.unwrap();
        if let Some(DiagnosticCode { code, .. }) = &diagnostic.code {
            let rendered_error_message = diagnostic
                .rendered
                .as_ref()
                .map(|s| s.as_ref())
                .unwrap_or("<no detailed explanation>");
            log::error!("processing[{}] {}", code, rendered_error_message);
            match code.as_ref() {
                "E0308" => {
                    if diagnostic.spans.iter().all(|s| {
                        let label = s.label.as_ref().unwrap();
                        label == "lifetime mismatch"
                            || label == "the expected foreign type"
                            || label == "the found foreign type"
                    }) && diagnostic
                        .spans
                        .iter()
                        .any(|s| s.label.as_ref().unwrap() == "lifetime mismatch")
                    {
                        // Handle lifetime mismatches

                        // Ensure that there is a single span
                        //assert_eq!(diagnostic.spans.len(), 1);

                        let (lower, lower_span) = diagnostic
                            .children
                            .iter()
                            .find_map(get_matching_lifetime_and_loc(&lower_re))
                            .unwrap();
                        log::info!("lower lifetime {} at {:?}", lower, lower_span);

                        // Look up the widest span in the original file, use EDIT_OFFSETS
                        let lower_span = edit_offsets.widest_origin_span(&lower_span);
                        let lower_fn = span_info.reverse_fn_spans.get(&lower_span).unwrap();

                        let qual = Qual {
                            kind: QualKind::Fn,
                            q_name: lower_fn.clone(),
                        };
                        let upper = if let Some((upper, upper_span)) = diagnostic
                            .children
                            .iter()
                            .find_map(get_matching_lifetime_and_loc(&upper_re))
                        {
                            log::info!("upper lifetime {} at {:?}", upper, upper_span);
                            let upper_span = edit_offsets.widest_origin_span(&upper_span);
                            let upper_fn = span_info.reverse_fn_spans.get(&upper_span).unwrap();
                            assert_eq!(lower_fn, upper_fn);
                            upper
                        } else if diagnostic.children.iter().any(|d| {
                            d.message.as_str()
                                == "...does not necessarily outlive the static lifetime"
                        }) {
                            log::info!("upper lifetime is 'static");
                            Lifetime::from("'static")
                        } else {
                            unreachable!(
                                "could not process the lifetime mismatch diagnostic {:#?}",
                                diagnostic
                            )
                        };
                        cfg.add_bound(qual, lower, upper);
                    } else if {
                        let diag = diagnostic.spans[0].label.as_ref().unwrap();
                        diag.starts_with("expected `&")
                            && diag.ends_with("found struct `std::boxed::Box`")
                    } {
                        // The current expression must be moved but
                        // its immediate use is not owned. Promote it
                        // to be owned. If the promotion fails, bail
                        // out to using a raw pointer.
                        let borrow_span = &diagnostic.spans[0];
                        let origin_span =
                            edit_offsets.widest_origin_span(&borrow_span.to_fat_span());
                        let hir_id = span_info.lookup_hir_id(&origin_span).unwrap();
                        if !try_promote_immediate_use(hir_id, PtrKind::Owned, &mut cfg) {
                            log::error!("promoting to owned failed");
                            let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                            cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                        }
                    } else if {
                        let label = diagnostic.spans[0]
                        .label
                        .as_ref()
                            .unwrap();
                        label.starts_with("expected struct `std::boxed::Box`, found `&")
                        || label.starts_with("expected struct `std::boxed::Box`, found mutable reference") || diagnostic.spans[0].label.as_ref().unwrap().as_str()
                        == "types differ in mutability"
                    }
                    {
                        // We assumed this value was a Box but it is
                        // actually a directly borrowed reference, and
                        // it is used in a way that a reference should
                        // not be. So, promote it to a raw pointer.

                        // Span of the expression we want to make raw
                        let new_expr_span = diagnostic.spans[0].to_fat_span();

                        // Find the widest origin span
                        let orig_expr_span = edit_offsets.widest_origin_span(&new_expr_span);

                        // Find the expression
                        let hir_id = span_info
                            .lookup_hir_id(&orig_expr_span)
                            .expect("Could not find a surrounding expression");
                        let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                        // Update the configuration
                        cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                        // TODO: This is imprecise when dealing with arrays,
                        // etc. Parse the given type strings to locate the
                        // difference instead.
                    } else {
                        let label = &diagnostic.spans[0].label.as_ref().unwrap().as_str();
                        let ptr_ref_mismatch_labels = vec![
                            "expected *-ptr, found enum `std::option::Option`",
                            "expected enum `std::option::Option`, found mutable reference",
                        ];
                        if ptr_ref_mismatch_labels.contains(label) {
                            // Span of the expression we want to make raw
                            let new_expr_span = diagnostic.spans[0].to_fat_span();

                            // Find the widest origin span
                            let orig_expr_span = edit_offsets.widest_origin_span(&new_expr_span);

                            // Find the expression
                            let hir_id = span_info
                                .lookup_hir_id(&orig_expr_span)
                                .expect("Could not find a surrounding expression");
                            let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                            println!(
                                r#"associated span: {:?}
HIR ID: {:?} loc: {:?}
poisons: {:?}"#,
                                orig_expr_span,
                                hir_id,
                                loc,
                                ptr_provenance.poisons(loc)
                            );
                            if let Some(FlowLoc::Param(f, arity, n)) =
                                ptr_provenance.arg_or_init.get(&hir_id)
                            {
                                println!(
                                    "projected lambdas for the immediate successor's function: {:?}#{} [arity = {:?}]",
                                    f, n, arity
                                );
                                let (params, ret) =
                                    ptr_provenance.project_lambdas(f, arity.clone());
                                for (i, p) in params.iter().enumerate() {
                                    println!("    locs: {:?}", p);
                                    println!(
                                        " - param#{}: {:?}",
                                        i,
                                        ptr_provenance.aggregate_poisons(p)
                                    );
                                }
                                println!(
                                    " - ret val: {:?}",
                                    ptr_provenance.aggregate_poisons(&ret)
                                );
                            }
                        }

                        diagnostic.pretty_print(0);
                        panic!("Cannot handle type mismatch: {:#?}", diagnostic);
                    }
                },
                "E0382" => {
                    // Borrow of moved value (use after move). Promote
                    // the relevant pointer to raw.

                    let find_span_for_any_msg = |msgs: &[&str]| diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some() && {
                                    let label = s.label.as_ref().unwrap().as_str();
                                    msgs.contains(&label)
                                }
                            })
                            .map(|span| edit_offsets.widest_origin_span(&span.to_fat_span()));

                    // find the span for the borrow (this may include the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    let use_span = find_span_for_any_msg(&[
                                        "value used here after move",
                                        "value borrowed here after move",
                                        "value borrowed here after partial move",
                                        "value moved here, in previous iteration of loop",
                                    ]).unwrap();

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    if let Some(struct_name) = ptr_provenance.maybe_expr_struct_type.get(&hir_id) {
                        // If this is a struct, make all fields raw
                        let mut locs = HashSet::default();
                        collect_ptr_locs(
                            &struct_info,
                            &ptr_provenance,
                            &Type::Struct(struct_name.clone()),
                            HashSet::default(),
                            &mut locs,
                        );
                        locs.into_iter()
                            .for_each(|loc| cfg.promote_ptr_kind(loc, PtrKind::Raw));
                    } else {
                        // Otherwise, this must be a pointer, mark it as raw
                        if ptr_provenance.is_poisoned(loc) {
                            // This pointer is already poisoned, try promoting
                            // the move location
                            if let Some(move_span) = find_span_for_any_msg(&["value moved here"]) {
                                let hir_id = span_info
                                    .lookup_hir_id(&move_span)
                                    .expect("Could not find a surrounding expression");
                                let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                                cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                            }
                        } else {
                            // This pointer isn't poisoned yet, try promoting it
                            cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                        }
                    }
                },
                "E0508" => {
                    // Move out of an array element, promote the relevant
                    // pointer to raw.
                    //
                    // TODO(interactive): Another solution is to ask the
                    // programmer if this is a move or copy to insert
                    // mem::replace or .clone() respectively.

                    // find the span for the move (this may include the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    for span in diagnostic.spans.iter() {
                        println!("{:?}", span);
                    }
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some() && {
                                    let label = s.label.as_ref().unwrap().as_str();
                                    [
                                        "cannot move out of here",
                                    ]
                                    .contains(&label)
                                }
                            })
                            .unwrap()
                            .to_fat_span(),
                    );

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    if let Some(struct_name) = ptr_provenance.maybe_expr_struct_type.get(&hir_id) {
                        // If this is a struct, make all fields raw
                        //
                        // TODO: don't do this for &T fields.
                        let mut locs = HashSet::default();
                        collect_ptr_locs(
                            &struct_info,
                            &ptr_provenance,
                            &Type::Struct(struct_name.clone()),
                            HashSet::default(),
                            &mut locs,
                        );
                        locs.into_iter()
                            .for_each(|loc| cfg.promote_ptr_kind(loc, PtrKind::Raw));
                    } else {
                        // Otherwise, this must be a pointer, mark it as raw
                        cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                    }
                },
                "E0515" => {
                    // A reference to a local variable or box is
                    // returned. Make the reference Owned to extend
                    // the object's lifetime.
                    //
                    // Also, in case this is a structural reference,
                    // mark the local as moved rather than borrowed.

                    // Check that we are processing the correct span
                    assert_eq!(
                        diagnostic.spans[0].label.as_ref().unwrap().as_str(),
                        "returns a value referencing data owned by the current function"
                    );

                    // Span of the expression we want to move
                    let span_to_move =
                        edit_offsets.narrowest_origin_span(&diagnostic.spans[1].to_fat_span());

                    let hir_to_move = span_info
                        .lookup_hir_id(&span_to_move)
                        .expect("Could not find a surrounding expression");

                    // promote the borrow to a move
                    cfg.promote_borrow_to_move(hir_to_move);

                    // Span of the expression we want to make owned
                    let new_expr_span = diagnostic.spans[0].to_fat_span();

                    // Find the widest origin span
                    let orig_expr_span = edit_offsets.narrowest_origin_span(&new_expr_span);

                    // Find the expression
                    let hir_id = span_info
                        .lookup_hir_id(&orig_expr_span)
                        .expect("Could not find a surrounding expression");

                    // Find the location and the function
                    // let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                    let fun = span_info.reverse_fn_spans.get(&orig_expr_span).unwrap();

                    // Update the configuration
                    // cfg.promote_ptr_kind(loc.clone(), PtrKind::Owned);

                    // TODO(maemre): refine this
                    if is_movable(hir_id) {
                        cfg.promote_borrow_to_move(hir_id);
                    } else {
                        cfg.promote_ptr_kind(Loc::RetVal(fun.clone()), PtrKind::Owned);
                    }
                },
                "E0716" => {
                    // Temporary value dropped while borrowed. First,
                    // try to change the borrow to a move. If it still
                    // doesn't fix the isue, extend the value's
                    // lifetime by making it owned.

                    // find the span for the temporary
                    let origin_span = diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.as_ref().map_or(false, |l| {
                                l.as_str()
                                    == "creates a temporary which is freed while still in use"
                            })
                        })
                        .unwrap();
                    let create_span =
                        edit_offsets.narrowest_origin_span(&origin_span.to_fat_span());

                    let val_hir_id = span_info.lookup_hir_id(&create_span).unwrap();

                    if is_movable(val_hir_id) {
                        // promote the borrow to a move
                        cfg.promote_borrow_to_move(val_hir_id);
                    } else {
                        // The borrow is already promoted to a move, Promote the pointer to be owned as a second choice.

                        // find the span for the expression that is later used
                        let (_hir_id, loc) = if let Some(borrow_use_span) =
                            &diagnostic.spans.iter().find(|s| {
                                s.label.is_some() && {
                                    let label = s.label.as_ref().unwrap().as_str();
                                    label == "borrow later used here"
                                        || label
                                            .starts_with("argument requires that borrow lasts for")
                                        || label
                                            .starts_with("cast requires that borrow lasts for")
                                }
                            }) {
                            let error_use_span = borrow_use_span.to_fat_span();
                            let use_span = edit_offsets.narrowest_origin_span(&error_use_span);

                            log::trace!("input span: {:?}", error_use_span);
                            log::trace!("narrowest origin span: {:?}", use_span);

                            let hir_id = span_info
                                .lookup_hir_id(&use_span)
                                .expect("Could not find a surrounding expression");
                            log::trace!("got id: {:?}", hir_id);
                            let loc = if let Some(term) = ptr_provenance.expr_to_term.get(&hir_id) {
                                term.get_lv().unwrap()
                            } else {
                                // The expression is not found in the
                                // expr_to_term map, it may be an assignment,
                                // then use the left-hand side of the
                                // assignment as the owned value.
                                let lhs_id = span_info.lookup_lhs_id(&use_span).expect("Could not find a surrounding assignment, and there is no associated term with the surrounding expression.");
                                ptr_provenance.expr_to_term[&lhs_id].get_lv().unwrap()
                            };
                            (hir_id, loc)
                        } else if diagnostic.spans.iter().any(|s| {
                            s.label.is_some() && {
                                s.label
                                    .as_ref()
                                    .unwrap()
                                    .as_str()
                                    .starts_with("assignment requires that borrow lasts for `'")
                            }
                        }) {
                            (
                                val_hir_id,
                                ptr_provenance.expr_to_term[&val_hir_id].get_lv().unwrap(),
                            )
                        } else {
                            panic!("cannot handle the subtype of E0716: {:#?}", diagnostic)
                        };

                        // Update the configuration, and mark the
                        // using expression as owned.
                        if ptr_provenance.is_loc_owned(&loc) {
                            // If the using expression is already
                            // owned, then mark the direct assignees
                            // of it as owned. This is a hack for
                            // malloc
                            if let Some(FlowLoc::Plain(direct_descendant)) =
                                ptr_provenance.arg_or_init.get(&val_hir_id)
                            {
                                cfg.promote_ptr_kind(direct_descendant.clone(), PtrKind::Owned);
                            } else {
                                // cannot promote borrows far enough
                                log::error!(
                                    "Giving up on dropped temporary error and marking {:?} as raw",
                                    loc
                                );
                                cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                            }
                        } else {
                            cfg.promote_ptr_kind(loc.clone(), PtrKind::Owned);
                        }
                    }
                },
                "E0499" => {
                    // Multiple mutable borrows. Mark the borrowed pointer as raw.

                    // find the span for the borrow (this includes the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    // log::warn!("E0499: diagnostic - {:?}", &diagnostic);
                    // log::warn!("E0499: diagnostic.spans - {:?}", &diagnostic.spans);
                    // log::warn!("E0499: diagnostic.spans.iter() - {:?}", &diagnostic.spans.iter());
                    let re = Regex::new(r".+was mutably borrowed here in the previous iteration of the loop").unwrap();
                    let use_span = edit_offsets.narrowest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some()
                                    && {
                                        let label = s.label.as_ref().unwrap().as_str();
                                        label == "first mutable borrow occurs here" ||
                                            // label == "`global` was mutably borrowed here in the previous iteration of the loop"
                                            re.is_match(label)
                                    }
                            })
                            .unwrap()
                            .to_fat_span(),
                    );

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    // Update the configuration, and mark the using
                    // expression as refcell/raw
                    let promoted_kind = refcell_promoted_kind(loc);
                    if !try_promote_immediate_use(hir_id, refcell_promoted_kind(loc), &mut cfg) {
                        // we already tried promoting the use site,
                        // check if we already did this promotion, and try
                        // alternative promotions if we haven't
                        if old_config.ptr_kind(&loc) < promoted_kind {
                            cfg.promote_ptr_kind(loc.clone(), promoted_kind);
                        } else if let Some(origin_span) = diagnostic.spans.iter().find(|s| {
                            s.label.is_some() && {
                                let label = s.label.as_ref().unwrap().as_str();
                                label == "first borrow later used here"
                            }
                        }) {
                            let use_span =
                                edit_offsets.narrowest_origin_span(&origin_span.to_fat_span());

                            let hir_id = span_info
                                .lookup_hir_id(&use_span)
                                .expect("Could not find a surrounding expression");
                            if let Some(loc) = ptr_provenance
                                .expr_to_term
                                .get(&hir_id)
                                .and_then(|l| l.get_lv())
                            {
                                // Update the configuration, and mark the using
                                // expression as refcell/raw
                                let promoted_kind = refcell_promoted_kind(loc);
                                if !try_promote_immediate_use(
                                    hir_id,
                                    refcell_promoted_kind(loc),
                                    &mut cfg,
                                ) {
                                    cfg.promote_ptr_kind(loc.clone(), promoted_kind);
                                }
                            }
                        }
                    }
                },
                "E0502" => {
                    // Mutable borrow overlapping with immutable
                    // borrow. Mark the borrowed pointer as raw.

                    let mut try_promote_immediate_use_then_loc = |hir_id, loc| {
                        let promoted_kind = refcell_promoted_kind(loc);
                        if !try_promote_immediate_use(hir_id, promoted_kind, &mut cfg) {
                            // we already tried promoting the use site,
                            // check if we already did this promotion, and try
                            // alternative promotions if we haven't
                            if old_config.ptr_kind(&loc) < promoted_kind {
                                cfg.promote_ptr_kind(loc.clone(), promoted_kind);
                                true
                            } else {
                                false
                            }
                        } else {
                            true
                        }
                    };


                    // find the span for the borrow (this includes the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    let loc_from_label = |p: fn(&str) -> bool| {
                        let use_span = edit_offsets.narrowest_origin_span(
                            &diagnostic
                                .spans
                                .iter()
                                .find(|s| {
                                    s.label.is_some() && p(s.label.as_ref().unwrap().as_str())
                                })
                                .unwrap()
                                .to_fat_span(),
                        );

                        let hir_id = span_info
                            .lookup_hir_id(&use_span)
                            .expect("Could not find a surrounding expression");
                        (hir_id, ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap())
                    };
                    let (hir_id, loc) = loc_from_label(|s: &str| s == "mutable borrow occurs here");
                    // try promoting the mutable borrow, if it fails also
                    // promote the immutable borrow
                    if ! try_promote_immediate_use_then_loc(hir_id, loc) {
                        let (hir_id, loc) = loc_from_label(|s: &str| s == "immutable borrow occurs here");
                        try_promote_immediate_use_then_loc(hir_id, loc);
                    }
                },
                "E0503" | "E0505" => {
                    // Use/move of a value that is already borrowed in
                    // an active (alive) lifetime.  Mark the borrowed
                    // pointer as refcell, then raw as fallback.

                    // find the span for the borrow (this includes the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some() && {
                                    let label = s.label.as_ref().unwrap().as_str();
                                    label.starts_with("borrow of ")
                                        && label.ends_with(" occurs here")
                                }
                            })
                            .unwrap()
                            .to_fat_span(),
                    );

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    // Update the configuration, and mark the using
                    // expression as owned
                    cfg.promote_ptr_kind(loc.clone(), refcell_promoted_kind(loc));
                    // TODO: cast also in the second location?
                },
                "E0495" => {
                    // Cannot infer an appropriate lifetime. Collect
                    // the missing lifetime requirements.

                    let (lower, lower_span) = diagnostic
                        .children
                        .iter()
                        .find_map(get_matching_lifetime_and_loc(&lower_re_495))
                        .unwrap();
                    log::info!("lower lifetime {} at {:?}", lower, lower_span);
                    // Look up the widest span in the original file, use EDIT_OFFSETS
                    let lower_span = edit_offsets.widest_origin_span(&lower_span);
                    let lower_fn = span_info.reverse_fn_spans.get(&lower_span).unwrap();
                    let upper = if let Some((upper, upper_span)) = diagnostic
                        .children
                        .iter()
                        .find_map(get_matching_lifetime_and_loc(&upper_re_495))
                    {
                        log::info!("upper lifetime {} at {:?}", upper, upper_span);

                        let upper_span = edit_offsets.widest_origin_span(&upper_span);

                        let upper_fn = span_info.reverse_fn_spans.get(&upper_span).unwrap();

                        assert_eq!(lower_fn, upper_fn);
                        upper
                    } else {
                        // The lifetime should be as long as 'static
                        Lifetime::from("'static")
                    };

                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: lower_fn.clone(),
                    };

                    cfg.add_bound(qual, lower, upper);
                },
                "E0507" => {
                    // Trying to dereference a temporary (or local) object and
                    // store (or return) it in a longer-living location.
                    //
                    // Promote the pointer to raw for now.
                    //
                    // TODO(maemre): There are cases where there are mutable
                    // references to slices of mutable pointers (i.e. nested
                    // pointers inside arrays) where we can try consuming the
                    // slice reference and re-borrow the single object inside to
                    // make it work. In those cases, we should rewrite
                    //
                    // *arr.offset(i) // here, arr: Option<&mut [&mut T]>> where
                    //                // [..] stands for custom slice
                    //
                    // into something like (probably with a wrapper method that
                    // consumes arr.unwrap() only once)
                    //
                    // arr.unwrap().slice[i+arr.unwrap().offset].as_mut().map(|o| &mut **o)
                    //
                    // instead of
                    //
                    // *borrow_mut(arr).unwrap().get_mut_offset(i)
                    //
                    // which refers to the temporary (the result of unwrap()).
                    //
                    // To do the above, we need to
                    //
                    // 1. TODO(maemre): add RT support (a CustomSlice method) to
                    // get the value inside for nested pointers, like the proper
                    // translation.
                    //
                    // 2. TODO(maemre): add something akin to a move-flow to
                    // tell the rewriter that the value inside `arr` should be
                    // moved.
                    //
                    // 3. TODO(maemre): have promotion to raw ready for when
                    // that move-flow fails.

                    // find the span for the borrow.
                    let orig_span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.is_some() && {
                                let label = s.label.as_ref().unwrap().as_str();
                                label.starts_with("move occurs because ")
                                    && label.ends_with("which does not implement the `Copy` trait")
                            }
                        })
                        .unwrap()
                        .to_fat_span();
                    let use_span = edit_offsets.narrowest_origin_span(orig_span);

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    // Update the configuration, and mark the using
                    // expression as raw
                    cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                },
                "E0597" => {
                    // Borrowed value does not live long enough, this
                    // happens when borrowing from the stack,
                    // potentially indicating a use-after-free because
                    // of temporary stack references. Mark the borrow
                    // as raw (we are skipping boxing here).
                    //
                    // Don't apply a fix if we already lifted the
                    // borrow to a move for the same expression in
                    // this iteration (this check is for the cases
                    // where 597 and 506 occur at the same time).

                    // find the span for the borrow.
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some()
                                    && s.label.as_ref().unwrap().as_str()
                                        == "borrowed value does not live long enough"
                            })
                            .unwrap()
                            .to_fat_span(),
                    );

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();

                    // Check if we already lifted the borrow here to a
                    // move, and mark the expression as raw only if
                    // there is no point in promoting to move.

                    if is_movable(hir_id) {
                        cfg.promote_borrow_to_move(hir_id);
                    } else if !try_promote_immediate_use(hir_id, PtrKind::Owned, &mut cfg) {
                        cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                    }
                },
                "E0623"
                    if diagnostic.spans.iter().any(|s| {
                        s.label.is_some()
                            && s.label.as_ref().unwrap()
                                == "these two types are declared with different lifetimes..."
                    }) =>
                {
                    // This is the case where there are no explicit
                    // lifetimes reported by the compiler, add
                    // constraints for all of the lifetimes on one
                    // side to match the other, a better option would
                    // be to inspect intermediate type checker state
                    // to extract the relevant lifetime constraints.

                    // The first type
                    let span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.is_some()
                                && s.label.as_ref().unwrap().as_str()
                                    == "these two types are declared with different lifetimes..."
                        })
                        .unwrap();
                    let snippet = &span.text[0];
                    let type_text =
                        &snippet.text[snippet.highlight_start - 1..snippet.highlight_end - 1];
                    let origin_span = edit_offsets.widest_origin_span(&span.to_fat_span());
                    let enclosing_fn = span_info.reverse_fn_spans.get(&origin_span).unwrap();
                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: enclosing_fn.clone(),
                    };
                    let lifetimes = extract_lifetimes(type_text);

                    // The second type
                    let span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| s.label.is_some() && s.label.as_ref().unwrap().as_str() == "")
                        .unwrap();
                    let snippet = &span.text[0];
                    let type_text =
                        &snippet.text[snippet.highlight_start - 1..snippet.highlight_end - 1];
                    let origin_span = edit_offsets.widest_origin_span(&span.to_fat_span());
                    let enclosing_fn2 = span_info.reverse_fn_spans.get(&origin_span).unwrap();
                    assert!(enclosing_fn == enclosing_fn2);
                    let lifetimes2 = extract_lifetimes(type_text);

                    // Equate the lifetimes on the two sides
                    for a in &lifetimes {
                        for b in &lifetimes2 {
                            if a != b {
                                cfg.add_bound(qual.clone(), a.clone(), b.clone());
                                cfg.add_bound(qual.clone(), b.clone(), a.clone());
                            }
                        }
                    }
                }
                "E0623"
                    if diagnostic.spans.iter().any(|s| {
                        s.label.is_some()
                            && s.label.as_ref().unwrap()
                                == "...but data with one lifetime flows into the other here"
                    }) =>
                {
                    // Some of the lifetime parameters of a type flow
                    // into each other inside this function. The
                    // compiler does not give us the precise missing
                    // constraint. Make all of them equivalent.
                    let span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.is_some()
                                && s.label.as_ref().unwrap().as_str()
                                    == "this type is declared with multiple lifetimes..."
                        })
                        .unwrap();
                    let snippet = &span.text[0];
                    let type_text = &snippet.text[snippet.highlight_start..snippet.highlight_end];
                    let origin_span = edit_offsets.widest_origin_span(&span.to_fat_span());
                    let enclosing_fn = span_info.reverse_fn_spans.get(&origin_span).unwrap();
                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: enclosing_fn.clone(),
                    };
                    let lifetimes = extract_lifetimes(type_text);
                    for a in &lifetimes {
                        for b in &lifetimes {
                            if a != b {
                                cfg.add_bound(qual.clone(), a.clone(), b.clone());
                                cfg.add_bound(qual.clone(), b.clone(), a.clone());
                            }
                        }
                    }
                }
                "E0623" => {
                    // Lifetime mismatch. Add the relevant constraints
                    // if possible, otherwise promote the relevant
                    // expression's type to be raw.
                    todo!("Handle diagnostic {:#?}", diagnostic)
                },
                "E0759" => {
                    // The type needs to have 'static lifetime, so extend all lifetime params

                    let span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.is_some()
                                && s.label
                                    .as_ref()
                                    .unwrap()
                                    .as_str()
                                    .starts_with("this data with lifetime ")
                        })
                        .unwrap();
                    let snippet = &span.text[0];
                    let type_text =
                        &snippet.text[snippet.highlight_start - 1..snippet.highlight_end - 1];
                    let origin_span = edit_offsets.widest_origin_span(&span.to_fat_span());
                    let enclosing_fn = span_info.reverse_fn_spans.get(&origin_span).unwrap();
                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: enclosing_fn.clone(),
                    };
                    let lifetimes = extract_lifetimes(type_text);
                    let static_lifetime = Lifetime::from("'static");
                    for a in &lifetimes {
                        cfg.add_bound(qual.clone(), a.clone(), static_lifetime.clone());
                    }

                    // Check if there is a borrow causing temporaries, add a move flow in this case.
                    if diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            let snippet = &s.text[0];
                            let text = &snippet.text
                                [(snippet.highlight_start - 1)..(snippet.highlight_end - 1)];
                            text == "borrow" || text == "borrow_mut"
                        })
                        .is_some()
                    {
                        // the relevant object is borrowed, mark the expression as move-flowed
                        let borrow_span = &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.as_ref().map_or(false, |l| {
                                    l.as_str().contains("is captured ")
                                        && l.as_str().contains(" here")
                                })
                            })
                            .unwrap();
                        let origin_span =
                            edit_offsets.widest_origin_span(&borrow_span.to_fat_span());
                        let hir_id = span_info.lookup_hir_id(&origin_span).unwrap();
                        cfg.promote_borrow_to_move(hir_id);
                    }
                },
                "E0596" => {
                    // Tried to create a mutable borrow a field behind
                    // an immutable borrow. Mark the relevant pointer as refcell then raw.
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some() && {
                                    let label = s.label.as_ref().unwrap().as_str();
                                    label == "cannot borrow as mutable"
                                        ||
                                        label.ends_with("is a `*const` pointer, so the data it refers to cannot be borrowed as mutable")
                                }
                            })
                            .unwrap()
                            .to_fat_span(),
                    );

                    let hir_id = span_info
                        .lookup_hir_id(&use_span)
                        .expect("Could not find a surrounding expression");
                    // log::warn!("++++++ ptr_provenance.expr_to_term.get(&hir_id)): {:?}", ptr_provenance.expr_to_term.get(&hir_id));
                    // log::warn!("++++++ HIR ID {:?} for span {:?} when processing {:#?}",  hir_id, use_span, diagnostic);
                    let loc = ptr_provenance.expr_to_term.get(&hir_id).unwrap_or_else(|| {
                        panic!("failed to look up the HIR ID {:?} for span {:?} when processing {:#?}",
                               hir_id,
                               use_span,
                               diagnostic)
                    }).get_lv().unwrap();
                    // let loc = ptr_provenance.expr_to_term.get(&hir_id).unwrap().get_lv().unwrap();

                    // Update the configuration, and mark the using
                    // expression as refcell/raw
                    if !try_promote_immediate_use(hir_id, refcell_promoted_kind(loc), &mut cfg) {
                        // we already tried promoting the use site,
                        // propagate the promotion to the expression's
                        // location.
                        cfg.promote_ptr_kind(loc.clone(), refcell_promoted_kind(loc));
                    }
                },
                "E0506" => {
                    // An attempt was made to assign to a borrowed value

                    // This is likely the result of a borrow that needs to be a move.

                    let span = &diagnostic
                        .spans
                        .iter()
                        .find(|s| {
                            s.label.as_ref().map_or(false, |l| {
                                l.as_str().starts_with("borrow")
                                    && l.as_str().ends_with("occurs here")
                            })
                        })
                        .unwrap();
                    let origin_span = edit_offsets.widest_origin_span(&span.to_fat_span());
                    let hir_id = span_info.lookup_hir_id(&origin_span).unwrap();

                    if is_movable(hir_id) {
                        cfg.promote_borrow_to_move(hir_id);
                    } else if !try_promote_immediate_use(hir_id, PtrKind::Owned, &mut cfg) {
                        let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                        cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                    }
                },
                "E0106" if diagnostic.children.iter().any(|c| c.message.starts_with("this function's return type contains a borrowed value, but the signature does not say whether it is borrowed from")) => {
                    for span in diagnostic.spans.iter() {
                        if span.label.as_ref().map(String::as_ref) == Some("expected named lifetime parameter") {
                            let fat_span = span.to_fat_span();
                            // let widest_origin_span = edit_offsets.widest_origin_span(&fat_span);
                            let narrowest_origin_span = edit_offsets.narrowest_origin_span(&fat_span);
                            let mut ret_locs = HashSet::default();
                            for (ty, loc) in span_info.lookup_rewritten_type(&narrowest_origin_span).unwrap() {
                                ptr_provenance.collect_return_locs(loc.iter().collect(), ty, &mut ret_locs);
                            }
                            for loc in ret_locs {
                                cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                            }
                        }
                    }
                },
                "E0521" if diagnostic.message == "borrowed data escapes outside of function" =>
                {
                    // Apply existing lifetime suggestions if there are any, fail otherwise
                    let applicable_suggestions = diagnostic.children.iter().filter_map(|diag| {
                        let prefix = "consider adding the following bound: ";
                        if diag.message.starts_with(prefix) {
                            lifetime_constraint_re.captures(&diag.message[prefix.len()..]).map(|caps| (
                                Lifetime::from(caps.name("lower").unwrap().as_str()),
                                Lifetime::from(caps.name("upper").unwrap().as_str()),
                            ))
                        } else {
                            None
                        }
                    }).collect::<Vec<(Lifetime, Lifetime)>>();

                   if applicable_suggestions.is_empty() {
                        println!("{:#?}", diagnostic);
                        println!("DONE: {}", "Borrowed data escapes outside of function but there are no ready fixes suggested by rustc.".red());
                        panic!(
                            "The diagnostic [{}] cannot be handled: {}. {}",
                            code, diagnostic.message, rendered_error_message
                        );
                    }

                    let origin_span = edit_offsets.widest_origin_span(&diagnostic.spans[0].to_fat_span());
                    let enclosing_fn = span_info.reverse_fn_spans.get(&origin_span).unwrap();
                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: enclosing_fn.clone(),
                    };

                    for (lower, upper) in applicable_suggestions {
                        cfg.add_bound(qual.clone(), lower, upper);
                    }
                },
                _ => {
                    println!("{:#?}", diagnostic);
                    println!("DONE: {}", "There is a compiler error that cannot be fixed.".red());
                    panic!(
                        "The diagnostic [{}] cannot be handled: {}. {}",
                        code, diagnostic.message, rendered_error_message
                    );
                },
            }
        } else {
            log::warn!("skipping diagnostic with message '{}'", diagnostic.message);
        }
    }

    cfg
}
