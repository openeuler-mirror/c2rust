//! Compiler error parsing and handling to generate fixes

use crate::{
    analysis,
    analysis::span::*,
    config::*,
    ptr_provenance::{Loc, PtrProvenanceAnalysis},
    types::{Lifetime, Name},
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

pub fn generate_fixes(compiler_errors: &str) -> Configuration {
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

    // helper function to extract a lifetime list enclosed in <>.
    let extract_lifetimes = |s: &str| {
        lifetime_arg_list
            .captures_iter(s)
            .flat_map(|capture| {
                capture
                    .name("lifetime_list")
                    .unwrap()
                    .as_str()
                    .split(", ")
                    .map(|s| Lifetime::from(s))
            })
            .collect::<HashSet<Lifetime>>()
    };

    // Span information for mapping program locations in a stable manner
    let span_info = analysis::result::<SpanInfo>().unwrap();
    // Use the pointer provenance results for mapping to a location
    let ptr_provenance = analysis::result::<PtrProvenanceAnalysis>().unwrap();

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
                    if diagnostic
                        .spans
                        .iter()
                        .all(|s| s.label.as_ref().unwrap() == "lifetime mismatch")
                    {
                        // Handle lifetime mismatches

                        // Ensure that there is a single span
                        assert_eq!(diagnostic.spans.len(), 1);

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
                    } else if diagnostic.spans[0]
                        .label
                        .as_ref()
                        .unwrap()
                        .starts_with("expected struct `std::boxed::Box`, found `&")
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
                    } else if diagnostic.spans[0].label.as_ref().unwrap().as_str()
                        == "types differ in mutability"
                    {
                        // The original program still has some nested
                        // pointers cast with differing mutability
                        // (e.g. * mut * mut T as * mut * const T ).
                        // Doing this with references would require
                        // unsafe code, so we should just revert them
                        // to unsafe pointers.

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
                    } else {
                        panic!("Cannot handle type mismatch: {:#?}", diagnostic);
                    }
                },
                "E0515" => {
                    // A reference to a local variable or box is
                    // returned. Make the reference Owned to extend
                    // the object's lifetime.

                    // Check that we are processing the correct span
                    assert_eq!(
                        diagnostic.spans[0].label.as_ref().unwrap().as_str(),
                        "returns a value referencing data owned by the current function"
                    );

                    // Span of the expression we want to make owned
                    let new_expr_span = diagnostic.spans[0].to_fat_span();

                    // Find the widest origin span
                    let orig_expr_span = edit_offsets.widest_origin_span(&new_expr_span);

                    // Find the expression
                    let hir_id = span_info
                        .lookup_hir_id(&orig_expr_span)
                        .expect("Could not find a surrounding expression");

                    // Find the location and the function
                    let loc = ptr_provenance.expr_to_term[&hir_id].get_lv().unwrap();
                    let fun = span_info.reverse_fn_spans.get(&orig_expr_span).unwrap();

                    // Update the configuration
                    cfg.promote_ptr_kind(loc.clone(), PtrKind::Owned);
                    cfg.promote_ptr_kind(Loc::RetVal(fun.clone()), PtrKind::Owned);
                },
                "E0716" => {
                    // Temporary value dropped while borrowed. Extend
                    // the value's lifetime by making it owned.

                    // find the span for the expression that is later used
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some()
                                    && s.label.as_ref().unwrap().as_str()
                                        == "borrow later used here"
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
                    cfg.promote_ptr_kind(loc.clone(), PtrKind::Owned);
                },
                "E0499" => {
                    // Multiple mutable borrows. Mark the borrowed pointer as raw.

                    // find the span for the borrow (this includes the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some()
                                    && s.label.as_ref().unwrap().as_str()
                                        == "first mutable borrow occurs here"
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
                    cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
                },
                "E0502" => {
                    // Mutable borrow overlapping with immutable
                    // borrow. Mark the borrowed pointer as raw.

                    // find the span for the borrow (this includes the
                    // `&mut` we injected but it will map to the
                    // original expression).
                    let use_span = edit_offsets.widest_origin_span(
                        &diagnostic
                            .spans
                            .iter()
                            .find(|s| {
                                s.label.is_some()
                                    && s.label.as_ref().unwrap().as_str()
                                        == "mutable borrow occurs here"
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
                    cfg.promote_ptr_kind(loc.clone(), PtrKind::Raw);
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
                    let (upper, upper_span) = diagnostic
                        .children
                        .iter()
                        .find_map(get_matching_lifetime_and_loc(&upper_re_495))
                        .unwrap();
                    log::info!("upper lifetime {} at {:?}", upper, upper_span);

                    // Look up the widest span in the original file, use EDIT_OFFSETS
                    let lower_span = edit_offsets.widest_origin_span(&lower_span);
                    let upper_span = edit_offsets.widest_origin_span(&upper_span);

                    let lower_fn = span_info.reverse_fn_spans.get(&lower_span).unwrap();
                    let upper_fn = span_info.reverse_fn_spans.get(&upper_span).unwrap();

                    assert_eq!(lower_fn, upper_fn);

                    let qual = Qual {
                        kind: QualKind::Fn,
                        q_name: lower_fn.clone(),
                    };

                    cfg.add_bound(qual, lower, upper);
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
                    let type_text = &snippet.text[snippet.highlight_start..snippet.highlight_end];
                    println!("extracted type text {}", type_text);
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
                    let type_text = &snippet.text[snippet.highlight_start..snippet.highlight_end];
                    println!("extracted type text {}", type_text);
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
                    println!("extracted type text {}", type_text);
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
                    let type_text = &snippet.text[snippet.highlight_start..snippet.highlight_end];
                    println!("extracted type text {}", type_text);
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
                },
                _ => {
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
