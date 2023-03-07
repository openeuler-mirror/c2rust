//! Span extraction passes to map functions to lines and/or spans reliably

use crate::{
    analysis,
    analysis::commons::*,
    compiler_interface::*,
    constants::*,
    io::{FileIO, OutputMode},
    lazy_static::lazy_static,
    ptr_provenance::*,
    rustc_ast::ast::LitKind,
    rustc_driver,
    rustc_errors::emitter::{ColorConfig, HumanReadableErrorType},
    rustc_hir,
    rustc_hir::{intravisit::FnKind, Generics, *},
    rustc_interface,
    rustc_lint::{LateContext, LateLintPass, LintContext, LintPass},
    rustc_span::{
        sym,
        symbol::{Ident, Symbol},
        BytePos, FileName, Span,
    },
    types::{FnSig, Lifetime, *},
    util::{HashMap, HashSet},
};
use rustfix::{Replacement, Snippet, Solution, Suggestion};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
    ops::Bound,
    panic,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

lazy_static! {
    pub static ref EDIT_OFFSETS: Mutex<EditOffsets> = Mutex::new(EditOffsets::default());
}

/// A heavy-weight span that can be only backed by a real file, and
/// doesn't depend on a backing store like rustc spans.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FatSpan {
    pub file_name: Name,
    pub begin: u32,
    pub end: u32,
}

/// The data structure to keep track of offset changes done during
/// rewrites.
///
/// Each edit effectively takes a range of bytes and replaces them
/// with another range. So, we can represent the changes to offsets
/// done by an edit by a triple `(begin: offset, original_size: size,
/// new_size: size)`. When mapping a position in the new file that
/// comes from the middle of an edit, we cannot pinpoint a single
/// position so we return a range of positions.
#[derive(Default, Debug)]
pub struct EditOffsets {
    per_file_info: HashMap<Name, PerFileEditOffset>,
    /// A dirty bit indicating whether we calculated the cumulative
    /// offsets yet.
    dirty: bool,
}

impl EditOffsets {
    /// Add given edit. Multiple edits at the same offset are
    /// permitted, otherwise multiple overlapping edits are not
    /// permitted. This is in line with the restrictions imposed on us
    /// by `rustfix` and makes the implementation much simpler.
    pub fn add_edit(&mut self, file_name: Name, begin: u32, orig_size: u32, new_size: u32) {
        self.dirty = true;
        // 1. find the relevant snippet
        // 2. check overlap, merge if this is at the beginning/end of that snippet, panic otherwise.
        // 3. if not merging, add this snippet
        let info = self.per_file_info.entry(file_name.clone()).or_default();
        // get the edits just before and just after
        let orig_end = begin + orig_size;

        // get the edits just before the end and check for any overlaps
        let mut edits_before = info
            .edits
            .range((Bound::Unbounded, Bound::Included(&orig_end)));
        let last_before = edits_before
            .next_back()
            .map(|(a, b)| (a.clone(), b.clone()));
        if last_before.is_some() {
            let (b, (o_size, _)) = last_before.clone().unwrap();
            let end_of_last_before = b + o_size;
            if end_of_last_before < orig_end && b > begin {
                // there is an edit that begins in the middle of this one,
                // this is not supported
                panic!(
                    "There are overlapping edits on file `{}`. The first one is {:?}, the second one is {:?}. The printed format is (begin, (original size, new size)).",
                    file_name,
                    last_before.unwrap(),
                    (begin, (orig_size, new_size))
                );
            }
        }

        // get the first edit just after the beginning and check for any overlaps
        let mut edits_after = info
            .edits
            .range((Bound::Included(&begin), Bound::Unbounded));
        let first_after = edits_after.next().map(|(a, b)| (a.clone(), b.clone()));
        if first_after.is_some() {
            let (b, (o_size, _)) = first_after.clone().unwrap();
            let end_of_first_after = b + o_size;
            if end_of_first_after < orig_end && b > begin {
                // there is an edit that begins in the middle of this one,
                // this is not supported
                panic!(
                    "There are overlapping edits on file `{}`. The first one is {:?}, the second one is {:?}. The printed format is (begin, (original size, new size)).",
                    file_name,
                    first_after.unwrap(),
                    (begin, (orig_size, new_size))
                );
            }
        }

        let mut current_edit = (begin, (orig_size, new_size));
        // Merge given edits if possible. Returns true if the edits are merged
        let mut merge_edits = |old_edit: &(u32, (u32, u32))| {
            let current_end = current_edit.0 + (current_edit.1).0;
            let old_edit_end = old_edit.0 + (old_edit.1).0;
            // TODO(maemre): Assert that the edits do not overlap,
            // this should be guaranteed by now.

            if old_edit.0 == current_end {
                // The old edit comes right after, recompute the
                // sizes, the beginning position does not change
                current_edit.1 = (
                    (current_edit.1).0 + (old_edit.1).0,
                    (current_edit.1).1 + (old_edit.1).1,
                );
                true
            } else if old_edit_end == current_edit.0 {
                // The old edit comes right before, copy its beginning
                // and recompute the sizes
                current_edit.0 = old_edit.0;
                current_edit.1 = (
                    (current_edit.1).0 + (old_edit.1).0,
                    (current_edit.1).1 + (old_edit.1).1,
                );
                true
            } else {
                // There is space between the edits
                false
            }
        };

        // there are no overlaps, check for possibility of merging edits
        if last_before == first_after && last_before.is_some() {
            // Case 1: The two edits are the same
            let edit = last_before.unwrap();
            if merge_edits(&edit) {
                // the edits are merged, remove last_before
                info.edits.remove(&edit.0);
            }
        } else {
            // The two edits are different or nonexistent

            // Merge the current edit with last_before if possible
            last_before.map(|edit| {
                if merge_edits(&edit) {
                    // the edits are merged, remove last_before
                    info.edits.remove(&edit.0);
                }
            });

            // Merge the current edit with first_after if possible
            first_after.map(|edit| {
                if merge_edits(&edit) {
                    // the edits are merged, remove last_before
                    info.edits.remove(&edit.0);
                }
            });
        }

        // insert this edit
        info.edits.insert(current_edit.0, current_edit.1);
    }

    pub fn compute_cumulative_offsets(&mut self) {
        for (file_name, info) in &mut self.per_file_info {
            // all edits are ordered and non-overlapping so we can
            // incrementally compute cumulative offsets
            let mut cum_offset = 0i32;
            for (begin, (orig_size, new_size)) in &info.edits {
                // compute the beginning and the end of the snippet in the new file
                let new_begin = (*begin as i32 + cum_offset) as u32;
                let new_end = new_begin + new_size;
                // update the cumulative offset after this edit
                cum_offset = cum_offset + (*new_size as i32) - (*orig_size as i32);
                // insert the offset information related to this edit
                info.cumulative_neg_offsets
                    .insert(new_begin, Offset::Rewritten(*begin));
                // note that we insert the negative offset at this point
                info.cumulative_neg_offsets
                    .insert(new_end, Offset::Normal(-cum_offset));
            }
        }
        self.dirty = false;
    }

    /// Reverse lookup possible origins of a byte position in the new file.
    pub fn reverse_lookup_pos(&self, file_name: &Name, pos: u32) -> (u32, u32) {
        // use panic instead of assert because we want this check even in optimized mode
        if self.dirty {
            panic!("The cumulative offsets are not computed after the last edit!");
        }

        if let Some(info) = self.per_file_info.get(file_name) {
            // find the last entry before (inclusive) the given position
            match info
                .cumulative_neg_offsets
                .range((Bound::Unbounded, Bound::Included(&pos)))
                .next_back()
            {
                Some((_, Offset::Normal(o))) => {
                    // the offset is between edits so there is a single position
                    let orig_pos = u32::try_from(pos as i32 + o).unwrap();
                    (orig_pos, orig_pos)
                },
                Some((_, Offset::Rewritten(lookup_pos))) => {
                    // look up the edit at `lookup_pos` to see range
                    let orig_snippet_size = info.edits[lookup_pos].0;
                    // the current position can come from anywhere between the beginning and the end of the snippet
                    (*lookup_pos, *lookup_pos + orig_snippet_size)
                },
                None => {
                    // the first edit is after pos
                    (pos, pos)
                },
            }
        } else {
            // the file is not edited
            (pos, pos)
        }
    }

    /// Reverse lookup widest possible span that the given span in new
    /// code is derived from.
    pub fn widest_origin_span(&self, span: &FatSpan) -> FatSpan {
        let earliest_begin = self.reverse_lookup_pos(&span.file_name, span.begin).0;
        let latest_end = self.reverse_lookup_pos(&span.file_name, span.end).1;
        FatSpan {
            file_name: span.file_name.clone(),
            begin: earliest_begin,
            end: latest_end,
        }
    }
}

/// A cumulative offset, see the documentation for
/// `PerFileEditOffset.cumulative_neg_offsets` for the meaning of
/// different variants.
#[derive(Debug)]
enum Offset {
    Normal(i32),
    Rewritten(u32),
}

/// Per-file information we hold. We keep track of an ordered map from
/// position to original and new sizes of each snippet, and a
/// cumulative map of offset changes for the code between the edits
/// for a faster lookup.
#[derive(Default, Debug)]
struct PerFileEditOffset {
    /// Original and new size of each edited snippet
    edits: BTreeMap<u32, (u32, u32)>,
    /// Cumulative *negative* offsets so we can lookup the original
    /// byte position, and get a key for edit. For example, if there
    /// is a single edit at byte 5 that changed a 3 byte snippet to a
    /// 6 byte one (so a net of 3 bytes), we will have two entries in this map:
    ///
    /// 11 -> normal(-3) (so, anything after byte 11 should be mapped back by 3 bytes)
    ///
    /// 5 -> rewritten(5) (so, anything between bytes 5 and 11 are
    /// rewritten and should be mapped back according to the snippet
    /// map entry 5)
    ///
    /// We keep an entry for the beginning and the end of the snippet
    /// to find the most relevant entry with one lookup
    cumulative_neg_offsets: BTreeMap<u32, Offset>,
}

/// A map that keeps data associated with spans, and uses a
/// range-tree like construct to look up the data associated with a
/// span.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SpanMap<V: PartialEq + Eq> {
    /// The internal structure is kept as `filename -> begin -> end`,
    /// and the inner map is a `BTreeMap` which allows us to find the
    /// related ranges quickly.
    internal_map: HashMap<Name, BTreeMap<u32, (u32, V)>>,
}

impl<V: PartialEq + Eq> SpanMap<V> {
    pub fn new() -> Self {
        SpanMap::<V> {
            internal_map: HashMap::default(),
        }
    }

    /// Returns the value associated with the span that strictly
    /// contains `line_span`, if no span contains `line_span`
    /// completely (e.g. when there is a partial overlap), then this
    /// method returns `None`.
    pub fn get<'a>(&'a self, span: &FatSpan) -> Option<&'a V> {
        // get the last element that is before `line_span.begin`
        self.internal_map.get(&span.file_name).and_then(|m| {
            m.range((Bound::Unbounded, Bound::Included(span.begin)))
                .next_back()
                .and_then(
                    |(_begin, (end, value))| {
                        if span.end <= *end { Some(value) } else { None }
                    },
                )
        })
    }

    pub fn get_mut<'a>(&'a mut self, line_span: &FatSpan) -> Option<&'a mut V> {
        // get the last element that is before `line_span.begin`
        self.internal_map
            .get_mut(&line_span.file_name)
            .and_then(|m| {
                m.range_mut((Bound::Unbounded, Bound::Included(line_span.begin)))
                    .next_back()
                    .and_then(|(_begin, (end, value))| {
                        if line_span.end <= *end {
                            Some(value)
                        } else {
                            None
                        }
                    })
            })
    }

    /// Insert given value, return true if insertion is successful, false if there are already overlapping spans
    pub fn insert(&mut self, span: FatSpan, value: V) -> bool {
        if let Some(m) = self.internal_map.get_mut(&span.file_name) {
            // Find the spans that start before `line_span.end` to
            // look for partial matches.
            //
            // TODO(maemre): This is effectively a linear search,
            // implement a proper interval tree for performance later.
            if m.range((Bound::Unbounded, Bound::Included(span.end)))
                .all(|(_begin, (end, _))| *end < span.begin)
            {
                // For all intervals, if begin <= line_span.end, then
                // end < line_span.begin. By classical logic, either
                // is true:
                //
                // - end < line_span.begin so there is no overlap
                // - begin > line_span.end so there is no overlap
                m.insert(span.begin, (span.end, value));
                true
            } else {
                let overlapping_spans = m
                    .range((Bound::Unbounded, Bound::Included(span.end)))
                    .filter(|(_begin, (end, _))| *end >= span.begin)
                    .map(|(b, (e, _))| (*b, *e))
                    .collect::<Vec<(u32, u32)>>();
                panic!(
                    "cannot insert {:?}, there are overlapping spans: {:?}",
                    span, overlapping_spans
                );
            }
        } else {
            // this is the first entry for this file, just insert it
            let mut m = BTreeMap::new();
            m.insert(span.begin, (span.end, value));
            self.internal_map.insert(span.file_name, m);
            true
        }
    }
}

/// A map that keeps data associated with spans that overlap, and uses
/// a range-tree like construct to look up the data associated with a
/// span.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OverlappingSpanMap<V: PartialEq + Eq> {
    /// The internal structure is kept as `filename -> begin -> end`,
    /// and the inner map is a `BTreeMap` which allows us to find the
    /// related ranges quickly.
    internal_map: HashMap<Name, BTreeMap<u32, (u32, V)>>,
}

impl<V: PartialEq + Eq> Default for OverlappingSpanMap<V> {
    fn default() -> Self {
        OverlappingSpanMap::new()
    }
}

impl<V: PartialEq + Eq> OverlappingSpanMap<V> {
    pub fn new() -> Self {
        OverlappingSpanMap {
            internal_map: HashMap::default(),
        }
    }

    /// Returns the value associated with the smallest span that
    /// strictly contains `line_span`, if no span contains `line_span`
    /// completely (e.g. when there is a partial overlap), then this
    /// method returns `None`. If there are more than one overlapping
    /// spans that contains the given span, then this method picks the
    /// one that starts last.
    pub fn get<'a>(&'a self, span: &FatSpan) -> Option<&'a V> {
        // get the elements that are before `span.begin` and find
        // something that contains `span.end`.
        self.internal_map.get(&span.file_name).and_then(|m| {
            m.range((Bound::Unbounded, Bound::Included(span.begin)))
                .rfind(|(_, (end, _))| span.end <= *end)
                .map(|(_, (_, value))| value)
        })
    }

    pub fn get_mut<'a>(&'a mut self, span: &FatSpan) -> Option<&'a mut V> {
        // get the elements that are before `span.begin` and find
        // something that contains `span.end`.
        self.internal_map.get_mut(&span.file_name).and_then(|m| {
            m.range_mut((Bound::Unbounded, Bound::Included(span.begin)))
                .rfind(|(_, (end, _))| span.end <= *end)
                .map(|(_, (_, value))| value)
        })
    }

    /// Insert given value without any checks for overlaps. Returns the previous value if there was already a value for this span
    pub fn insert(&mut self, span: FatSpan, value: V) -> Option<V> {
        self.internal_map
            .entry(span.file_name)
            .or_default()
            .insert(span.begin, (span.end, value))
            .map(|p| p.1)
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct SpanInfo {
    /// Look-up table for spans of each function
    pub fn_spans: HashMap<Name, FatSpan>,
    /// Reverse look-up table for spans of each function
    pub reverse_fn_spans: SpanMap<Name>,
    /// Look-up table for each span to the ID of the expression
    /// covering it
    pub span_to_hir_id: OverlappingSpanMap<HirId>,
}

impl SpanInfo {
    /// Find the ID of the smallest expression that contains the given span
    pub fn lookup_hir_id(&self, span: &FatSpan) -> Option<HirId> {
        self.span_to_hir_id.get(span).cloned()
    }
}

impl analysis::AnalysisResult for SpanInfo {
    fn name() -> String {
        "SpanInfo".to_owned()
    }
}

/// A pass to build line spans and stable spans.
pub struct SpanInfoPass {
    info: SpanInfo,
}

impl SpanInfoPass {
    pub fn new() -> Box<LatePass> {
        log::info!("Created SpanInfoPass");
        Box::new(SpanInfoPass {
            info: SpanInfo::default(),
        })
    }
}

impl LintPass for SpanInfoPass {
    fn name(&self) -> &'static str {
        "SpanInfoPass"
    }
}

impl<'tcx> LateLintPass<'tcx> for SpanInfoPass {
    fn check_fn_post(
        &mut self,
        ctx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        hir_id: HirId,
    ) {
        if matches!(kind, FnKind::Method(..)) && is_synthetic_fn(decl, body)
            || span.from_expansion()
        {
            // This is a macro-generated method, skip it
            return;
        }

        let name = Name::from(get_hir_qname(ctx, hir_id));
        let source_map = ctx.sess().source_map();
        let fname = source_map.span_to_filename(span);
        let file_name = match &fname {
            FileName::Real(ref n) => Name::from(n.local_path().unwrap().to_str().unwrap()),
            _ => {
                return;
            },
        };
        let file = source_map.get_source_file(&fname).unwrap();
        let lo_offset = file.original_relative_byte_pos(span.lo()).0;
        let hi_offset = file.original_relative_byte_pos(span.hi()).0;
        let span = FatSpan {
            file_name,
            begin: lo_offset as u32,
            end: hi_offset as u32,
        };

        self.info.fn_spans.insert(name.clone(), span.clone());
        assert!(
            self.info
                .reverse_fn_spans
                .insert(span.clone(), name.clone()),
            "Failed to insert the line span {:?} for function `{}`",
            span,
            name
        );
    }

    fn check_expr(&mut self, ctx: &LateContext<'tcx>, e: &'tcx Expr<'tcx>) {
        // TODO: get the owner function's name to keep the maps
        // smaller for quicker lookup, and write custom recursion to
        // keep the file name around
        let span = e.span;
        let source_map = ctx.sess().source_map();
        let fname = source_map.span_to_filename(span);
        let file_name = match &fname {
            FileName::Real(ref n) => Name::from(n.local_path().unwrap().to_str().unwrap()),
            _ => {
                return;
            },
        };
        let file = source_map.get_source_file(&fname).unwrap();
        let lo_offset = file.original_relative_byte_pos(span.lo()).0;
        let hi_offset = file.original_relative_byte_pos(span.hi()).0;
        let span = FatSpan {
            file_name,
            begin: lo_offset as u32,
            end: hi_offset as u32,
        };

        self.info.span_to_hir_id.insert(span, e.hir_id);
    }

    fn check_crate_post(&mut self, _: &LateContext<'tcx>) {
        // Update analysis results
        analysis::replace::<SpanInfo>(Box::new(std::mem::take(&mut self.info)));
        log::info!("updated span info");
    }
}

// TODO: Implement span building analysis
// TODO: Implement ownership analysis
