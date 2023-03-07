//! Configurations as described in the OOPSLA paper. Initial program
//! creation can assume an empty configuration, later configurations
//! will be derived using taint analyses.

use crate::{
    analysis::AnalysisResult,
    ptr_provenance::Loc,
    types::*,
    util::{HashMap, HashSet},
};
use lazy_static::lazy_static;
use std::{
    cmp::{Ordering, PartialOrd},
    sync::RwLock,
};

lazy_static! {
    /// The current configuration we are using
    pub static ref CONFIG: RwLock<Configuration> = RwLock::new(Configuration::default());
}

/// Qualifiers for generics or lifetimes indicating where in the code
/// they belong to (e.g. struct `foo::Bar` or fn `quux::baz`).
///
/// Each qualifier is a place a generic variable may occur (structs
/// and functions for now).
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Qual {
    /// kind of the organizational unit
    pub kind: QualKind,
    /// qualified name of this organizational unit
    pub q_name: Name,
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum QualKind {
    Fn,
    Struct,
}

/// Different kinds of pointers we care about. This type implements
/// `std::cmp::PartialOrd` with the lattice ordering.
#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
pub enum PtrKind {
    Borrowing,
    Owned,
    Raw,
}

impl Default for PtrKind {
    fn default() -> Self {
        PtrKind::Borrowing
    }
}

impl PartialOrd for PtrKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        use PtrKind::*;

        match (self, other) {
            (x, y) if x == y => Some(Ordering::Equal),
            (Borrowing, _) | (_, Raw) => Some(Ordering::Less),
            _ => Some(Ordering::Greater),
        }
    }
}

impl PtrKind {
    pub fn join(&self, other: &PtrKind) -> PtrKind {
        use PtrKind::*;

        match (*self, *other) {
            (x, y) if x == y => x,
            (Borrowing, other) => other,
            (this, Borrowing) => this,
            (Raw, _) | (_, Raw) => Raw,
            // There are no remaining cases
            (_, _) => unreachable!(
                "There should not be a case left for the join of {:?} and {:?}",
                *self, *other
            ),
        }
    }

    #[inline(always)]
    /// Lattice bottom value
    pub fn bot() -> PtrKind {
        PtrKind::Borrowing
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct Configuration {
    /// Pointer kinds, if there is no entry for a location, then it is
    /// a borrowing pointer. This API is mostly stable, but we may
    /// switch to more approximate locations instead of HIR IDs later
    /// on.
    pub ptr_kind: HashMap<Loc<Name>, PtrKind>,

    /// Upper bounds of each lifetime, so if there is a function `foo`
    /// with the signature `fn foo<...>(...) where 'a1 : 'a2, 'a1:
    /// 'a3` then this map contains the entry `{'a1 -> {'a2, 'a3}}`
    /// for the key `foo`.
    ///
    /// This map is guaranteed to be empty for the initial program.
    pub bounds: HashMap<Qual, HashMap<Lifetime, HashSet<Lifetime>>>,
}

impl Configuration {
    /// Compute the lattice join of this and the other
    /// configuration. Returns true if this configuration has changed.
    pub fn join(&mut self, other: Configuration) -> bool {
        let mut changed = false;

        // pointwise join of pointer kinds
        for (loc, other_kind) in other.ptr_kind {
            // Treat empty entries as bottom
            let kind_in_self = self.ptr_kind.entry(loc).or_insert(PtrKind::bot());
            // copy the old value
            let old_value = *kind_in_self;
            *kind_in_self = old_value.join(&other_kind);
            changed = changed || old_value != *kind_in_self;
        }

        // If the pointer kinds have changed, undo all bounds. This is
        // costier but easier to implement than finding a stable
        // mapping of automatically-generated lifetime names.
        if changed {
            self.bounds = HashMap::default();
        } else {
            // pointwise join the lifetimes
            for (qual, bounds) in other.bounds {
                for (lower, uppers) in bounds {
                    for upper in uppers {
                        changed = self.add_bound(qual.clone(), lower.clone(), upper) || changed;
                    }
                }
            }
        }

        changed
    }

    /// Add a lifetime bound. Return true if this bound was not already present.
    pub fn add_bound(&mut self, qual: Qual, lower: Lifetime, upper: Lifetime) -> bool {
        self.bounds
            .entry(qual)
            .or_default()
            .entry(lower)
            .or_default()
            .insert(upper)
    }

    pub fn promote_ptr_kind(&mut self, loc: Loc<Name>, kind: PtrKind) {
        let saved_kind = self.ptr_kind.entry(loc).or_insert(PtrKind::bot());
        *saved_kind = saved_kind.join(&kind);
    }
}

impl AnalysisResult for Configuration {
    fn name() -> String {
        "Configuration".to_owned()
    }
}
