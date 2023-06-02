//! Configurations as described in the OOPSLA paper. Initial program
//! creation can assume an empty configuration, later configurations
//! will be derived using taint analyses.

use crate::{
    analysis::AnalysisResult,
    ptr_provenance::{Loc, SerializableHirId},
    rustc_hir::HirId,
    serde::{Deserialize, Serialize},
    types::*,
    util::{HashMap, HashSet},
};
use lazy_static::lazy_static;
use std::{
    cmp::{Ordering, PartialOrd},
    fmt,
    fmt::Debug,
    sync::RwLock,
};

lazy_static! {
    /// The current configuration we are using
    pub static ref CONFIG: RwLock<Configuration> = RwLock::new(Configuration::default());
}

/// What parts of the configuration have changed
#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConfigChange {
    Unchanged,
    /// A change in pointer kinds, this means the lifetime constraints
    /// have been reset.
    PtrKind,
    MoveFlows,
    LifetimeConstraints,
}

/// Qualifiers for generics or lifetimes indicating where in the code
/// they belong to (e.g. struct `foo::Bar` or fn `quux::baz`).
///
/// Each qualifier is a place a generic variable may occur (structs
/// and functions for now).
#[derive(PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
pub struct Qual {
    /// kind of the organizational unit
    pub kind: QualKind,
    /// qualified name of this organizational unit
    pub q_name: Name,
}

impl Debug for Qual {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.q_name)
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum QualKind {
    Fn,
    Struct,
}

/// Different kinds of pointers we care about. This type implements
/// `std::cmp::PartialOrd` with the lattice ordering.
///
/// ```
///         Raw
///          |
///     OwnedRefCell
///        /  \
///    Owned  RefCell
///       \    /
///      Borrowing
/// ```
#[derive(PartialEq, Eq, Hash, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PtrKind {
    Borrowing,
    RefCell,
    Owned,
    OwnedRefCell,
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
            // Not using `(x, y) if x == y` to enable exhaustive pattern warnings
            (Borrowing, Borrowing)
            | (RefCell, RefCell)
            | (Owned, Owned)
            | (OwnedRefCell, OwnedRefCell)
            | (Raw, Raw) => Some(Ordering::Equal),
            (Borrowing, _) | (_, Raw) | (Owned, OwnedRefCell) | (RefCell, OwnedRefCell) => {
                Some(Ordering::Less)
            },
            (_, Borrowing) | (Raw, _) | (OwnedRefCell, Owned) | (OwnedRefCell, RefCell) => {
                Some(Ordering::Greater)
            },
            (RefCell, Owned) | (Owned, RefCell) => None,
        }
    }
}

impl PtrKind {
    pub fn join(&self, other: &PtrKind) -> PtrKind {
        use PtrKind::*;

        match (*self, *other) {
            (RefCell, Owned) | (Owned, RefCell) => OwnedRefCell,
            (x, y) => match x.partial_cmp(&y) {
                Some(Ordering::Less) => y,
                Some(Ordering::Equal) | Some(Ordering::Greater) => x,
                None => unreachable!(
                    "There should not be a case left for the join of {:?} and {:?}",
                    *self, *other
                ),
            },
        }
    }

    pub fn add_owned(&self) -> PtrKind {
        use PtrKind::*;

        match *self {
            RefCell => OwnedRefCell,
            Borrowing => Owned,
            _ => *self,
        }
    }

    pub fn add_refcell(&self) -> PtrKind {
        use PtrKind::*;

        match *self {
            Owned => OwnedRefCell,
            Borrowing => RefCell,
            _ => *self,
        }
    }

    #[inline(always)]
    /// Lattice bottom value
    pub fn bot() -> PtrKind {
        PtrKind::Borrowing
    }
}

#[derive(PartialEq, Eq, Clone, Default, Serialize, Deserialize)]
pub struct Configuration {
    /// Pointer kinds, if there is no entry for a location, then it is
    /// a borrowing pointer. This API is mostly stable, but we may
    /// switch to more approximate locations instead of HIR IDs later
    /// on.
    pub ptr_kind: HashMap<Loc<Name>, PtrKind>,

    /// Set of expressions that borrow a value that should be upgraded to move it instead.
    pub move_flows: HashSet<SerializableHirId>,

    /// Upper bounds of each lifetime, so if there is a function `foo`
    /// with the signature `fn foo<...>(...) where 'a1 : 'a2, 'a1:
    /// 'a3` then this map contains the entry `{'a1 -> {'a2, 'a3}}`
    /// for the key `foo`.
    ///
    /// This map is guaranteed to be empty for the initial program.
    pub bounds: HashMap<Qual, HashMap<Lifetime, HashSet<Lifetime>>>,
}

/// Helper types for debug printing support
mod debug {
    use super::Qual;
    use crate::{
        types::*,
        util::{HashMap, HashSet},
    };
    use std::{fmt, fmt::Debug};

    /// A wrapper around lifetimes for pretty-printing even with the debug formatter.
    struct PrettyLifetime<'a>(&'a Lifetime);
    impl<'a> Debug for PrettyLifetime<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    struct LifetimeSet<'a, T: IntoIterator<Item = &'a Lifetime>>(&'a T);
    impl<'a, T: Copy + IntoIterator<Item = &'a Lifetime>> Debug for LifetimeSet<'a, T> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // TODO: update to use the iter_intersperse feature for performance when
            // we switch to a new compiler version.
            let v = self
                .0
                .into_iter()
                .map(|l| l.as_ref())
                .collect::<Vec<&str>>()
                .join(" + ");
            write!(f, "{}", v)
        }
    }

    struct PerQualBoundsMap<'a>(&'a HashMap<Lifetime, HashSet<Lifetime>>);

    impl<'a> Debug for PerQualBoundsMap<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut m = f.debug_map();
            for (lower, upper) in self.0 {
                m.entry(&PrettyLifetime(lower), &LifetimeSet(&upper));
            }
            m.finish()
        }
    }

    pub struct BoundsMap<'a>(pub &'a HashMap<Qual, HashMap<Lifetime, HashSet<Lifetime>>>);

    impl<'a> Debug for BoundsMap<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let mut m = f.debug_map();
            for (lower, upper) in self.0 {
                m.entry(lower, &PerQualBoundsMap(&upper));
            }
            m.finish()
        }
    }
}

impl Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Configuration")
            .field("ptr_kind", &self.ptr_kind)
            .field("move_flows", &self.move_flows)
            .field("bounds", &debug::BoundsMap(&self.bounds))
            .finish()
    }
}

impl Configuration {
    /// Compute the lattice join of this and the other
    /// configuration. Returns information on which parts of the
    /// configuration have changed.
    pub fn join(&mut self, other: Configuration) -> ConfigChange {
        let mut changed = ConfigChange::Unchanged;

        // pointwise join of pointer kinds
        for (loc, other_kind) in other.ptr_kind {
            // Treat empty entries as bottom
            let kind_in_self = self.ptr_kind.entry(loc).or_insert(PtrKind::bot());
            // copy the old value
            let old_value = *kind_in_self;
            *kind_in_self = old_value.join(&other_kind);

            if changed == ConfigChange::Unchanged && old_value != *kind_in_self {
                changed = ConfigChange::PtrKind;
            }
        }

        // Note: move flows don't change pointer kinds for anything
        // involving named lifetime variables. So, we update the type
        // of change to be MoveFlows only if it was previously Unchanged.
        let old_len = self.move_flows.len();
        self.move_flows.extend(other.move_flows);
        if changed == ConfigChange::Unchanged && self.move_flows.len() > old_len {
            changed = ConfigChange::MoveFlows;
        }

        // If the pointer kinds have changed, undo all bounds. This is
        // costier but easier to implement than finding a stable
        // mapping of automatically-generated lifetime names.
        if changed == ConfigChange::PtrKind {
            self.bounds = HashMap::default();
        } else {
            // pointwise join the lifetimes
            for (qual, bounds) in other.bounds {
                for (lower, uppers) in bounds {
                    for upper in uppers {
                        if self.add_bound(qual.clone(), lower.clone(), upper)
                            && changed == ConfigChange::Unchanged
                        {
                            changed = ConfigChange::LifetimeConstraints
                        }
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

    pub fn promote_borrow_to_move(&mut self, id: HirId) {
        self.move_flows.insert(SerializableHirId(id));
    }

    pub fn is_move(&self, id: HirId) -> bool {
        self.move_flows.contains(&SerializableHirId(id))
    }

    pub fn ptr_kind(&self, loc: &Loc<Name>) -> PtrKind {
        self.ptr_kind.get(loc).cloned().unwrap_or(PtrKind::bot())
    }
}

impl AnalysisResult for Configuration {
    fn name() -> String {
        "Configuration".to_owned()
    }
}
