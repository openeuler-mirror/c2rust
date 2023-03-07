pub mod equality_based;
pub mod set_based;

use crate::Name;
use std::{fmt::Debug, hash::Hash};

#[derive(Debug)]
pub enum ConstraintError<Var> {
    CtorMismatch(Ctor<Var>, Ctor<Var>),
    EmptynessViolation(Constraint<u32>),
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// A constructor term, the first field is the tag, the second one is
/// the sequence of covariant arguments, the third one is the
/// contravariant arguments.
pub struct Ctor<Var>(pub Name, pub Vec<SimpleTerm<Var>>, pub Vec<SimpleTerm<Var>>);

impl<Var: Debug> Debug for Ctor<Var> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({:?}; {:?})", self.0, self.1, self.2)
    }
}

impl<Var> Ctor<Var> {
    pub fn repack<U, F: FnMut(Var) -> U>(self, f: &mut F) -> Ctor<U> {
        Ctor(
            self.0,
            self.1.into_iter().map(|s| s.repack(f)).collect(),
            self.2.into_iter().map(|s| s.repack(f)).collect(),
        )
    }

    pub fn simple(tag: Name, co: Vec<Var>, contra: Vec<Var>) -> Self {
        Ctor(
            tag,
            co.into_iter().map(SimpleTerm::LV).collect(),
            contra.into_iter().map(SimpleTerm::LV).collect(),
        )
    }
}

/// Non-constructor terms, these can be arguments to constructors
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum SimpleTerm<Var> {
    /// A logic variable X
    LV(Var),
    /// The empty set, ignored in equality solver
    EmptySet,
    /// The set of everything, ignored in equality solver
    All,
}

impl<Var> SimpleTerm<Var> {
    pub fn repack<U, F: FnMut(Var) -> U>(self, f: &mut F) -> SimpleTerm<U> {
        use SimpleTerm::*;

        match self {
            LV(x) => LV(f(x)),
            EmptySet => EmptySet,
            All => All,
        }
    }

    pub fn is_lv(&self) -> bool {
        matches!(self, SimpleTerm::LV(_))
    }

    pub fn unwrap_lv(&self) -> &Var {
        if let SimpleTerm::LV(x) = self {
            x
        } else {
            panic!("Tried to unwrap LV out of a non-LV simple term")
        }
    }
}

/// A term for using constructors in constraints
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Term<Var> {
    /// A constructor c(E1, ..., En)
    C(Ctor<Var>),
    /// A simple term
    S(SimpleTerm<Var>),
}

impl<Var> Term<Var> {
    pub fn repack<U, F: FnMut(Var) -> U>(self, f: &mut F) -> Term<U> {
        use Term::*;

        match self {
            C(ctor) => C(ctor.repack(f)),
            S(st) => S(st.repack(f)),
        }
    }

    /// Extract the logic variable case
    pub fn get_lv(&self) -> Option<&Var> {
        match self {
            Term::S(SimpleTerm::LV(x)) => Some(x),
            _ => None,
        }
    }

    /// Consume this term and extract the logic variable inside
    pub fn into_lv(self) -> Option<Var> {
        match self {
            Term::S(SimpleTerm::LV(x)) => Some(x),
            _ => None,
        }
    }
}

impl<Var: Debug> Term<Var> {
    pub fn extract_simple(self) -> SimpleTerm<Var> {
        use Term::*;

        match self {
            S(s) => s,
            C(c) => panic!("Tried extracting simple term out of constructor `{:?}`", c),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// A constraint to be represented in the set-based constraint
/// system. This represents an edge in the subset graph.
pub struct Constraint<Var>(pub Term<Var>, pub Term<Var>);

impl<Var> Constraint<Var> {
    pub fn repack<U, F: FnMut(Var) -> U>(self, f: &mut F) -> Constraint<U> {
        Constraint(self.0.repack(f), self.1.repack(f))
    }
}

impl<Var> std::fmt::Display for Constraint<Var>
where
    Var: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?} ⊆ {:?}", self.0, self.1)
    }
}

impl<Var> std::fmt::Debug for Constraint<Var>
where
    Var: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{:?} ⊆ {:?}", self.0, self.1)
    }
}
