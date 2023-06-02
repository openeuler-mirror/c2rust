/// Equality-based constraint solver for analyses in different stages.
use crate::util::{HashMap, HashSet};
use crate::{solver::*, Name};
use std::{fmt::Debug, hash::Hash};

/// A set-based constraint system where `Var` is the type of
/// variables. It supports constraints of the form `t1 ⊆ t2` where
/// `t1` and `t2` are terms, that are either a variable `X`, or a
/// complex term of the form `c(X1, ..., Xn)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConstraintSystem<Var: Eq + Hash, Poison: Eq + Hash + Clone> {
    /// A mapping from variables to numbers to allow using vectors
    var_to_num: HashMap<Var, u32>,
    /// A reverse-lookup table to find the variables for a given number
    num_to_var: Vec<Var>,
    /// Parent part of union-find
    parent: Vec<u32>,
    /// Rank part of union-find
    rank: Vec<u32>,
    /// Constructors the root of each disjoint set
    ctor_map: HashMap<u32, HashMap<Name, Ctor<u32>>>,
    /// Poison data to carry along when merging variables
    poison: HashMap<u32, HashSet<Poison>>,
}

/*
// Equality implementation that ignores roots and compares the disjoint sets directly
impl<V: Eq + PartialEq + Clone + Hash + Debug,  Poison: Eq + Clone + Hash + Debug> PartialEq for ConstraintSystem<V, Poison> {
    fn eq(&self, other: &Self) -> bool {
        // Get and compare the disjoint sets

        // For each variable, get the set of constructors
    }
}*/

impl<V: Eq + Clone + Hash + Debug, Poison: Eq + Clone + Hash + Debug> ConstraintSystem<V, Poison> {
    pub fn new() -> Self {
        ConstraintSystem {
            var_to_num: HashMap::default(),
            num_to_var: Vec::new(),
            parent: Vec::default(),
            rank: Vec::default(),
            ctor_map: HashMap::default(),
            poison: HashMap::default(),
        }
    }

    pub fn parent(&self) -> &Vec<u32> {
        &self.parent
    }

    /// Inefficient version of find
    pub fn find(&self, mut x: u32) -> u32 {
        // imperative version because Rust doesn't have TCO
        while x != self.parent[x as usize] {
            x = self.parent[x as usize];
        }
        x
    }

    pub fn find_mut(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            // path halving
            let p = self.parent[x as usize];
            self.parent[x as usize] = self.parent[p as usize];
            x = self.parent[x as usize];
        }
        x
    }

    pub fn ctor_map(&self, x: u32) -> Option<&HashMap<Name, Ctor<u32>>> {
        self.ctor_map.get(&self.find(x))
    }

    /// Compute constructors from the root, this copies the
    /// constructors, and does not give the full combinations, but
    /// picks a representative for each constructor tag.
    #[cfg(test)]
    pub fn ctors(&mut self, x: &V) -> HashSet<Ctor<V>> {
        let num_x = self.to_num(x);
        let root = self.find_mut(num_x);
        let mut ctors = HashSet::default();
        if let Some(ctor_map) = self.ctor_map.get(&root) {
            for cs in ctor_map.values() {
                ctors.insert(
                    cs.clone()
                        .repack(&mut |n: u32| self.num_to_var[n as usize].clone()),
                );
            }
        }
        ctors
    }

    /// Compute union of two simple terms, ignoring empty set and the
    /// universe.
    fn union(&mut self, x: SimpleTerm<u32>, y: SimpleTerm<u32>) {
        use SimpleTerm::*;

        if let (LV(x), LV(y)) = (x, y) {
            self.union_var(x, y);
        }
    }

    fn union_var(&mut self, x: u32, y: u32) {
        // replace nodes by their roots, while path halving
        let mut x = self.find_mut(x);
        let mut y = self.find_mut(y);

        if x == y {
            // they are in the same set
            return;
        }

        // order ranks
        if self.rank[x as usize] < self.rank[y as usize] {
            std::mem::swap(&mut x, &mut y);
        }

        // x is the new root
        self.parent[y as usize] = x;
        // update the rank of x
        if self.rank[x as usize] == self.rank[y as usize] {
            self.rank[x as usize] += 1;
        }
        // move the constructors of y to x
        if let Some(ctors_of_y) = self.ctor_map.remove(&y) {
            for (_, ctor) in ctors_of_y {
                self.add_ctor(x, ctor);
            }
        }
        // merge poison sets
        if let Some(poison_of_y) = self.poison.remove(&y) {
            self.poison.entry(x).or_default().extend(poison_of_y);
        }
    }

    #[must_use]
    pub fn add_goal(&mut self, goal: Constraint<V>) -> Result<(), ConstraintError<V>> {
        let num_goal = goal.repack(&mut |x| self.to_num(&x));
        self.add_num_goal(num_goal)
    }

    pub fn add_poison(&mut self, x: V, poison: Poison) {
        let num_x = self.to_num(&x);
        let root = self.find_mut(num_x);
        self.poison.entry(root).or_default().insert(poison);
    }

    /// Add `ctor` to the constructor map of `x`
    pub fn add_ctor(&mut self, x: u32, ctor: Ctor<u32>) {
        let root = self.find_mut(x);
        if let Some(old) = self.ctor_map.entry(root).or_default().get(&ctor.0).cloned() {
            // there is another ctor of the same name in the root of
            // x, merge ctors.
            //
            // TODO: occurs check

            assert!(old.1.len() == ctor.1.len());
            // Treat λ specially because of varargs, and propagate arguments in
            // a best-effort way. λ is contravariant on parameters but still has
            // a single return value, so we discard only the contravariant
            // argument length check.
            if ctor.0 != Name::from("λ") {
                assert!(old.2.len() == ctor.2.len());
            } else {
                // Insert the longer λ as the λ associated with x
                if ctor.2.len() > old.2.len() {
                    self.ctor_map
                        .get_mut(&root)
                        .unwrap()
                        .insert(ctor.0.clone(), ctor.clone());
                }
            }
            old.1
                .into_iter()
                .zip(ctor.1)
                .for_each(|(a, b)| self.union(a, b));
            old.2
                .into_iter()
                .zip(ctor.2)
                .for_each(|(a, b)| self.union(a, b));
        } else {
            // there are not ctors, just add the new one
            self.ctor_map
                .get_mut(&root)
                .unwrap()
                .insert(ctor.0.clone(), ctor);
        }
    }

    #[must_use]
    #[inline(always)]
    fn add_num_goal(&mut self, goal: Constraint<u32>) -> Result<(), ConstraintError<V>> {
        use SimpleTerm::*;
        use Term::*;

        // Add the goal to the constraint graph on-the-go
        match goal {
            Constraint(S(EmptySet), _)
            | Constraint(S(All), _)
            | Constraint(_, S(EmptySet))
            | Constraint(_, S(All)) => {},
            Constraint(S(LV(x)), S(LV(y))) => {
                self.union_var(x, y);
            },
            Constraint(C(c), S(LV(x))) => {
                self.add_ctor(x, c);
            },
            Constraint(S(LV(x)), C(c)) => {
                self.add_ctor(x, c);
            },
            Constraint(C(c), C(d))
                if c.0 != d.0 || c.1.len() != d.1.len() || c.2.len() != d.2.len() => {},
            Constraint(C(Ctor(_, lower, lower_contra)), C(Ctor(_, upper, upper_contra))) => {
                // TODO: occurs check
                lower
                    .into_iter()
                    .zip(upper)
                    .for_each(|(l, u)| self.union(l, u));
                lower_contra
                    .into_iter()
                    .zip(upper_contra)
                    .for_each(|(l, u)| self.union(u, l));
                todo!();
            },
        }

        Ok(())
    }

    /// Get the number for `x`, assign it a number if one is not
    /// assigned yet. This will clone `x` if it is not assigned a
    /// number.
    pub fn to_num(&mut self, x: &V) -> u32 {
        if let Some(n) = self.var_to_num.get(x) {
            *n
        } else {
            let next_num = self.parent.len() as u32;
            self.num_to_var.push(x.clone());
            self.var_to_num.insert(x.clone(), next_num);
            self.parent.push(next_num);
            self.rank.push(0);
            next_num
        }
    }

    /// Get the number for `x` if there is one.
    pub fn to_maybe_num(&self, x: &V) -> Option<u32> {
        self.var_to_num.get(x).copied()
    }

    /// Get the variable for `x` if there is one.
    pub fn to_var(&self, x: u32) -> Option<&V> {
        self.num_to_var.get(x as usize)
    }

    /// Copies and returns the set of variables equivalent to x. This
    /// operation is O(n).
    ///
    /// TODO(maemre): We can make this O(size of the set) rather than
    /// O(# vars) if we precompute the child nodes on union, which
    /// would be amortized O(1) I think.
    pub fn compute_eqset(&mut self, x: &V) -> HashSet<V> {
        let num_x = self.to_num(x);
        let root = self.find_mut(num_x);
        let mut s = HashSet::default();
        for y in 0..self.num_to_var.len() {
            if self.find_mut(y as u32) == root {
                s.insert(self.num_to_var[y].clone());
            }
        }
        s
    }

    /// Copies and returns the equivalence classes, mapped by the
    /// root, does not optimize the union-find data structure.
    pub fn compute_eq_classes_slow(&self) -> HashMap<u32, HashSet<V>> {
        let mut eq_classes: HashMap<u32, HashSet<V>> = HashMap::default();
        for x in 0..self.num_to_var.len() {
            let root = self.find(x as u32);
            let s = eq_classes.entry(root).or_default();
            s.insert(self.num_to_var[x].clone());
        }
        eq_classes
    }

    /// Copies and returns the equivalence classes, mapped by the
    /// root.
    pub fn compute_eq_classes(&mut self) -> HashMap<u32, HashSet<V>> {
        let mut eq_classes: HashMap<u32, HashSet<V>> = HashMap::default();
        for x in 0..self.num_to_var.len() {
            let root = self.find_mut(x as u32);
            let s = eq_classes.entry(root).or_default();
            s.insert(self.num_to_var[x].clone());
        }
        eq_classes
    }

    /// Check for equality without optimizing the underlying data structure
    pub fn eq(&self, x: &V, y: &V) -> bool {
        let x = self.var_to_num[x];
        let y = self.var_to_num[y];
        self.find(x) == self.find(y)
    }

    /// Check for equality while compacting the union-find data
    /// structure. Use this over `eq` whenever possible
    pub fn eq_mut(&mut self, x: &V, y: &V) -> bool {
        let x = self.var_to_num[x];
        let y = self.var_to_num[y];
        self.find_mut(x) == self.find_mut(y)
    }

    pub fn vars(&self) -> Vec<V> {
        self.num_to_var.clone()
    }

    /// Solve the constraint system for goals, starting from sets as
    /// the initial sets.
    pub fn solve(&mut self) -> Result<(), ConstraintError<V>> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_hash_set<T: Eq + Hash>(v: Vec<T>) -> HashSet<T> {
        v.into_iter().collect()
    }

    #[test]
    fn term_repack() {
        use SimpleTerm::*;
        use Term::*;

        let mut f = |n: u32| n.to_string();

        assert_eq!(S(LV("3".to_owned())), S(LV(3).repack(&mut f)));
        assert_eq!(
            C(Ctor::simple(
                Name::from("c"),
                vec!["3".to_owned(), "4".to_owned()],
                vec!["5".to_owned(), "6".to_owned()]
            )),
            C(Ctor::simple(Name::from("c"), vec![3, 4], vec![5, 6])).repack(&mut f)
        );
    }

    #[test]
    fn solve_idempotency() {
        use SimpleTerm::*;
        use Term::*;

        let mut sys = ConstraintSystem::<u32, ()>::new();
        sys.add_goal(Constraint(S(LV(3)), S(LV(4)))).unwrap();

        sys.solve()
            .expect("The constraint system should not have errors");

        let mut hash_set_4 = HashSet::default();
        hash_set_4.insert(3);
        hash_set_4.insert(4);

        assert!(sys.ctors(&3).is_empty());
        assert!(sys.ctors(&4).is_empty());
        assert!(sys.ctors(&3).is_empty());
        assert!(sys.ctors(&4).is_empty());
        assert_eq!(&sys.compute_eqset(&3), &hash_set_4);
        assert_eq!(&sys.compute_eqset(&4), &hash_set_4);
    }

    #[test]
    fn solve_transitivity() {
        use SimpleTerm::*;
        use Term::*;

        // Testing the following set of constraints:
        //
        // 1 = 2
        // 2 = 3
        // 3 = 4
        //
        // The solution has the following sets:
        // {1, 2, 3, 4}
        //
        // ctors: everything: {}

        let mut sys = ConstraintSystem::<u32, ()>::new();
        sys.add_goal(Constraint(S(LV(1)), S(LV(2)))).unwrap();
        sys.add_goal(Constraint(S(LV(2)), S(LV(3)))).unwrap();
        sys.add_goal(Constraint(S(LV(3)), S(LV(4)))).unwrap();

        sys.solve().unwrap();

        let supersets_1 = mk_hash_set(vec![1, 2, 3, 4]);

        assert_eq!(&sys.compute_eqset(&1), &supersets_1);
        assert_eq!(&sys.compute_eqset(&2), &supersets_1);
        assert_eq!(&sys.compute_eqset(&3), &supersets_1);
        assert_eq!(&sys.compute_eqset(&4), &supersets_1);

        assert!(sys.ctors(&1).is_empty());
        assert!(sys.ctors(&2).is_empty());
        assert!(sys.ctors(&3).is_empty());
        assert!(sys.ctors(&4).is_empty());
    }

    #[test]
    fn solve_constructor() {
        use SimpleTerm::*;
        use Term::*;

        // Testing the following set of constraints:
        //
        // 1 = 2
        // c(1, 3) = 1
        // 2 = c(2, 4)
        //
        // The solution has the following sets:
        // {1, 2}
        // {3, 4}
        //
        // ctors:
        // {1, 2} -> {c(1, 3)}
        // {3, 4} -> {}

        let mut sys = ConstraintSystem::<u32, ()>::new();

        let goal_set = mk_hash_set(vec![
            Constraint(S(LV(1)), S(LV(2))),
            Constraint(
                C(Ctor::simple(Name::from("c"), vec![1, 3], vec![])),
                S(LV(1)),
            ),
            Constraint(
                S(LV(2)),
                C(Ctor::simple(Name::from("c"), vec![2, 4], vec![])),
            ),
        ]);

        for goal in goal_set {
            sys.add_goal(goal).unwrap();
        }

        sys.solve().unwrap();

        let ctor_set1 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![1, 3], vec![])]);
        let ctor_set2 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![2, 4], vec![])]);

        let supersets_1 = mk_hash_set(vec![1, 2]);
        let supersets_2 = mk_hash_set(vec![3, 4]);

        println!("The solved system is: {:#?}", sys);

        assert_eq!(&sys.compute_eqset(&1), &supersets_1);
        assert_eq!(&sys.compute_eqset(&2), &supersets_1);
        assert_eq!(&sys.compute_eqset(&3), &supersets_2);
        assert_eq!(&sys.compute_eqset(&4), &supersets_2);

        assert!((sys.ctors(&1) == ctor_set1) || (sys.ctors(&1) == ctor_set2));
        assert!((sys.ctors(&2) == ctor_set1) || (sys.ctors(&2) == ctor_set2));
        assert!(sys.ctors(&3).is_empty());
        assert!(sys.ctors(&4).is_empty());
    }

    #[test]
    fn solve_complex() {
        use SimpleTerm::*;
        use Term::*;

        // Testing the following set of constraints:
        //
        // 1 = 2
        // 1 = 3
        // 1 = c(1,5)
        // c(3,5) = 2
        // c(1,4) = 1
        //
        // The solution has the following sets:
        // {1, 2, 3} -> {c(1,4)}
        // {4, 5} -> {}

        let mut sys = ConstraintSystem::<u32, ()>::new();

        let goal_set = mk_hash_set(vec![
            Constraint(S(LV(1)), S(LV(2))),
            Constraint(S(LV(1)), S(LV(3))),
            Constraint(
                S(LV(1)),
                C(Ctor::simple(Name::from("c"), vec![1, 5], vec![])),
            ),
            Constraint(
                C(Ctor::simple(Name::from("c"), vec![3, 5], vec![])),
                S(LV(2)),
            ),
            Constraint(
                C(Ctor::simple(Name::from("c"), vec![1, 4], vec![])),
                S(LV(1)),
            ),
        ]);

        for goal in goal_set {
            sys.add_goal(goal).unwrap();
        }

        sys.solve().unwrap();
        println!("The solved system is: {:#?}", sys);

        let ctor_set1 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![1, 5], vec![])]);
        let ctor_set2 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![1, 4], vec![])]);

        let set_1 = mk_hash_set(vec![1, 2, 3]);
        let set_45 = mk_hash_set(vec![4, 5]);

        assert_eq!(&sys.compute_eqset(&1), &set_1);
        assert_eq!(&sys.compute_eqset(&2), &set_1);
        assert_eq!(&sys.compute_eqset(&3), &set_1);
        assert_eq!(&sys.compute_eqset(&4), &set_45);
        assert_eq!(&sys.compute_eqset(&5), &set_45);

        assert!((sys.ctors(&1) == ctor_set1) || (sys.ctors(&1) == ctor_set2));
        assert!((sys.ctors(&2) == ctor_set1) || (sys.ctors(&2) == ctor_set2));
        assert!((sys.ctors(&3) == ctor_set1) || (sys.ctors(&2) == ctor_set2));
        assert!(sys.ctors(&4).is_empty());
        assert!(sys.ctors(&5).is_empty());
    }

    #[test]
    fn solve_invariance() {
        use SimpleTerm::*;
        use Term::*;

        // Testing the following set of constraints (note that everything is on the contravariant side):
        //
        // 1 = 2
        // 1 = 3
        // 1 = c(;1,5)
        // c(;3,5) = 2
        // c(;1,4) = 1
        //
        // The solution has the following sets:
        // {1, 2, 3} -> {c(;1,4)}
        // {4, 5} -> {}

        let mut sys = ConstraintSystem::<u32, ()>::new();

        let goal_set = mk_hash_set(vec![
            Constraint(S(LV(1)), S(LV(2))),
            Constraint(S(LV(1)), S(LV(3))),
            Constraint(
                S(LV(1)),
                C(Ctor::simple(Name::from("c"), vec![], vec![1, 5])),
            ),
            Constraint(
                C(Ctor::simple(Name::from("c"), vec![], vec![3, 5])),
                S(LV(2)),
            ),
            Constraint(
                C(Ctor::simple(Name::from("c"), vec![], vec![1, 4])),
                S(LV(1)),
            ),
        ]);

        for goal in goal_set {
            sys.add_goal(goal).unwrap();
        }

        sys.solve().unwrap();
        println!("The solved system is: {:#?}", sys);

        let ctor_set1 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![], vec![1, 5])]);
        let ctor_set2 = mk_hash_set(vec![Ctor::simple(Name::from("c"), vec![], vec![1, 4])]);

        let set_1 = mk_hash_set(vec![1, 2, 3]);
        let set_45 = mk_hash_set(vec![4, 5]);

        assert_eq!(&sys.compute_eqset(&1), &set_1);
        assert_eq!(&sys.compute_eqset(&2), &set_1);
        assert_eq!(&sys.compute_eqset(&3), &set_1);
        assert_eq!(&sys.compute_eqset(&4), &set_45);
        assert_eq!(&sys.compute_eqset(&5), &set_45);

        assert!((sys.ctors(&1) == ctor_set1) || (sys.ctors(&1) == ctor_set2));
        assert!((sys.ctors(&2) == ctor_set1) || (sys.ctors(&2) == ctor_set2));
        assert!((sys.ctors(&3) == ctor_set1) || (sys.ctors(&2) == ctor_set2));
        assert!(sys.ctors(&4).is_empty());
        assert!(sys.ctors(&5).is_empty());
    }
}
