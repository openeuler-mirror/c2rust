/// Utility functions
use crate::lazy_static::lazy_static;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[cfg(feature = "std_hash")]
pub type HashMap<K, V> = std::collections::HashMap<K, V>;
#[cfg(feature = "std_hash")]
pub type HashSet<Elem> = std::collections::HashSet<Elem>;

#[cfg(not(feature = "std_hash"))]
pub type HashMap<K, V> = std::collections::HashMap<K, V, ahash::RandomState>;
#[cfg(not(feature = "std_hash"))]
pub type HashSet<Elem> = std::collections::HashSet<Elem, ahash::RandomState>;

lazy_static! {
    static ref PROFILING_RESULTS: Mutex<HashMap<String, Duration>> = Mutex::new(HashMap::default());
}

#[inline]
pub fn profile<T, F: FnOnce() -> T>(key: &str, closure: F) -> T {
    if cfg!(feature = "profiling") {
        let before = Instant::now();
        let result = closure();
        let elapsed = before.elapsed();

        let mut map = PROFILING_RESULTS.lock().unwrap();
        let last_duration = map.entry(key.to_owned()).or_insert(Duration::new(0, 0));

        *last_duration += elapsed;

        result
    } else {
        closure()
    }
}

pub fn report_profiling_results() {
    if cfg!(feature = "profiling") {
        println!("PROFILING RESULTS");
        for (key, duration) in PROFILING_RESULTS.lock().unwrap().iter() {
            println!("{}: {} ms", key, duration.as_millis());
        }
    }
}

/// A struct to compute the powerset of arrays
pub struct Powerset<T: Clone> {
    /// The set containing all elements
    set: Vec<T>,
    /// Bitvector encoding the next set to generate
    next_item: usize,
}

impl<T: Clone> Powerset<T> {
    fn post_last_item(&self) -> usize {
        1 << self.set.len()
    }
}

impl<T: Clone> Iterator for Powerset<T> {
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        assert!(self.next_item <= self.post_last_item());
        if self.next_item == self.post_last_item() {
            return None;
        }

        let mut result = Vec::new();
        for (i, elem) in self.set.iter().enumerate() {
            if self.next_item & (1 << i) != 0 {
                result.push(elem.clone());
            }
        }
        self.next_item += 1;
        Some(result)
    }
}

pub fn powerset<T>(s: &[T]) -> Powerset<T>
where
    T: Clone,
{
    assert!(
        s.len() < 32,
        "Can compute powerset of slices with < 32 elements. Given slice has {} elements",
        s.len()
    );

    Powerset {
        set: s.iter().map(|x| x.clone()).collect(),
        next_item: 0,
    }
}
