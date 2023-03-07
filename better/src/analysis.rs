use crate::lazy_static::lazy_static;
/// Analysis utilities to carry results around
use core::any::Any;
use std::{collections::HashMap, sync::Mutex};

pub mod commons;
pub mod span;

/// Marker trait for analysis results for an analysis, allows RTTI
/// look-up
pub trait AnalysisResult: Any + Send + Eq {
    /// Name of this analysis result, it can only be called on
    /// concrete analysis result types.
    fn name() -> String
    where
        Self: Sized;
}

lazy_static! {
    static ref ANALYSIS_RESULTS: Mutex<HashMap<String, Box<dyn Any + Send + 'static>>> =
        Mutex::new(HashMap::default());
}

/// Whether we should save intermediary results for analysis change
/// debugging
pub static DEBUG_ANALYSIS_CHANGES: bool = true;

/// Invalidates the given analysis result
pub fn invalidate<T: AnalysisResult>() -> Option<Box<T>> {
    let old_result = ANALYSIS_RESULTS.lock().unwrap().remove(&T::name());
    old_result.map(|r| r.downcast::<T>().unwrap())
}

/// Replaces the given analysis result
pub fn replace<T: AnalysisResult>(new_result: Box<T>) {
    let mut analysis_results = ANALYSIS_RESULTS.lock().unwrap();

    if DEBUG_ANALYSIS_CHANGES {
        let old_result = analysis_results
            .get(&T::name())
            .map(|r| (*r).downcast_ref::<T>().unwrap());
        if old_result.is_some() && *old_result.unwrap() == *new_result {
            log::info!("Computed the same analysis result for {}", T::name());
        } else {
            log::info!("Computed new analysis result for {}", T::name());
        }
    }

    analysis_results.insert(T::name(), new_result);
}

/// Copies the given analysis result
pub fn result<T: AnalysisResult + Clone>() -> Option<T> {
    ANALYSIS_RESULTS
        .lock()
        .unwrap()
        .get(&T::name())
        .map(|r| (*r).downcast_ref::<T>().unwrap().clone())
}
