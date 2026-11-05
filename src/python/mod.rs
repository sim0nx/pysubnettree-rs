//! Python bindings.
//!
//! - [`builder::SubnetTreeBuilder`]: modifiable, guarded by a lock.
//! - [`frozen::SubnetTreeRS`]: immutable and lock-free, built from a builder or loaded from disk.
//!
//! Both own a [`data::Data`] exclusively: `build()` and `to_builder()` copy it.

mod builder;
mod data;
mod frozen;
mod keys;
mod values;

use pyo3::prelude::*;

use crate::format;

/// Fast, memory-efficient longest-prefix-match lookups of IPv4/IPv6 subnets.
#[pymodule]
#[pyo3(name = "_pysubnettree_rs")]
fn pysubnettree_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<builder::SubnetTreeBuilder>()?;
    m.add_class::<frozen::SubnetTreeRS>()?;
    m.add("FORMAT_VERSION", format::VERSION)?;
    // lets benchmarks refuse unoptimized builds
    m.add("_DEBUG_BUILD", cfg!(debug_assertions))?;
    Ok(())
}
