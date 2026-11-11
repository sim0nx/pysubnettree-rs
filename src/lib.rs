//! Fast, memory-efficient longest-prefix-match lookups of IPv4/IPv6 subnets.
//!
//! The pure Rust core ([`tree::Tree`]) is usable without Python; the `python` feature (enabled by
//! default) adds the `pysubnettree_rs` extension module.
#![forbid(unsafe_code)]

pub mod format;
pub mod strings;
pub mod table;
pub mod tree;
pub mod value;

#[cfg(feature = "python")]
mod python;
