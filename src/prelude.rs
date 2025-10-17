pub use core::fmt;
pub use core::result::Result;


#[cfg(all(not(feature = "std"), feature = "zkvm"))]
pub use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
    collections::{BTreeMap, BTreeSet},
    boxed::Box,
};

#[cfg(any(feature = "std", not(feature = "zkvm")))]
pub use std::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::OnceLock,
};