//! Structure of the formats we can read without their body.

pub mod pe;

pub use pe::{PeImage, PeSection};
