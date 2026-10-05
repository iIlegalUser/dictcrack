// dictcrack-core: native archive password-cracking engine.
// Rust rewrite of the C# core (src/*.cs). See docs/superpowers/specs.

pub mod archive;
pub mod attacks;
pub mod crypto;
pub mod encoding;
pub mod engine;
pub mod result;
pub mod session;
pub mod tool;
pub mod verifier;
