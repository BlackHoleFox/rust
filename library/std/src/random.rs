//! Access to the secure random number generator of the OS.
//!
//! This module exposes functions to read random bytes from the OS.
//!
//! The functions in this module are suitable for cryptographic applications, like generating keys or
//! seeds for a different RNG construct.
//!
//! If you want to generate large amounts of random data in your application, you should
//! consider using this module to seed a different, userspace, psuedorandom number generator instead.
//!
//! # Platform-specific behavior
//!
//! Some platforms and environments may have other requirements for secure random number generation
//! that are outside of the standard library's control. Examples include espidf and the very early Linux
//! process on older kernels.
//!
//! Care should be taken to either seed a another RNG (if possible) as mentioned above, or ensuring the platform
//! is correctly configured.

use crate::fmt;

/// An error indicating that the random number generator is unavailable.
///
/// UNIX sandboxing and WASM are notable for potentially causing this.
#[unstable(feature = "stdrandom", issue = "none")]
#[derive(Clone, PartialEq, Eq)]
pub struct UnavailableError(());

#[unstable(feature = "stdrandom", issue = "none")]
impl fmt::Debug for UnavailableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnavailableError").finish()
    }
}

#[unstable(feature = "stdrandom", issue = "none")]
impl fmt::Display for UnavailableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system RNG is unavailable")
    }
}

/// Fills `buffer` with random bytes from the OS's random number generator.
///
/// If the function returns `Ok(())`, it is guaranteed that the whole buffer has been
/// filled with random data. Additionally, the data returend is suitable for cryptographic use.
///
/// # Panics
///
/// This function will panic if either the RNG was unavailble, or reading from the RNG fails.
///
/// To handle the possibility of the RNG being inaccessible, use [try_fill_bytes] instead.
#[unstable(feature = "stdrandom", issue = "none")]
#[doc(alias = "getrandom")]
pub fn fill_bytes(buffer: &mut [u8]) {
    try_fill_bytes(buffer).expect("failed to access RNG")
}

/// Fills `buffer` with random bytes from the OS's random number generator.
///
/// If the function returns `Ok(())`, it is guaranteed that the whole buffer has been
/// filled with random data. Additionally, the data returend is suitable for cryptographic use.
///
/// # Errors
///
/// This function returns an error if the RNG is not currently accessible.
///
/// # Panics
///
/// This function will panic if reading from the RNG fails.
#[unstable(feature = "stdrandom", issue = "none")]
pub fn try_fill_bytes(buffer: &mut [u8]) -> Result<(), UnavailableError> {
    crate::sys::rand::random_bytes(buffer, true).map_err(|_| UnavailableError(()))
}
