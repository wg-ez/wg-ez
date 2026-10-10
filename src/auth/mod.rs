#![forbid(unsafe_code)]

//! Auth sub-modules: Argon2id passwords, TOTP, sessions + pending logins.

pub mod password;
pub mod session;
pub mod totp;
