#![allow(dead_code)]

use pingsix_macros::EncryptFields;

#[derive(EncryptFields)]
struct Config {
    #[encrypt(bogus)]
    password: String,
}

fn main() {}
