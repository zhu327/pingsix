#![allow(dead_code)]

use pingsix_macros::EncryptFields;

#[derive(EncryptFields)]
#[encrypt_fields(bogus)]
struct Config {
    #[encrypt]
    password: String,
}

fn main() {}
