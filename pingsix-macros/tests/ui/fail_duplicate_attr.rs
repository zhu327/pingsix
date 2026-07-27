#![allow(dead_code)]

use pingsix_macros::EncryptFields;

#[derive(EncryptFields)]
struct Config {
    #[encrypt]
    #[encrypt]
    password: String,
}

fn main() {}
