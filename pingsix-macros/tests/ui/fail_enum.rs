use pingsix_macros::EncryptFields;

#[derive(EncryptFields)]
enum NotAStruct {
    A,
}

fn main() {}
