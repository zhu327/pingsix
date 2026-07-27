#[test]
fn encrypt_fields_compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fail_*.rs");
}
