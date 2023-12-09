mod fuzzer;

#[no_mangle]
pub extern "C" fn lib() {
    fuzzer::main();
}