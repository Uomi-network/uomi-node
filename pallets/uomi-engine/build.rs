fn main() {
    // Rebuild if the WAT source changes
    println!("cargo:rerun-if-changed=src/test_agents/agent_http.wat");

    // Compile WAT to WASM and write alongside the source for easy inclusion in tests
    let wat_path = "src/test_agents/agent_http.wat";
    let wasm_path = "src/test_agents/agent_http.wasm";

    let wat_src = std::fs::read_to_string(wat_path)
        .expect("failed to read agent_http.wat");
    let wasm = wat::parse_str(&wat_src)
        .expect("failed to compile agent_http.wat to wasm");

    // Only write if missing or content differs
    let need_write = match std::fs::read(wasm_path) {
        Ok(existing) => existing != wasm,
        Err(_) => true,
    };
    if need_write {
        std::fs::write(wasm_path, &wasm).expect("failed to write agent_http.wasm");
    }
}
