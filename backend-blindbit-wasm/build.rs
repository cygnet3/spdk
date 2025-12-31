fn main() {
    let target = std::env::var("TARGET").expect("TARGET environment variable not set");

    if !target.contains("wasm32") {
        panic!(
            "\n\n\
            ============================================================\n\
            ERROR: backend-blindbit-wasm can only be built for WASM targets\n\
            ============================================================\n\
            \n\
            Current target: {}\n\
            Required target: wasm32-unknown-unknown\n\
            \n\
            Please build with: cargo build --target wasm32-unknown-unknown\n\
            ============================================================\n\n",
            target
        );
    }
}
