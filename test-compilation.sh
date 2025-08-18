#!/bin/bash

set -e  # Exit on any error

echo "🧪 Testing All Compilation Scenarios"
echo "===================================="

echo ""
echo "✅ 1. Testing workspace with all features..."
cargo check --workspace --all-features

echo ""
echo "✅ 2. Testing workspace with no features..."
cargo check --workspace --no-default-features

echo ""
echo "✅ 3. Testing core client only (default)..."
cargo check -p sp-client

echo ""
echo "✅ 4. Testing core client with parallel feature..."
cargo check -p sp-client --features parallel

echo ""
echo "✅ 5. Testing core client without features..."
cargo check -p sp-client --no-default-features

echo ""
echo "✅ 6. Testing backend only..."
cargo check -p backend-blindbit-native

echo ""
echo "✅ 7. Testing core client for WASM..."
cargo check -p sp-client --target wasm32-unknown-unknown

echo ""
echo "✅ 8. Testing core client for WASM (with no features)..."
cargo check -p sp-client --target wasm32-unknown-unknown --no-default-features

echo ""
echo "❌ 9. Testing that backend FAILS for WASM (expected to fail)..."
if cargo check -p backend-blindbit-native --target wasm32-unknown-unknown 2>/dev/null; then
    echo "ERROR: Backend should NOT compile for WASM!"
    exit 1
else
    echo "✅ Good! Backend correctly fails to compile for WASM"
fi

echo ""
echo "✅ 10. Testing build (not just check)..."
cargo build --workspace --all-features

echo ""
echo "🎉 All compilation tests passed!"
echo ""
echo "Summary:"
echo "--------"
echo "✅ Core client compiles for native and WASM"
echo "✅ Core client works with and without features"
echo "✅ Backend compiles for native only"
echo "❌ Backend correctly fails for WASM"
echo "✅ Workspace supports all feature combinations"
