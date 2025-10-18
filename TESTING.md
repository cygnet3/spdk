# Compilation Testing Guide

This workspace is designed to support multiple architectures with clean separation. Here's how to test all compilation scenarios:

## Quick Test All Scenarios

```bash
./test-compilation.sh
```

## Manual Testing Commands

### Core Client Tests
```bash
# Default compilation (native)
cargo check -p sp-client

# With parallel processing feature
cargo check -p sp-client --features parallel

# No features
cargo check -p sp-client --no-default-features

# WASM compilation (should work)
cargo check -p sp-client --target wasm32-unknown-unknown
```

### Backend Tests
```bash
# Native compilation (should work)
cargo check -p backend-blindbit-native

# WASM compilation (should FAIL)
cargo check -p backend-blindbit-native --target wasm32-unknown-unknown
```

### Workspace Tests
```bash
# All features
cargo check --workspace --all-features

# No features
cargo check --workspace --no-default-features

# Default
cargo check --workspace
```

## Expected Results

| Command | Target | Result |
|---------|--------|--------|
| `sp-client` | native | ✅ Pass |
| `sp-client` | wasm32 | ✅ Pass |
| `backend-blindbit-native` | native | ✅ Pass |
| `backend-blindbit-native` | wasm32 | ❌ Fail (expected) |
| `workspace` | native | ✅ Pass |

## Architecture Goals

- **Core client (`sp-client`)**: Architecture-agnostic, minimal dependencies
- **Native backend (`backend-blindbit-native`)**: Native-only, full functionality
- **Future WASM backend (`backend-blindbit-wasm`)**: WASM-specific implementation
- **Future backends**: `backend-electrum-native`, `backend-esplora-native`, etc.

## Feature Flags

- `parallel`: Enable parallel processing in core client (native performance optimization)
- No backend-specific feature flags needed - use separate crates instead

## CI/CD Integration

Add these commands to your CI pipeline:

```yaml
# Test all compilation scenarios
- name: Test compilation scenarios
  run: ./test-compilation.sh

# Test specific targets
- name: Test WASM
  run: cargo check -p sp-client --target wasm32-unknown-unknown

- name: Test native backend fails on WASM
  run: |
    if cargo check -p backend-blindbit-native --target wasm32-unknown-unknown; then
      echo "ERROR: Backend should not compile for WASM"
      exit 1
    fi
```
