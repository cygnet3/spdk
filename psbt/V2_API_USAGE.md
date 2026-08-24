# PSBT v2 API Usage (Short Guide)

Use the role-based API (`Creator` -> `Constructor` -> `Updater` -> `Signer`) and avoid mutating raw fields directly.

## Recommended flow

1. Start with `Creator`, then choose constructor mode:
   - `constructor_modifiable()`
   - `constructor_inputs_only_modifiable()`
   - `constructor_outputs_only_modifiable()`
2. Add inputs/outputs only via `Constructor`.
3. Call `.psbt()` to materialize and validate locktime consistency.
4. Use `Updater` for metadata updates (sequence, scripts, key origins, UTXO info, etc.).
5. Combine partial PSBTs with `v2::combine(...)` when multiple parties contribute.
6. Sign/finalize/extract in later roles.

## Why constructor methods matter

When you add an output with `Constructor::output(...)`, the API updates both:

- `psbt.outputs.push(output)`
- `psbt.global.output_count += 1`

This keeps serialization/deserialization consistent.

## Minimal pattern

```rust
use psbt_v2::v2::{Constructor, Modifiable, Output};
use bitcoin::TxOut;

let out = TxOut { value, script_pubkey };

let psbt = Constructor::<Modifiable>::default()
    .input(input_a)
    .input(input_b)
    .output(Output::new(out))
    .psbt()?;
```

## Pitfalls to avoid

- Do not manually edit `psbt.outputs` or `psbt.global.output_count`.
- Do not assume `Updater` can add outputs (constructor phase does that).
- Ensure the PSBT is created with outputs modifiable if you need to append outputs.
- Current output decode logic treats `amount == 0` as missing; this can reject valid zero-sat outputs.
