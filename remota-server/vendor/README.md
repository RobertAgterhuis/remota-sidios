# Vendored crates

Unmodified IronRDP 0.10.0 crates (MIT OR Apache-2.0, see each crate's LICENSE files) except:

- `Cargo.toml`: `ironrdp-connector` depends on `sspi` 0.23 and `picky` 7.0.0-rc.26 instead of 0.21
  and rc.25, so they can share `ecdsa` 0.17 with `russh`.
- `src/credssp.rs` in both crates: `TsRequest::buffer_len()` returns a `Result` in `sspi` 0.23, so
  its error is mapped with `custom_err!`.

Remove both and the `[patch.crates-io]` section once an IronRDP release depends on `sspi` 0.22 or
later.
- `src/lib.rs` in `ironrdp-connector`: allows `unfulfilled_lint_expectations` (one `#[expect]` no longer
  fires with the toolchain used here).
