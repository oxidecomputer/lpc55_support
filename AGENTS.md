# AGENTS Guide

## Overview
- Workspace of Rust crates for interacting with NXP LPC55 microcontrollers beyond raw registers.
- Provides:
  - `lpc55_areas`: typed representations of CMPA/CFPA regions and related helpers.
  - `lpc55_sign`: library code for stamping, signing, and validating LPC55 images.
  - `lpc55_sign_bin`: CLI front-end for `lpc55_sign` (generates CMPA/CFPA images, signed binaries, debug credentials).
  - `lpc55_isp`: ISP-mode transport and command helpers, plus CLIs (`lpc55_flash`, `cfpa-update`).
  - `measurement_token`: `#![no_std]` constants shared by firmware components.
- All source files are MPL-2.0 licensed (see headers); respect license during modifications.

## Toolchain & Environment
- `rust-toolchain.toml` pins the workspace to Rust **1.89.0** (stable).
- `Cargo.lock` uses lockfile format v4 and depends on crates that require recent compilers (`base64ct` ≥1.8, `colored` 3.0, etc.).
  - Using system `cargo` 1.75 (or any cargo <1.88) fails with `lock file version 4 requires -Znext-lockfile-bump` and Rust version gate errors.
  - Always invoke commands through rustup with at least the pinned toolchain: `rustup run 1.89.0 cargo <cmd>` or set `rustup override set 1.89.0` in the repo.
  - If you must use an older cargo, append `-Znext-lockfile-bump`, but expect compilation to fail until toolchain ≥1.89.0 is active.
- Install required components: `rustup component add rustfmt --toolchain 1.89.0` (and optionally `clippy`).
- Network access is needed on first build to fetch dependencies, including the git-based `serialport` fork (`https://github.com/jgallagher/serialport-rs` on branch `illumos-support`).

## Build & Test Commands
- Build everything (matched to CI):
  - `rustup run 1.89.0 cargo build` (workspace default target).
- Run tests:
  - `rustup run 1.89.0 cargo test --workspace` (limited unit coverage; mainly `lpc55_sign` tests).
- Run specific binaries:
  - `rustup run 1.89.0 cargo run --bin lpc55_sign -- <args>`
  - `rustup run 1.89.0 cargo run --bin lpc55_flash -- <args>`
  - `rustup run 1.89.0 cargo run --bin cfpa-update -- <args>`
- CI mirrors these: `.github/workflows/build.yml` runs `cargo build` on Ubuntu & Windows with the stable toolchain, while `.github/workflows/formatting.yml` runs `cargo fmt --all -- --check` using nightly rustfmt.

## Formatting & Linting
- Formatting: `rustup run nightly cargo fmt --all` matches the CI configuration (nightly rustfmt component). Running `cargo fmt --all` with toolchain 1.89.0 + rustfmt also works, but verify with nightly if CI will check your change.
- No automated clippy in CI; run `rustup run 1.89.0 cargo clippy --workspace --all-targets` if you need lint coverage.

## Repository Layout & Key Modules
- `lpc55_areas/src/lib.rs`: packed_struct declarations for CMPA/CFPA, enums for boot/debug configuration, helper methods for building configuration words, and clap/serde-friendly `DebugSettings`.
  - Patterns: heavy use of `#[derive(PrimitiveEnum, PackedStruct, clap::ValueEnum, serde::Serialize/Deserialize)]` with `#[serde(rename_all = "kebab-case", deny_unknown_fields)]`. Maintain exact casing when adding fields.
  - Bitfield helpers built with `bitfield::bitfield!`; follow existing naming conventions (`set_*`, `invert_field`).
- `lpc55_sign/src`: signing pipeline.
  - `lib.rs` exposes `Error` enum (`thiserror::Error`) covering all failure modes; extend carefully to keep exact error messages.
  - `signed_image.rs` handles stamping signed images (`pad_roots`, `root_key_hash`, `generate_cmpa`, `generate_cfpa`). Respect invariants: `image_key_revoke` must remain unary; `DiceArgs` toggles require secure boot.
  - `cert.rs`, `debug_auth.rs`, `verify.rs` manage certificate parsing and debug credential flows; rely on DER encoding from `x509-cert`, `pem-rfc7468`, and RSA primitives.
- `lpc55_sign_bin/src/main.rs`: Clap-based CLI orchestrating operations. Notable behaviors:
  - Uses `#[derive(Parser)]` with nested `#[clap(flatten)]` structures for TOML configs.
  - `cmpa` command prompts for confirmation when `--lock` is set; `--yes` bypasses the prompt (important for non-interactive runs/tests).
  - TOML helpers rely on `from_toml_file` with strong error contexts via `anyhow::Context`.
- `lpc55_isp/src`: ISP transport layer and command wrappers, using serial I/O.
  - `cmd.rs` orchestrates multi-phase ISP commands (`DataPhase` enum) and enforces ack reading; use existing helper functions when adding commands.
  - `isp.rs` defines packet formats using `packed_struct` and manual CRC calculations; maintain framing/CRC logic when modifying protocols.
- `measurement_token/src/lib.rs`: `#![no_std]` constants for shared measurement token addresses/values. Avoid introducing `std` dependencies here.

## Tests & Validation Strategy
- Current automated tests are minimal (`lpc55_sign::tests::test_is_unary`). Most validation occurs through integration with hardware and CLI workflows.
- When altering core logic (e.g., `generate_cmpa`, `generate_cfpa`, ISP commands), add targeted unit or integration tests if feasible.
- For CLI changes, consider snapshotting help output (`Command::command().render_help()`) or verifying generated structures programmatically.

## Usage & Domain Context
- README.md documents typical workflows: using `lpc55_flash` to erase/write memory, `cfpa_update` to manage CFPA revisions, and `lpc55_sign` to produce CRC or signed images. Reference it before changing CLI interfaces to keep docs in sync.
- The tooling expects binary inputs/outputs and certificate chains (DER). Handling of root key hashes and debug credential flows is sensitive; changes should preserve compatibility with NXP ROM requirements (see comments referencing UM 11126 and MPC docs).

## Common Gotchas
- Toolchain drift is the primary failure mode: ensure you are using Rust ≥1.89.0 or you will hit lockfile and minimum rustc errors.
- Many structs enforce `deny_unknown_fields`; adding new configuration fields requires simultaneous updates to both clap definitions and serde defaults.
- `packed_struct` macros require matching size/bit metadata. Changing field order or size can silently corrupt binary layouts—double-check offsets against NXP documentation.
- `serialport` dependency pulls from a git repo; offline builds require a cached copy. Any change touching `serialport` features should confirm compatibility with that fork.
- Interactive prompts (`cmpa --lock`) can block automation; pass `--yes` or refactor with care.
- `measurement_token` is `no_std`; adding standard library calls will break downstream consumers.

## CI Expectations
- Pull requests must pass `cargo build` on Linux and Windows (stable 1.89 toolchain) and `cargo fmt --all -- --check` under nightly. Mirror these locally before pushing.
- CI also includes a post-build `git diff --exit-code` step; running formatters/build commands should not leave uncommitted changes.

## When Making Changes
- Follow existing module organization: shared data structures belong in `lpc55_areas`, cryptographic and signing logic lives in `lpc55_sign`, CLI UX in `lpc55_sign_bin`, and ISP communication in `lpc55_isp`.
- Extend the `Error` enum in `lpc55_sign::lib.rs` for new error types, keeping human-readable messages.
- Use `anyhow::Context` in CLI error paths for actionable diagnostics, matching existing patterns.
- Maintain `serde` + `clap` symmetry: new config fields need defaults (`#[serde(default = ...)]`) and matching CLI flags.
- After modifications: format, run `cargo build`, then `cargo test --workspace` with the pinned toolchain.
