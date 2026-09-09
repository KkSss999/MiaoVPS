# Contributing to MiaoVPS

Thank you for contributing.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

Keep changes focused, add tests for behavior changes, and update the relevant
documentation. Do not commit generated build output, local MiaoVPS state,
credentials, private keys, exported WireGuard configuration, or real
infrastructure details.

## Pull requests

Describe the problem, the chosen approach, user-visible behavior, and the
validation performed. Networking and routing changes should include platform,
operating-system version, failure behavior, and rollback evidence.

By submitting a contribution, you agree that it may be distributed under the
project's MIT License.
