//! End-to-end tests of the `pwk` binary against a fake, stateful Passwork 7 server.
//!
//! Written from docs/design.md and docs/protocol.md. The server (`server.rs`) holds an
//! encrypted world built with `pwk_crypto`; the tests run the real binary with HOME,
//! config and state in a temporary directory and decrypt what it sends.

mod harness;
mod http;
mod server;

mod objects;
mod secrets;
mod session;
