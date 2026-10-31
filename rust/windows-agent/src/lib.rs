pub mod compatibility;
pub mod config;
pub mod enrollment;
mod enrollment_credential;
pub mod enrollment_wire;
pub mod health;
// Inert inventory port: no production path exists until a fresh authenticated
// inventory profile and explicit local scope admission are implemented.
#[cfg(test)]
mod inventory_services;
#[cfg(windows)]
pub mod native;
pub mod protocol;
pub mod runtime;
pub mod sender;
#[cfg(windows)]
pub mod service;
pub mod state;
