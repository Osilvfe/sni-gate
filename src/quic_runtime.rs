//! Process-wide QUIC / terminating-HTTP/3 runtime limits.
//!
//! These are resource-policy knobs, not route semantics. Keeping them outside
//! the hierarchical `[http3]` companion switch prevents a per-route setting from
//! accidentally changing process-wide admission or pooling behavior. Values are
//! parsed once at startup from `SNI_GATE_QUIC_*`; the data path then reads one
//! immutable policy object.

use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 256;
pub const DEFAULT_MAX_H3_CONNECTIONS: usize = 1024;
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: usize = 256;
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;
pub const DEFAULT_MAX_UPSTREAM_POOL_ENTRIES: usize = 256;
pub const DEFAULT_UPSTREAM_POOL_IDLE: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_PENDING_UPSTREAM_CONNECTS: usize = 64;

const ENV_MAX_PENDING_HANDSHAKES: &str = "SNI_GATE_QUIC_MAX_PENDING_HANDSHAKES";
const ENV_MAX_H3_CONNECTIONS: &str = "SNI_GATE_QUIC_MAX_H3_CONNECTIONS";
const ENV_MAX_REQUESTS_PER_CONNECTION: &str = "SNI_GATE_QUIC_MAX_REQUESTS_PER_CONNECTION";
const ENV_MAX_FIELD_SECTION_SIZE: &str = "SNI_GATE_QUIC_MAX_FIELD_SECTION_SIZE";
const ENV_MAX_UPSTREAM_POOL_ENTRIES: &str = "SNI_GATE_QUIC_MAX_UPSTREAM_POOL_ENTRIES";
const ENV_UPSTREAM_POOL_IDLE_SECS: &str = "SNI_GATE_QUIC_UPSTREAM_POOL_IDLE_SECS";
const ENV_MAX_PENDING_UPSTREAM_CONNECTS: &str = "SNI_GATE_QUIC_MAX_PENDING_UPSTREAM_CONNECTS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicRuntimeLimits {
    pub max_pending_handshakes: usize,
    pub max_h3_connections: usize,
    pub max_requests_per_connection: usize,
    pub max_field_section_size: u64,
    pub max_upstream_pool_entries: usize,
    pub upstream_pool_idle: Duration,
    pub max_pending_upstream_connects: usize,
}

impl Default for QuicRuntimeLimits {
    fn default() -> Self {
        Self {
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            max_h3_connections: DEFAULT_MAX_H3_CONNECTIONS,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
            max_upstream_pool_entries: DEFAULT_MAX_UPSTREAM_POOL_ENTRIES,
            upstream_pool_idle: DEFAULT_UPSTREAM_POOL_IDLE,
            max_pending_upstream_connects: DEFAULT_MAX_PENDING_UPSTREAM_CONNECTS,
        }
    }
}

static LIMITS: OnceLock<QuicRuntimeLimits> = OnceLock::new();

/// Parse and install the process-wide limits. Calling this more than once is a
/// programming error because semaphores and pools are sized from these values
/// and cannot be resized safely while traffic is live.
pub fn init_from_env() -> Result<&'static QuicRuntimeLimits> {
    if LIMITS.get().is_some() {
        return Err(anyhow!("QUIC runtime limits were initialized more than once"));
    }
    let limits = QuicRuntimeLimits::from_env()?;
    LIMITS
        .set(limits)
        .map_err(|_| anyhow!("QUIC runtime limits were initialized concurrently"))?;
    Ok(LIMITS.get().expect("QUIC runtime limits just initialized"))
}

/// Data-path accessor. Tests and binaries that do not call `init_from_env`
/// explicitly retain the exact production defaults rather than panicking.
pub fn limits() -> &'static QuicRuntimeLimits {
    LIMITS.get_or_init(QuicRuntimeLimits::default)
}

impl QuicRuntimeLimits {
    fn from_env() -> Result<Self> {
        let defaults = Self::default();
        Ok(Self {
            max_pending_handshakes: parse_positive_usize(
                ENV_MAX_PENDING_HANDSHAKES,
                defaults.max_pending_handshakes,
            )?,
            max_h3_connections: parse_positive_usize(
                ENV_MAX_H3_CONNECTIONS,
                defaults.max_h3_connections,
            )?,
            max_requests_per_connection: parse_positive_usize(
                ENV_MAX_REQUESTS_PER_CONNECTION,
                defaults.max_requests_per_connection,
            )?,
            max_field_section_size: parse_positive_u64(
                ENV_MAX_FIELD_SECTION_SIZE,
                defaults.max_field_section_size,
            )?,
            max_upstream_pool_entries: parse_positive_usize(
                ENV_MAX_UPSTREAM_POOL_ENTRIES,
                defaults.max_upstream_pool_entries,
            )?,
            upstream_pool_idle: Duration::from_secs(parse_positive_u64(
                ENV_UPSTREAM_POOL_IDLE_SECS,
                defaults.upstream_pool_idle.as_secs(),
            )?),
            max_pending_upstream_connects: parse_positive_usize(
                ENV_MAX_PENDING_UPSTREAM_CONNECTS,
                defaults.max_pending_upstream_connects,
            )?,
        })
    }
}

fn env_value(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {name}")),
    }
}

fn parse_positive_usize(name: &str, default: usize) -> Result<usize> {
    let Some(raw) = env_value(name)? else {
        return Ok(default);
    };
    let value = raw
        .trim()
        .parse::<usize>()
        .with_context(|| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(value)
}

fn parse_positive_u64(name: &str, default: u64) -> Result<u64> {
    let Some(raw) = env_value(name)? else {
        return Ok(default);
    };
    let value = raw
        .trim()
        .parse::<u64>()
        .with_context(|| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(anyhow!("{name} must be greater than zero"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_production_hardening_values() {
        let limits = QuicRuntimeLimits::default();
        assert_eq!(limits.max_pending_handshakes, 256);
        assert_eq!(limits.max_h3_connections, 1024);
        assert_eq!(limits.max_requests_per_connection, 256);
        assert_eq!(limits.max_field_section_size, 64 * 1024);
        assert_eq!(limits.max_upstream_pool_entries, 256);
        assert_eq!(limits.upstream_pool_idle, Duration::from_secs(60));
        assert_eq!(limits.max_pending_upstream_connects, 64);
    }
}
