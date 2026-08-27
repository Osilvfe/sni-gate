//! Process-wide QUIC / terminating-HTTP/3 runtime limits.
//!
//! These are resource-policy knobs, not route semantics. Keeping them outside
//! the hierarchical `[http3]` companion switch prevents a per-route setting from
//! accidentally changing process-wide admission or pooling behavior. Values are
//! parsed once at startup from `SNI_GATE_QUIC_*`; the data path then reads one
//! immutable policy object.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 256;
pub const DEFAULT_MAX_H3_CONNECTIONS: usize = 1024;
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: usize = 256;
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;
pub const DEFAULT_MAX_UPSTREAM_POOL_ENTRIES: usize = 256;
pub const DEFAULT_UPSTREAM_POOL_IDLE: Duration = Duration::from_secs(60);
pub const DEFAULT_MAX_PENDING_UPSTREAM_CONNECTS: usize = 64;
pub const DEFAULT_MAX_H3_INGRESS_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_RAW_FORWARDING_BYTES: usize = 64 * 1024 * 1024;

const ENV_MAX_PENDING_HANDSHAKES: &str = "SNI_GATE_QUIC_MAX_PENDING_HANDSHAKES";
const ENV_MAX_H3_CONNECTIONS: &str = "SNI_GATE_QUIC_MAX_H3_CONNECTIONS";
const ENV_MAX_REQUESTS_PER_CONNECTION: &str = "SNI_GATE_QUIC_MAX_REQUESTS_PER_CONNECTION";
const ENV_MAX_FIELD_SECTION_SIZE: &str = "SNI_GATE_QUIC_MAX_FIELD_SECTION_SIZE";
const ENV_MAX_UPSTREAM_POOL_ENTRIES: &str = "SNI_GATE_QUIC_MAX_UPSTREAM_POOL_ENTRIES";
const ENV_UPSTREAM_POOL_IDLE_SECS: &str = "SNI_GATE_QUIC_UPSTREAM_POOL_IDLE_SECS";
const ENV_MAX_PENDING_UPSTREAM_CONNECTS: &str = "SNI_GATE_QUIC_MAX_PENDING_UPSTREAM_CONNECTS";
const ENV_MAX_H3_INGRESS_BYTES: &str = "SNI_GATE_QUIC_MAX_H3_INGRESS_BYTES";
const ENV_MAX_RAW_FORWARDING_BYTES: &str = "SNI_GATE_QUIC_MAX_RAW_FORWARDING_BYTES";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicRuntimeLimits {
    pub max_pending_handshakes: usize,
    pub max_h3_connections: usize,
    pub max_requests_per_connection: usize,
    pub max_field_section_size: u64,
    pub max_upstream_pool_entries: usize,
    pub upstream_pool_idle: Duration,
    pub max_pending_upstream_connects: usize,
    pub max_h3_ingress_bytes: usize,
    pub max_raw_forwarding_bytes: usize,
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
            max_h3_ingress_bytes: DEFAULT_MAX_H3_INGRESS_BYTES,
            max_raw_forwarding_bytes: DEFAULT_MAX_RAW_FORWARDING_BYTES,
        }
    }
}

static LIMITS: OnceLock<QuicRuntimeLimits> = OnceLock::new();
static INBOUND_HANDSHAKE_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
static H3_INGRESS_BYTE_BUDGET: OnceLock<Arc<ByteBudget>> = OnceLock::new();
static RAW_FORWARDING_BYTE_BUDGET: OnceLock<Arc<ByteBudget>> = OnceLock::new();

/// A non-blocking, process-wide byte budget. The owned permit is stored beside
/// the queued allocation, so every consume, drop, and channel-close path
/// returns capacity automatically.
#[derive(Debug)]
pub struct ByteBudget {
    capacity: usize,
    permits: Arc<Semaphore>,
}

impl ByteBudget {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity <= Semaphore::MAX_PERMITS);
        Self {
            capacity,
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(test)]
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    pub fn try_acquire(&self, bytes: usize) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        let permits = u32::try_from(bytes).map_err(|_| TryAcquireError::NoPermits)?;
        self.permits.clone().try_acquire_many_owned(permits)
    }
}

/// Parse and install the process-wide limits on the first QUIC listener. Later
/// listeners share exactly the same immutable object. If two listeners start at
/// the same time, either parsed value is equivalent because they read the same
/// process environment before traffic begins.
pub fn init_from_env() -> Result<&'static QuicRuntimeLimits> {
    if let Some(limits) = LIMITS.get() {
        return Ok(limits);
    }
    let parsed = QuicRuntimeLimits::from_env()?;
    let _ = LIMITS.set(parsed);
    Ok(LIMITS
        .get()
        .expect("QUIC runtime limits initialized by this or a concurrent listener"))
}

/// Data-path accessor. Tests that exercise H3 helpers without starting a full
/// listener retain the exact production defaults rather than depending on the
/// process environment.
pub fn limits() -> &'static QuicRuntimeLimits {
    LIMITS.get_or_init(QuicRuntimeLimits::default)
}

pub fn inbound_handshake_limit() -> Arc<Semaphore> {
    INBOUND_HANDSHAKE_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(limits().max_pending_handshakes)))
        .clone()
}

pub fn h3_ingress_byte_budget() -> Arc<ByteBudget> {
    H3_INGRESS_BYTE_BUDGET
        .get_or_init(|| Arc::new(ByteBudget::new(limits().max_h3_ingress_bytes)))
        .clone()
}

pub fn raw_forwarding_byte_budget() -> Arc<ByteBudget> {
    RAW_FORWARDING_BYTE_BUDGET
        .get_or_init(|| Arc::new(ByteBudget::new(limits().max_raw_forwarding_bytes)))
        .clone()
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
            max_h3_ingress_bytes: parse_byte_budget(
                ENV_MAX_H3_INGRESS_BYTES,
                defaults.max_h3_ingress_bytes,
            )?,
            max_raw_forwarding_bytes: parse_byte_budget(
                ENV_MAX_RAW_FORWARDING_BYTES,
                defaults.max_raw_forwarding_bytes,
            )?,
        })
    }
}

fn parse_byte_budget(name: &str, default: usize) -> Result<usize> {
    let value = parse_positive_usize(name, default)?;
    if value > Semaphore::MAX_PERMITS {
        return Err(anyhow!("{name} must not exceed {}", Semaphore::MAX_PERMITS));
    }
    Ok(value)
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
        assert_eq!(limits.max_h3_ingress_bytes, 8 * 1024 * 1024);
        assert_eq!(limits.max_raw_forwarding_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn byte_budget_releases_capacity_with_owned_permit() {
        let budget = ByteBudget::new(4);
        let permit = budget.try_acquire(4).unwrap();
        assert_eq!(budget.available(), 0);
        assert!(budget.try_acquire(1).is_err());
        drop(permit);
        assert_eq!(budget.available(), 4);
    }

    #[test]
    fn process_wide_limiters_return_shared_instances() {
        assert!(Arc::ptr_eq(
            &inbound_handshake_limit(),
            &inbound_handshake_limit()
        ));
        assert!(Arc::ptr_eq(
            &h3_ingress_byte_budget(),
            &h3_ingress_byte_budget()
        ));
        assert!(Arc::ptr_eq(
            &raw_forwarding_byte_budget(),
            &raw_forwarding_byte_budget()
        ));
    }
}
