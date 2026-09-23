//! Statistical models for per-candidate ranking.
//!
//! Three independent components, each with a single responsibility:
//!
//! * [`KalmanRtt`] — scalar Kalman filter for RTT, with integrated one-sided
//!   CUSUM change detector. The filter tracks the posterior mean *and*
//!   variance; the variance is the uncertainty signal the rest of the system
//!   uses. CUSUM detects step increases (gradual CDN degradation) that a
//!   simple failure threshold misses, and widens the variance so the filter
//!   re-converges quickly on the new regime.
//!
//! * [`NigThroughput`] — Normal-Inverse-Gamma conjugate posterior over
//!   log-throughput. Updates are O(1) and exact. Time discounting is applied
//!   on each new observation rather than on a wall-clock schedule, so a
//!   candidate with no traffic retains its estimate indefinitely until new
//!   evidence arrives. Subnet-level priors (see [`SubnetKey`]) propagate
//!   information across candidates that share an IP prefix, which is the
//!   primary mechanism for making Thompson Sampling viable at N > 1000.
//!
//! * [`score`] — the unified ranking key, in seconds:
//!   `rtt_estimate + payload_bytes / throughput_sample`.
//!   When `payload_bytes` is zero the throughput layer is entirely inert —
//!   the score is the Kalman RTT estimate, exactly matching the pre-existing
//!   EWMA behaviour. Thompson Sampling only fires when `payload_bytes > 0`,
//!   so operators who do not configure a payload size get no change in
//!   routing behaviour.
//!
//! All types are plain structs with no interior mutability. They live inside
//! the probe task's exclusive `PoolState` and are never shared across tasks.

use std::net::IpAddr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Kalman RTT filter + one-sided CUSUM change detector
// ---------------------------------------------------------------------------

/// Initial (wide) posterior variance assigned to every new or reset candidate.
/// Large enough to make the filter high-gain until it converges.
const WIDE_P: f64 = 1_000.0; // ms²

/// Posterior variance below which the filter is considered converged and
/// CUSUM activation is permitted.
const CUSUM_ACTIVATE_P: f64 = 5.0; // ms²

/// The RTT shift (ms) that CUSUM is tuned to detect. Half this value is
/// subtracted each step as the allowance; false alarms are unlikely below it.
const CUSUM_DELTA_MS: f64 = 50.0;

/// CUSUM alarm threshold. Expressed in ms so the alarm fires after cumulative
/// evidence of a ~CUSUM_DELTA_MS shift accumulates past this level.
const CUSUM_H: f64 = 200.0;

/// Scalar Kalman filter for RTT, with integrated one-sided CUSUM.
///
/// The process model is a random walk: `x_k = x_{k-1} + w_k`, where `w_k`
/// has variance Q. This is appropriate for CDN nodes whose RTT is piecewise-
/// stable with occasional step changes (route updates, PoP failovers). The
/// CUSUM component detects those step changes so the filter can re-converge
/// on the new baseline quickly, without forcing Q to be large enough to
/// track rapid changes at the cost of steady-state noise.
#[derive(Debug, Clone)]
pub struct KalmanRtt {
    /// Posterior mean, in milliseconds.
    pub mean_ms: f64,
    /// Posterior variance (uncertainty), in ms².
    /// Starts wide, shrinks as observations accumulate, resets on a CUSUM
    /// alarm so the filter behaves like a high-gain filter until it re-settles.
    pub variance: f64,
    /// Process noise Q: how much the true RTT can drift between observations.
    q: f64,
    /// Observation noise R: expected measurement variance of one RTT sample.
    r: f64,
    /// One-sided CUSUM accumulator for detecting upward RTT shifts.
    cusum: f64,
    /// Whether the filter has converged at least once; CUSUM only fires
    /// after the first convergence to avoid false alarms during startup.
    converged: bool,
}

impl KalmanRtt {
    pub fn new(q: f64, r: f64) -> Self {
        Self {
            mean_ms: 200.0, // conservative prior: 200 ms before any data
            variance: WIDE_P,
            q,
            r,
            cusum: 0.0,
            converged: false,
        }
    }

    /// Incorporate one RTT measurement.
    ///
    /// Returns `true` when CUSUM fired, indicating a detected upward regime
    /// change. The internal state has already been reset to a wide posterior
    /// so the next call enters a fast-convergence phase. The caller should log
    /// a warning; no other action is required.
    pub fn update(&mut self, obs: Duration) -> bool {
        let obs_ms = obs.as_secs_f64() * 1000.0;

        // Predict: advance the state covariance by the process noise.
        let p_pred = self.variance + self.q;

        // Update: apply the Kalman gain.
        let k = p_pred / (p_pred + self.r);
        let innovation = obs_ms - self.mean_ms;
        self.mean_ms += k * innovation;
        self.variance = (1.0 - k) * p_pred;

        if self.variance < CUSUM_ACTIVATE_P {
            self.converged = true;
        }

        // CUSUM is only meaningful once the filter has settled on a baseline.
        if !self.converged {
            return false;
        }

        // Page's one-sided CUSUM for an upward shift of CUSUM_DELTA_MS.
        // The slack CUSUM_DELTA_MS/2 means the statistic drifts down when the
        // RTT is below mean + CUSUM_DELTA_MS/2 and drifts up above it.
        self.cusum = (self.cusum + innovation - CUSUM_DELTA_MS / 2.0).max(0.0);
        if self.cusum > CUSUM_H {
            // Reset: widen P so the filter re-acquires the new level quickly,
            // and clear the accumulator so CUSUM does not fire again immediately.
            self.variance = WIDE_P;
            self.cusum = 0.0;
            return true;
        }
        false
    }

    /// Best estimate of the current RTT, in Duration form.
    #[inline]
    pub fn estimate(&self) -> Duration {
        Duration::from_secs_f64(self.mean_ms / 1000.0)
    }

    /// Whether the filter has converged (variance dropped below the activation threshold).
    #[inline]
    pub fn is_converged(&self) -> bool {
        self.converged
    }
}

// ---------------------------------------------------------------------------
// Normal-Inverse-Gamma posterior over log-throughput
// ---------------------------------------------------------------------------

/// Throughput lower bound used to guard against log(0) and score overflow.
/// 1 KB/s is below any real connection that would be used for web traffic.
pub const MIN_THROUGHPUT_BPS: f64 = 1_024.0;

/// Default prior parameters: a weak belief centred at 256 KB/s with high
/// uncertainty. This is conservative: most CDN nodes can do far better, so
/// the posterior moves toward the true value quickly.
pub fn default_nig_prior() -> NigThroughput {
    NigThroughput::new(
        (256.0 * 1_024.0_f64).ln(), // μ₀ ≈ ln(262 144) ≈ 12.5 nats
        0.5,                        // κ₀: half a pseudo-observation
        1.5,                        // α₀
        1.0,                        // β₀
    )
}

/// Normal-Inverse-Gamma conjugate posterior over log-throughput.
///
/// The model: `log(throughput) ~ N(μ, σ²)` with a NIG prior on `(μ, σ²)`.
/// Updates are O(1) and exact — no Monte Carlo sampling is required for the
/// posterior parameters themselves. Thompson Sampling draws one value from
/// the posterior predictive, which is a Student-t in log space; we use the
/// normal approximation to that t, which is accurate for α > 2 and
/// acceptably optimistic in the tails for sparse data.
///
/// Time discounting: the pseudo-count κ and shape α are scaled by `γ < 1`
/// *before* each new observation is folded in. This gives recent observations
/// more weight than old ones without requiring a separate scheduled sweep.
/// A candidate with zero traffic retains its estimate indefinitely, which is
/// correct: absence of new data is not evidence of change.
#[derive(Debug, Clone)]
pub struct NigThroughput {
    /// Posterior mean of log-throughput (nats).
    pub mu: f64,
    /// Pseudo-observation count; measures confidence in μ.
    pub kappa: f64,
    /// Shape of the inverse-gamma marginal on variance.
    pub alpha: f64,
    /// Scale of the inverse-gamma marginal on variance.
    pub beta: f64,
    // Prior floor — discount never goes below the original prior strength.
    #[allow(dead_code)]
    mu0: f64,
    kappa0: f64,
    alpha0: f64,
    beta0: f64,
}

impl NigThroughput {
    pub fn new(mu: f64, kappa: f64, alpha: f64, beta: f64) -> Self {
        Self {
            mu,
            kappa,
            alpha,
            beta,
            mu0: mu,
            kappa0: kappa,
            alpha0: alpha,
            beta0: beta,
        }
    }

    /// Update the posterior with one throughput measurement (bytes/sec).
    ///
    /// `gamma` is the time-discount factor applied before the update. Values
    /// near 1.0 retain old information longer; 0.9 causes roughly half the
    /// effective sample count to decay within ~7 observations.
    pub fn observe(&mut self, bps: f64, gamma: f64) {
        let x = bps.max(MIN_THROUGHPUT_BPS).ln();
        self.decay(gamma);

        // Conjugate NIG update for one observation x:
        //   κ_n = κ + 1
        //   μ_n = (κ μ + x) / κ_n
        //   α_n = α + ½
        //   β_n = β + κ(x − μ)² / (2 κ_n)
        let kn = self.kappa + 1.0;
        let diff = x - self.mu;
        self.mu = (self.kappa * self.mu + x) / kn;
        self.alpha += 0.5;
        self.beta += self.kappa * diff * diff / (2.0 * kn);
        self.kappa = kn;
    }

    /// Apply time decay without a new observation. Used for subnet priors
    /// when they are updated on behalf of a member candidate.
    pub fn decay(&mut self, gamma: f64) {
        self.kappa = (self.kappa * gamma).max(self.kappa0);
        self.alpha = (self.alpha * gamma).max(self.alpha0);
        self.beta = (self.beta * gamma).max(self.beta0);
        // mu is a weighted mean; scaling kappa symmetrically keeps it stable.
    }

    /// Draw one throughput sample (bytes/sec) for Thompson Sampling.
    ///
    /// The posterior predictive is Student-t in log space; we use the normal
    /// approximation `N(μ, β(κ+1)/(α·κ))`. The result is exponentiated and
    /// clamped to at least [`MIN_THROUGHPUT_BPS`].
    pub fn sample(&self) -> f64 {
        // Marginal variance of μ under the NIG: β(κ+1)/(α·κ).
        let scale_sq = (self.beta * (self.kappa + 1.0)) / (self.alpha * self.kappa);
        let scale = scale_sq.sqrt().max(1e-6);
        let log_bps = self.mu + scale * standard_normal();
        log_bps.exp().max(MIN_THROUGHPUT_BPS)
    }

    /// Posterior mean throughput (bytes/sec), for diagnostics and logging.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn mean_bps(&self) -> f64 {
        // E[log-normal] with μ and σ² = β/(α−1) (when α > 1).
        if self.alpha > 1.0 {
            (self.mu + self.beta / (2.0 * (self.alpha - 1.0))).exp()
        } else {
            self.mu.exp()
        }
    }
}

// ---------------------------------------------------------------------------
// Subnet grouping for hierarchical priors
// ---------------------------------------------------------------------------

/// The subnet key used to group candidates into a shared prior.
///
/// IPv4 candidates are grouped into /24 subnets (first three octets);
/// IPv6 into /48 subnets (first six bytes). This reflects CDN anycast
/// topology: within a /24 or /48 the addresses typically share the same
/// PoP and have correlated throughput. Sharing a prior means one
/// observation propagates useful information to all sibling candidates,
/// which is what keeps Thompson Sampling viable at N > 1000 even when
/// only a few candidates have received direct observations.
///
/// Candidates from different ASes or PoPs that happen to share a prefix
/// are not harmed: the prior is weak (κ₀ = 0.5), so a few individual
/// observations override it quickly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    V4([u8; 3]),
    V6([u8; 6]),
}

impl SubnetKey {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => {
                let o = a.octets();
                SubnetKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(a) => {
                let o = a.octets();
                SubnetKey::V6([o[0], o[1], o[2], o[3], o[4], o[5]])
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Score formula
// ---------------------------------------------------------------------------

/// Compute the ranking score for a candidate (in seconds, lower is better).
///
/// When `payload_bytes` is zero the score is the Kalman RTT estimate — no
/// throughput sampling occurs and routing behaviour is unchanged relative
/// to the EWMA-based design. When `payload_bytes > 0` a single sample is
/// drawn from the NIG posterior and used to estimate transfer time; the
/// total score is `rtt + payload / sampled_throughput`.
///
/// Candidates with little throughput data have wide NIG posteriors and
/// will occasionally draw optimistic samples, routing a connection their
/// way and collecting a passive observation. Candidates with tight posteriors
/// draw near their mean, providing stability.
pub fn score(kalman: &KalmanRtt, nig: &NigThroughput, payload_bytes: u64) -> f64 {
    let rtt_s = kalman.mean_ms / 1000.0;
    if payload_bytes == 0 {
        return rtt_s;
    }
    let tp = nig.sample().max(MIN_THROUGHPUT_BPS);
    rtt_s + payload_bytes as f64 / tp
}

// ---------------------------------------------------------------------------
// PRNG utility
// ---------------------------------------------------------------------------

/// One standard-normal variate via the Box-Muller transform.
/// Uses `rand::random::<f64>()` which is already a project dependency.
fn standard_normal() -> f64 {
    use std::f64::consts::TAU;
    let u1 = (rand::random::<f64>()).max(f64::EPSILON);
    let u2 = rand::random::<f64>();
    (-2.0 * u1.ln()).sqrt() * (TAU * u2).cos()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kalman_converges_and_tracks() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Feed 20 observations at 50 ms.
        for _ in 0..20 {
            k.update(Duration::from_millis(50));
        }
        let est_ms = k.estimate().as_millis();
        assert!(
            (45..=55).contains(&est_ms),
            "estimate {est_ms} ms out of range"
        );
        assert!(k.variance < CUSUM_ACTIVATE_P, "should have converged");
    }

    #[test]
    fn cusum_fires_on_step_increase() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Converge at 50 ms.
        for _ in 0..30 {
            k.update(Duration::from_millis(50));
        }
        assert!(k.converged);
        // Now step up to 200 ms; CUSUM should fire within a moderate number
        // of observations (well under 100).
        let mut fired = false;
        for _ in 0..100 {
            if k.update(Duration::from_millis(200)) {
                fired = true;
                break;
            }
        }
        assert!(fired, "CUSUM did not fire on a large step increase");
        // After firing, variance should have been reset.
        assert!(k.variance >= WIDE_P / 2.0);
    }

    #[test]
    fn cusum_does_not_fire_on_noise() {
        let mut k = KalmanRtt::new(0.01, 0.1);
        // Converge at 50 ms.
        for _ in 0..30 {
            k.update(Duration::from_millis(50));
        }
        // Feed noisy observations around 50 ms — CUSUM must not fire.
        for i in 0..200 {
            let obs = if i % 2 == 0 { 45 } else { 55 };
            let fired = k.update(Duration::from_millis(obs));
            assert!(!fired, "CUSUM fired on noise at step {i}");
        }
    }

    #[test]
    fn nig_posterior_moves_toward_truth() {
        let mut n = default_nig_prior();
        // True throughput: 1 MB/s.
        let truth = 1_024.0 * 1_024.0;
        for _ in 0..50 {
            n.observe(truth, 1.0); // no discount
        }
        let mean = n.mean_bps();
        // After 50 observations the posterior mean should be within 20% of truth.
        assert!(
            mean > truth * 0.8 && mean < truth * 1.2,
            "posterior mean {mean:.0} bps far from truth {truth:.0}"
        );
    }

    #[test]
    fn nig_discount_weakens_old_evidence() {
        let mut n = default_nig_prior();
        // Establish a strong belief at 1 MB/s.
        let high = 1_024.0 * 1_024.0;
        for _ in 0..50 {
            n.observe(high, 1.0);
        }
        let kappa_before = n.kappa;
        // Now observe 64 KB/s with heavy discount — the prior weakens and
        // the new evidence takes over.
        let low = 64.0 * 1_024.0;
        for _ in 0..20 {
            n.observe(low, 0.5);
        }
        assert!(
            n.kappa < kappa_before,
            "discount did not weaken old evidence"
        );
    }

    #[test]
    fn score_degrades_to_rtt_when_payload_zero() {
        let k = KalmanRtt::new(0.01, 0.1);
        let n = default_nig_prior();
        // With payload_bytes = 0, score must equal rtt estimate regardless of nig.
        let s = score(&k, &n, 0);
        let rtt_s = k.estimate().as_secs_f64();
        assert!(
            (s - rtt_s).abs() < 1e-9,
            "score with payload=0 must equal RTT"
        );
    }

    #[test]
    fn score_penalises_slow_throughput() {
        let mut k_fast = KalmanRtt::new(0.01, 0.1);
        let mut k_slow = KalmanRtt::new(0.01, 0.1);
        // fast: 20 ms RTT; slow: 30 ms RTT.
        for _ in 0..30 {
            k_fast.update(Duration::from_millis(20));
            k_slow.update(Duration::from_millis(30));
        }
        let mut nig_fast = default_nig_prior();
        let mut nig_slow = default_nig_prior();
        // fast: 1 MB/s; slow: 64 KB/s.
        for _ in 0..50 {
            nig_fast.observe(1_024.0 * 1_024.0, 1.0);
            nig_slow.observe(64.0 * 1_024.0, 1.0);
        }
        // Payload: 512 KB. fast should almost always score lower.
        let payload = 512 * 1_024;
        let mut fast_wins = 0u32;
        for _ in 0..100 {
            if score(&k_fast, &nig_fast, payload) < score(&k_slow, &nig_slow, payload) {
                fast_wins += 1;
            }
        }
        // With such a large throughput difference, fast should win > 90% of the time.
        assert!(
            fast_wins > 90,
            "fast candidate won only {fast_wins}/100 trials"
        );
    }

    #[test]
    fn subnet_key_groups_correctly() {
        let a: IpAddr = "172.64.229.1".parse().unwrap();
        let b: IpAddr = "172.64.229.200".parse().unwrap();
        let c: IpAddr = "172.64.230.1".parse().unwrap();
        assert_eq!(
            SubnetKey::of(a),
            SubnetKey::of(b),
            "same /24 must share key"
        );
        assert_ne!(
            SubnetKey::of(a),
            SubnetKey::of(c),
            "different /24 must differ"
        );
    }
}
