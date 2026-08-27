//! Shared multi-address connection racing.
//!
//! DNS returns candidates in preferred-family interleaved order. This module
//! starts them with the RFC 8305 recommended 250 ms spacing and returns the
//! first successful result, keeping one overall route timeout.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const MAX_CANDIDATES: usize = 16;

pub async fn race<T, F, Fut>(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
    attempt: F,
) -> Result<(T, SocketAddr)>
where
    F: Fn(SocketAddr) -> Fut + Clone,
    Fut: Future<Output = Result<T>>,
{
    if addrs.is_empty() {
        return Err(anyhow!("upstream resolution returned no addresses"));
    }

    let addrs = &addrs[..addrs.len().min(MAX_CANDIDATES)];
    let launch = |addr| {
        let attempt = attempt.clone();
        async move { attempt(addr).await.map(|value| (value, addr)) }
    };
    let mut attempts = FuturesUnordered::new();
    attempts.push(launch(addrs[0]));

    timeout(connect_timeout, async move {
        let mut errors = Vec::new();
        let mut next = 1;
        let stagger = tokio::time::sleep(HAPPY_EYEBALLS_DELAY);
        tokio::pin!(stagger);
        while !attempts.is_empty() {
            tokio::select! {
                result = attempts.next() => match result.expect("attempt set is non-empty") {
                    Ok(value) => return Ok(value),
                    Err(error) => {
                        errors.push(format!("{error:#}"));
                        // A prompt failure is useful signal: do not make the
                        // next candidate wait out the normal family stagger.
                        if let Some(&addr) = addrs.get(next) {
                            attempts.push(launch(addr));
                            next += 1;
                            stagger.as_mut().reset(Instant::now() + HAPPY_EYEBALLS_DELAY);
                        }
                    }
                },
                _ = &mut stagger, if next < addrs.len() => {
                    attempts.push(launch(addrs[next]));
                    next += 1;
                    stagger.as_mut().reset(Instant::now() + HAPPY_EYEBALLS_DELAY);
                }
            }
        }
        Err(anyhow!(
            "all upstream connection attempts failed: {}",
            errors.join("; ")
        ))
    })
    .await
    .context("upstream connect timed out")?
}

pub async fn tcp(
    addrs: &[SocketAddr],
    connect_timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    race(addrs, connect_timeout, |addr| async move {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to {addr}"))?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_uses_a_later_candidate() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let live = listener.local_addr().unwrap();
        let unavailable = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });

        let (_, selected) = tcp(&[unavailable, live], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(selected, live);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn preferred_candidate_keeps_the_head_start() {
        let preferred = "[::1]:443".parse().unwrap();
        let alternate = "127.0.0.1:443".parse().unwrap();
        let (value, selected) = race(
            &[preferred, alternate],
            Duration::from_secs(1),
            |addr| async move {
                if addr == preferred {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok("preferred")
                } else {
                    Ok("alternate")
                }
            },
        )
        .await
        .unwrap();
        assert_eq!((value, selected), ("preferred", preferred));
    }

    #[tokio::test]
    async fn prompt_failure_starts_the_next_candidate_immediately() {
        let first = "[::1]:443".parse().unwrap();
        let second = "127.0.0.1:443".parse().unwrap();
        let starts = Arc::new(AtomicUsize::new(0));
        let before = Instant::now();
        let (_, selected) = race(&[first, second], Duration::from_secs(1), {
            let starts = starts.clone();
            move |addr| {
                let starts = starts.clone();
                async move {
                    starts.fetch_add(1, Ordering::Relaxed);
                    if addr == first {
                        Err(anyhow!("first candidate failed"))
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(selected, second);
        assert_eq!(starts.load(Ordering::Relaxed), 2);
        assert!(before.elapsed() < HAPPY_EYEBALLS_DELAY);
    }
}
