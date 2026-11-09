//! Which hosts a sync redirect may send the SDK to (mirrors the Go SDK's redirect policy).
//!
//! A signed download is a 302 from the sync endpoint to a URL the SDK then fetches without credentials. The
//! target must be https on port 443, carry no userinfo, name a Google Cloud Storage host or a host the
//! application configured (exact host or `*.domain`), and the download itself must not redirect again. A
//! refused target counts as a failed signed download (fallback through the endpoint plus the redirect cool-down).

use reqwest::Url;

/// Environment variable listing extra download hosts, comma separated.
pub const REDIRECT_HOSTS_ENV: &str = "ATTOS_REDIRECT_HOSTS";

/// Google Cloud Storage (path-style and virtual-hosted) and the Attos download CDN (exact host).
const DEFAULT_HOSTS: [&str; 3] = ["storage.googleapis.com", "*.storage.googleapis.com", "dl.attoscloud.com"];

#[derive(Debug, Clone)]
pub(crate) struct RedirectPolicy {
    hosts: Vec<String>,
    /// Tests only: also allow http, IP literals, loopback and any host.
    any_target: bool,
}

fn normalize(h: &str) -> Option<String> {
    let h = h.trim().to_ascii_lowercase();
    if h.is_empty() || h.contains(['/', '@', ':', '?', '#', '%', ' ', '\t']) || h.starts_with('.') || h.ends_with('.') {
        return None;
    }
    if let Some(rest) = h.strip_prefix("*.") {
        // "*.com" style wildcards are refused
        return (!rest.is_empty() && !rest.contains('*') && rest.contains('.')).then_some(h);
    }
    (!h.contains('*')).then_some(h)
}

impl RedirectPolicy {
    /// `extra` entries come from `SyncConfig::redirect_hosts`; `ATTOS_REDIRECT_HOSTS` is added to them.
    pub(crate) fn new(extra: &[String], env: Option<&str>, any_target: bool) -> Self {
        let from_env = env.unwrap_or("").split(',').map(str::to_string).collect::<Vec<_>>();
        let hosts = DEFAULT_HOSTS
            .iter()
            .map(|s| s.to_string())
            .chain(from_env)
            .chain(extra.iter().cloned())
            .filter_map(|h| normalize(&h))
            .collect();
        Self { hosts, any_target }
    }

    /// Whether a signed download may be fetched from `u`.
    pub(crate) fn check(&self, u: &Url) -> Result<(), String> {
        if self.any_target {
            return if u.host_str().is_some() && matches!(u.scheme(), "http" | "https") {
                Ok(())
            } else {
                Err(format!("unusable redirect target {}", redact(u)))
            };
        }
        if u.scheme() != "https" {
            return Err(format!("redirect target {} is not https", redact(u)));
        }
        if !u.username().is_empty() || u.password().is_some() {
            return Err(format!("redirect target {} carries userinfo", redact(u)));
        }
        if u.fragment().is_some() {
            return Err(format!("redirect target {} is malformed", redact(u)));
        }
        if let Some(p) = u.port() {
            // The url crate drops the default port, so any explicit port is not 443.
            return Err(format!("redirect target {} uses port {}", redact(u), p));
        }
        let host = match u.host() {
            Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
            _ => return Err(format!("redirect target {} is not an allowed host", redact(u))),
        };
        if host.ends_with('.') || !host.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.') {
            return Err(format!("redirect target {} is not an allowed host", redact(u)));
        }
        for pat in &self.hosts {
            match pat.strip_prefix("*.") {
                Some(rest) => {
                    if host.len() > rest.len() + 1 && host.ends_with(&format!(".{}", rest)) {
                        return Ok(());
                    }
                }
                None => {
                    if &host == pat {
                        return Ok(());
                    }
                }
            }
        }
        Err(format!("redirect host {:?} is not in the allowed list (set {} or SyncConfig::redirect_hosts)", host, REDIRECT_HOSTS_ENV))
    }

    /// Whether an ordinary (unmarked) redirect of the sync request may be followed: never a downgrade from
    /// https, never userinfo, and only to the same host or an allowed one.
    pub(crate) fn allows_ordinary(&self, next: &Url, first: &Url) -> Result<(), String> {
        if self.any_target {
            return Ok(());
        }
        if first.scheme() == "https" && next.scheme() != "https" {
            return Err(format!("redirect from https to {} refused", next.scheme()));
        }
        if !next.username().is_empty() || next.password().is_some() {
            return Err("redirect target carries userinfo".into());
        }
        if same_origin_host(next, first) {
            return Ok(());
        }
        self.check(next)
    }
}

/// Same host and port (credentials may only travel with these).
pub(crate) fn same_origin_host(a: &Url, b: &Url) -> bool {
    a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
        && a.port_or_known_default() == b.port_or_known_default()
}

/// The URL without its query (signed URLs carry the signature there) or credentials.
fn redact(u: &Url) -> String {
    let mut r = u.clone();
    r.set_query(None);
    let _ = r.set_username("");
    let _ = r.set_password(None);
    r.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> RedirectPolicy {
        let extra: Vec<String> = ["dl.example.com", "*.cdn.example.net", "BAD/HOST", "*.com", "x*y.com", ""]
            .iter()
            .map(|s| s.to_string())
            .collect();
        RedirectPolicy::new(&extra, None, false)
    }

    #[test]
    fn allowed_hosts() {
        for raw in [
            "https://storage.googleapis.com/bkt/obj?X-Goog-Signature=abc&generation=7",
            "https://STORAGE.GOOGLEAPIS.COM/bkt/obj",
            "https://storage.googleapis.com:443/bkt/obj",
            "https://my-bucket.storage.googleapis.com/obj?x=1",
            "https://dl.attoscloud.com/o/datasets/abc/d.v2.attos/1699999999123456?exp=1800000300&sig=abc",
            "https://dl.example.com/o/abc",
            "https://edge.cdn.example.net/o/abc",
            "https://a.b.cdn.example.net/o/abc",
        ] {
            let u = Url::parse(raw).unwrap();
            assert!(p().check(&u).is_ok(), "{} refused", raw);
        }
    }

    #[test]
    fn denied_hosts() {
        for raw in [
            "http://storage.googleapis.com/b/o",
            "https://user:pw@storage.googleapis.com/b/o",
            "https://user@storage.googleapis.com/b/o",
            "https://storage.googleapis.com@evil.com/b/o",
            "https://storage.googleapis.com.evil.com/b/o",
            "https://evil.com/storage.googleapis.com/b/o",
            "https://evil.com/?storage.googleapis.com",
            "https://evilstorage.googleapis.com/b/o",
            "https://storage.googleapis.com.:443/b/o",
            "https://storage.googleapis.com:8443/b/o",
            "https://127.0.0.1/b/o",
            "https://[::1]/b/o",
            "https://localhost/b/o",
            "https://storage.googleapis.com/b/o#frag",
            "https://st\u{43e}rage.googleapis.com/b/o",
            "https://googleapis.com/b/o",
            "https://evildl.attoscloud.com/o",
            "https://x.dl.attoscloud.com/o",
            "https://attoscloud.com/o",
            "http://dl.attoscloud.com/o",
            "https://example.com/b/o",
            "https://cdn.example.net/o",
            "https://x.com/o",
            "https://xay.com/o",
            "https://dl.example.com.evil.com/o",
            "https://notdl.example.com/o",
            "https://storage.googleapis.com%2eevil.com/b/o",
        ] {
            if let Ok(u) = Url::parse(raw) {
                assert!(p().check(&u).is_err(), "{} allowed", raw);
            }
        }
    }

    #[test]
    fn env_hosts_and_test_escape() {
        let q = RedirectPolicy::new(&[], Some("cdn.acme.io, *.edge.acme.io"), false);
        assert!(q.check(&Url::parse("https://cdn.acme.io/o").unwrap()).is_ok());
        assert!(q.check(&Url::parse("https://a.edge.acme.io/o").unwrap()).is_ok());
        assert!(q.check(&Url::parse("https://acme.io/o").unwrap()).is_err());
        let any = RedirectPolicy::new(&[], None, true);
        assert!(any.check(&Url::parse("http://127.0.0.1:9/o").unwrap()).is_ok());
    }

    #[test]
    fn ordinary_redirects() {
        let first = Url::parse("https://api.attos.dev/api/v1/datasets/sync/x").unwrap();
        let q = p();
        assert!(q.allows_ordinary(&Url::parse("https://api.attos.dev/other").unwrap(), &first).is_ok());
        assert!(q.allows_ordinary(&Url::parse("http://api.attos.dev/other").unwrap(), &first).is_err());
        assert!(q.allows_ordinary(&Url::parse("https://evil.com/x").unwrap(), &first).is_err());
        assert!(q.allows_ordinary(&Url::parse("https://storage.googleapis.com/b/o").unwrap(), &first).is_ok());
    }
}
