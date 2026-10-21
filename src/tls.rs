//! In-process TLS termination for the axum server.
//!
//! The gateway ships its own certificates, so TLS is built here from PEM files
//! rather than pulled from a proxy. `rustls-pemfile` is deliberately not a
//! dependency: [`TlsConfig::from_pem_files`] strips the `-----BEGIN/END-----`
//! armour itself, base64-decodes the body and hands DER to rustls.
//!
//! # Wiring
//!
//! ```ignore
//! let tls = TlsConfig::from_pem_files(&cfg.server.cert, &cfg.server.key)?;
//! serve(listener, app, tls).await?;
//! ```
//!
//! [`serve`] never returns and does not implement graceful shutdown. To keep the
//! graceful-shutdown behaviour of [`axum::serve`], build the accept type yourself:
//!
//! ```ignore
//! axum::serve(TlsListener::new(listener, tls), app)
//!     .with_graceful_shutdown(shutdown_signal())
//!     .await?;
//! ```

use std::io;
use std::sync::Arc;

use anyhow::anyhow;
use axum::Router;
use axum::serve::Listener;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::ServerConfig;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

/// ALPN protocol advertised to clients.
///
/// Only HTTP/1.1 is offered: `axum::serve` can speak HTTP/2 only when axum is
/// built with the `http2` feature, which is not a default feature.
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// A ready-to-use `rustls` server configuration.
///
/// Cheap to clone (the configuration lives behind an [`Arc`]), so it can be
/// stored next to the listener it serves.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    config: Arc<ServerConfig>,
}

impl TlsConfig {
    /// Reads `cert_path` and `key_path`, parses them and builds a rustls server
    /// configuration (TLS 1.3 and TLS 1.2, ALPN `http/1.1`).
    ///
    /// `cert_path` holds one or more `CERTIFICATE` blocks: the end-entity
    /// (server) certificate first, then any intermediate certificates in chain
    /// order. `key_path` holds exactly one private key block, in PKCS#8
    /// (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`)
    /// form; the format is detected from the DER, not from the label.
    ///
    /// Errors name the offending file and say what was expected, e.g.
    /// `cannot read tls cert /etc/anyhop/tls.crt: No such file or directory` or
    /// `no CERTIFICATE block in /etc/anyhop/tls.crt`.
    ///
    /// # Key / certificate consistency
    ///
    /// A mismatched pair is rejected here, not at handshake time: rustls 0.23
    /// compares the `SubjectPublicKeyInfo` of the private key with the one in
    /// the end-entity certificate while building the configuration. rustls
    /// reports "unknown" (and accepts) when it cannot derive a public key from
    /// the private key; with the `ring` provider used here that does not happen
    /// for RSA or ECDSA keys, so in practice a mismatch always fails loudly.
    ///
    /// # Errors
    ///
    /// Fails when either file cannot be read, contains no block of the expected
    /// kind, is not valid PEM/base64/DER, or when the key does not belong to the
    /// certificate.
    pub fn from_pem_files(cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        install_crypto_provider();

        let cert_pem = std::fs::read_to_string(cert_path)
            .map_err(|err| anyhow!("cannot read tls cert {cert_path}: {err}"))?;
        let certs = parse_cert_chain(&cert_pem, cert_path)?;

        let key_pem = std::fs::read_to_string(key_path)
            .map_err(|err| anyhow!("cannot read tls key {key_path}: {err}"))?;
        let key = parse_private_key(&key_pem, key_path)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| {
                anyhow!(
                    "cannot use the certificate chain in {cert_path} with the private key in \
                     {key_path}: {err} (rustls compares the public keys, so this usually means \
                     the key does not belong to the certificate)"
                )
            })?;
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// Returns a [`TlsAcceptor`] for this configuration.
    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.config))
    }

    /// Returns the underlying rustls configuration.
    ///
    /// Useful when the caller needs to tune it (session storage, cipher suites)
    /// or wants to share it with another server.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }
}

/// Wraps a [`Listener`] so that every accepted connection is TLS-terminated
/// before axum sees it.
///
/// Implements [`Listener`], so it plugs into [`axum::serve`] wherever a
/// `tokio::net::TcpListener` would — which keeps `axum::serve`'s graceful
/// shutdown and HTTP/1 keep-alive behaviour intact.
#[derive(Clone)]
pub struct TlsListener<L> {
    inner: L,
    acceptor: TlsAcceptor,
}

impl<L: std::fmt::Debug> std::fmt::Debug for TlsListener<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `TlsAcceptor` is not `Debug`; the wrapped listener is the only useful part.
        f.debug_struct("TlsListener")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<L> TlsListener<L> {
    /// Wraps `inner`, terminating every connection with `tls`.
    pub fn new(inner: L, tls: TlsConfig) -> Self {
        Self {
            inner,
            acceptor: tls.acceptor(),
        }
    }
}

impl<L> Listener for TlsListener<L>
where
    L: Listener,
{
    type Io = TlsStream<L::Io>;
    type Addr = L::Addr;

    /// Accepts a connection and completes the TLS handshake.
    ///
    /// Handshake failures are logged and dropped: [`Listener`] has no way to
    /// report a per-connection error, and the next iteration blocks on the next
    /// connection, so a client that talks garbage cannot spin the loop.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = self.inner.accept().await;
            match self.acceptor.accept(stream).await {
                Ok(stream) => return (stream, addr),
                Err(err) => debug!(error = %err, "tls handshake failed; connection dropped"),
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Serves `router` over TLS on `listener` until the process dies.
///
/// `listener` is any [`Listener`] — in practice a `tokio::net::TcpListener`,
/// optionally wrapped with [`axum::serve::ListenerExt::tap_io`] to set
/// `TCP_NODELAY`. `router` is converted into an [`axum::Router`].
///
/// The accept loop, TLS handshake, HTTP/1 connection handling and per-connection
/// task spawning are all [`axum::serve`]'s; this function only wraps the
/// listener. Graceful shutdown is **not** implemented (the caller asked for the
/// simple variant): the returned future never completes, so run it as the last
/// statement of `main`. For shutdown handling, call `axum::serve` directly with
/// [`TlsListener`] and `.with_graceful_shutdown(...)`.
///
/// The same escape hatch is needed for anything else `axum::serve` accepts
/// besides a `Router` — notably a make-service that carries
/// `axum::extract::ConnectInfo<SocketAddr>`:
///
/// ```ignore
/// axum::serve(
///     TlsListener::new(listener, tls),
///     app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
/// )
/// .await?;
/// ```
///
/// # Errors
///
/// Only if [`axum::serve`] returns an I/O error, which it does not do on a live
/// listener. A failed TLS handshake is logged and the connection dropped; it
/// never stops the server.
pub async fn serve<L, M>(listener: L, router: M, tls: TlsConfig) -> anyhow::Result<()>
where
    L: Listener,
    L::Addr: std::fmt::Debug,
    M: Into<Router>,
{
    let listener = TlsListener::new(listener, tls);
    match listener.local_addr() {
        Ok(addr) => info!("anyhop listening on https://{addr:?}"),
        Err(err) => debug!(error = %err, "cannot read the local address of the tls listener"),
    }
    axum::serve(listener, router.into()).await?;
    Ok(())
}

/// Installs the `ring` crypto provider as the process default.
///
/// Idempotent: `rustls` returns an error when a provider is already installed
/// (another library, or a second call), which is fine — the installed provider
/// is used either way.
fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .is_err()
    {
        debug!("a rustls CryptoProvider was already installed; keeping it");
    }
}

/// Decodes every PEM block whose label is `label`, in file order.
///
/// Lines outside a matching `BEGIN`/`END` pair are ignored, so a key file that
/// also carries unrelated blocks (or comments) still parses.
fn pem_blocks(pem: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let mut blocks = Vec::new();
    let mut body = String::new();
    let mut collecting = false;

    for line in pem.lines() {
        let line = line.trim();
        if line == begin {
            body.clear();
            collecting = true;
        } else if line == end {
            if collecting {
                let der = STANDARD
                    .decode(body.as_bytes())
                    .map_err(|err| format!("invalid base64 in the {label} block: {err}"))?;
                blocks.push(der);
                body.clear();
                collecting = false;
            }
        } else if collecting {
            body.push_str(line);
        }
    }

    Ok(blocks)
}

/// Parses a certificate chain: every `CERTIFICATE` block, in order.
fn parse_cert_chain(pem: &str, path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let blocks =
        pem_blocks(pem, "CERTIFICATE").map_err(|err| anyhow!("cannot parse {path}: {err}"))?;
    if blocks.is_empty() {
        return Err(anyhow!(
            "no CERTIFICATE block in {path}: expected a PEM file starting with \
             -----BEGIN CERTIFICATE-----"
        ));
    }
    Ok(blocks.into_iter().map(CertificateDer::from).collect())
}

/// The concrete DER shapes rustls accepts for a private key.
#[derive(Clone, Copy)]
enum KeyKind {
    /// PKCS#8, `PRIVATE KEY`.
    Pkcs8,
    /// PKCS#1, `RSA PRIVATE KEY`.
    Pkcs1,
    /// SEC1, `EC PRIVATE KEY`.
    Sec1,
}

/// Detects the DER shape of `der` the same way rustls does.
fn detect_key_kind(der: &[u8]) -> Option<KeyKind> {
    match PrivateKeyDer::try_from(der) {
        Ok(PrivateKeyDer::Pkcs8(_)) => Some(KeyKind::Pkcs8),
        Ok(PrivateKeyDer::Pkcs1(_)) => Some(KeyKind::Pkcs1),
        Ok(PrivateKeyDer::Sec1(_)) => Some(KeyKind::Sec1),
        // `PrivateKeyDer` is #[non_exhaustive]; anything else is unsupported.
        Ok(_) => None,
        Err(_) => None,
    }
}

/// Parses the single private key block of `pem`, whichever of the three
/// supported armours it uses.
fn parse_private_key(pem: &str, path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        let blocks = pem_blocks(pem, label).map_err(|err| anyhow!("cannot parse {path}: {err}"))?;
        let Some(der) = blocks.into_iter().next() else {
            continue;
        };
        let kind = detect_key_kind(&der).ok_or_else(|| {
            anyhow!("unsupported private key format in {path}: expected PKCS#8, PKCS#1 or SEC1")
        })?;
        return Ok(match kind {
            KeyKind::Pkcs8 => PrivatePkcs8KeyDer::from(der).into(),
            KeyKind::Pkcs1 => PrivatePkcs1KeyDer::from(der).into(),
            KeyKind::Sec1 => PrivateSec1KeyDer::from(der).into(),
        });
    }

    Err(anyhow!(
        "no private key block in {path}: expected -----BEGIN PRIVATE KEY----- (PKCS#8), \
         -----BEGIN RSA PRIVATE KEY----- (PKCS#1) or -----BEGIN EC PRIVATE KEY----- (SEC1)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The certificate/key pair that ships in the repository.
    const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/localhost.crt");
    const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/localhost.key");

    /// Self-signed P-256 pair used to exercise the EC branches. It is a leaf
    /// certificate (`CA:FALSE`) with `SAN=DNS:localhost`, so the end-to-end test
    /// can also use it as its own trust anchor.
    /* test certificate generated at run time */

    /// The same EC key as PKCS#8 (`PRIVATE KEY`).
    /* generated */

    /// The same EC key as SEC1 (`EC PRIVATE KEY`).
    /* generated */

    /// `test/certs/localhost.key` re-encoded as PKCS#1 (`RSA PRIVATE KEY`):
    /// the same key, so it must load against the committed certificate.
    const RSA_KEY_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAz8z+EOWujT0z5WdpyKbC59FsRjiRy4IZall/cZlKG+3X3+Rw
9ytBEl2MnidCop0VxPjcfZWkrOPT5ITy2I3UQIIR35mblGchvhd8KH0LkWS13N24
Dgzf1udG1mWx5V1e2R/FbzM3VNz22Z5EP409ffhSeUpJNHtBzzFgumDRQf+RhOpx
LlHdjMgpxU3ii9jsoUUyUXUUg6x2YE64lK/EJRGwRcs8N76oMibKo+pdI49Ia7cX
at22GRstDSCr/2MBt1r0yyrvVvfRcV8tO0xor7IirBPuJibzAEXznjk+6B6fbUIp
cgUwS1BOPvdGZAtIYNgz1putYnMp+k+E+Ed2PwIDAQABAoIBAFtW6Op2ewZcO55/
mVD4dD2/oQ8wuG0yz4cetdUyIxApuLUSTdFnct/mvPOboD+oOrRtC0Ysa8kPD8mn
4rLrjLuaMM8PTwKpXnyXCB0n8djD4uilkMykPhPRbyK4ary+EP3xaDBb29tykRLQ
7YDdzYS8jUwBKjJmZ2PyeWkTO4f9Sebb9nM9LSNwYLrJaZsiS8yH8GtRiEOXtU8n
UmTjW0PdJ5spOk86MBqZ8mAZ80iflFWj3aqqeduNWXt32Ng1ibE1XNhT3zJeDnHp
sYW+vhVMejoIBYGkLvYXNmlfrdMPonsqtYF2X7xnp2yslm6eCqcmD46bkplyUMQ8
1H2JlTECgYEA+82iFOgAl9pK/Z5B1vcoVqcw5IsWqoEyShpVSkzxQlD7CO50MOCy
H/3Ml6ahFPcvFXTss5+jtAOnnKwBxRsE7NPZAXkqSXADmXqMRA3mGPe/ILfX+3kg
FQ9/IDEJv478jgjSvICRxDHq5JwrFYnJilE5EcLzxW6kE0+6OvH8O3cCgYEA00Od
PB7mNeHcCWv2XfS4fJtXGM7EZuOqzU+cX3tjHVpoXOu/9zmuyrk57DubIlio2TTD
zVGsMq0aAxmLSBzEpzFz35gziaYtJg7Dc/UeHfzw2jVD2jRvyYZ42Wk0FxLYBxy1
cm8DNTCoe3f7M1/kJ2TLaM8n5BGW0N10UmI8PXkCgYEAipQtM5xLV0dIJjRGv+ve
Q3JYMi9qFgRsjOPZNL8LuBehUNULFStUXM7tHjkSRduUChcDfgfJrHSmdk8j2jp4
h24/69OnNitzj7AmKf4MOImAop0LPNb4lR6mNC1I1Cf5TqIEeMG5d2SRhad8/qmK
RZlV8zR7vJibrBUgxPgQfRkCgYAHjy7MHOrt2KQP7j4FhKEpTEGkkJl0eQb+i6+z
tu2H+lkrof/fb7/yXwhUjJlzdCqugvXSne6Eba81ly9lqCndNabIxGBrt3d8GiEi
QA4Q0qEnnapM3310f4xJczs67CCwuHVBn/lEaPZOXK+vWeoHAtNIb8kknwB/fr0P
yZYQOQKBgQCXs+2hQP+S1CdUiRONGLBthn+cE35wOAXD9Mn5bqjl6jO3eOTrD2hn
CcbyiadJNou6HH9KrAXo1iaykK3FzyjET+rU0BZHyWEkcLEALBVO0aXR7XfhS4zu
2dASSLZTfu6JYxnVPx5SHCd0MbxMPTYmTQl2fF8Q+M7UED1AUIpVLg==
-----END RSA PRIVATE KEY-----
";

    /// Writes a PEM file to the temp dir and removes it again on drop.
    struct TempPem {
        path: PathBuf,
    }

    impl TempPem {
        fn new(tag: &str, contents: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("anyhop-tls-{}-{seq}-{tag}.pem", std::process::id()));
            if let Err(err) = std::fs::write(&path, contents) {
                panic!("cannot write {}: {err}", path.display());
            }
            Self { path }
        }

        fn str(&self) -> &str {
            match self.path.to_str() {
                Some(path) => path,
                None => panic!("temp path is not valid UTF-8: {}", self.path.display()),
            }
        }
    }

    impl Drop for TempPem {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Unwraps an `Ok`, failing the test otherwise (keeps clippy's
    /// `unwrap_used` happy).
    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("expected Ok, got Err({err:?})"),
        }
    }

    /// Renders a `Result`'s error, failing the test on `Ok`.
    fn err<T, E: std::fmt::Display>(result: Result<T, E>) -> String {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn loads_the_committed_localhost_pair() {
        let tls = ok(TlsConfig::from_pem_files(CERT, KEY));
        // The acceptor is what `serve` hands to the connection loop.
        let _acceptor = tls.acceptor();
        assert_eq!(
            tls.server_config().alpn_protocols,
            vec![b"http/1.1".to_vec()],
            "ALPN must advertise http/1.1 only"
        );
    }

    #[test]
    fn missing_cert_file_names_the_path() {
        let missing = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/no-such-file.crt");
        let message = err(TlsConfig::from_pem_files(missing, KEY));
        assert!(message.contains("cannot read tls cert"), "{message}");
        assert!(message.contains(missing), "{message}");
    }

    #[test]
    fn missing_key_file_names_the_path() {
        let missing = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/no-such-file.key");
        let message = err(TlsConfig::from_pem_files(CERT, missing));
        assert!(message.contains("cannot read tls key"), "{message}");
        assert!(message.contains(missing), "{message}");
    }

    #[test]
    fn file_without_certificate_block_names_the_path() {
        let key_pem = ok(std::fs::read_to_string(KEY));
        let certless = TempPem::new("key-as-cert", &key_pem);
        let message = err(TlsConfig::from_pem_files(certless.str(), KEY));
        assert!(message.contains("no CERTIFICATE block"), "{message}");
        assert!(message.contains(certless.str()), "{message}");
    }

    #[test]
    fn file_without_key_block_names_the_path() {
        let cert_pem = ok(std::fs::read_to_string(CERT));
        let keyless = TempPem::new("cert-as-key", &cert_pem);
        let message = err(TlsConfig::from_pem_files(CERT, keyless.str()));
        assert!(message.contains("no private key block"), "{message}");
        assert!(message.contains(keyless.str()), "{message}");
    }

    #[test]
    fn garbage_key_reports_the_expected_formats() {
        let garbage = TempPem::new(
            "garbage",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        );
        let message = err(TlsConfig::from_pem_files(CERT, garbage.str()));
        assert!(
            message.contains("unsupported private key format"),
            "{message}"
        );
        assert!(message.contains("PKCS#8, PKCS#1 or SEC1"), "{message}");
        assert!(message.contains(garbage.str()), "{message}");
    }

    #[test]
    fn non_base64_key_reports_the_expected_formats() {
        let garbage = TempPem::new(
            "not-base64",
            "-----BEGIN PRIVATE KEY-----\nnot base64 at all!\n-----END PRIVATE KEY-----\n",
        );
        let message = err(TlsConfig::from_pem_files(CERT, garbage.str()));
        assert!(message.contains(garbage.str()), "{message}");
        assert!(
            message.contains("invalid base64") || message.contains("unsupported private key"),
            "{message}"
        );
    }

    #[test]
    fn ec_pkcs8_pair_is_accepted() {
        let cert = TempPem::new("ec-pkcs8-cert", EC_CERT);
        let key = TempPem::new("ec-pkcs8-key", EC_KEY_PKCS8);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn ec_sec1_key_is_accepted() {
        let cert = TempPem::new("ec-sec1-cert", EC_CERT);
        let key = TempPem::new("ec-sec1-key", EC_KEY_SEC1);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn rsa_pkcs1_key_is_accepted() {
        let key = TempPem::new("rsa-pkcs1-key", RSA_KEY_PKCS1);
        let tls = ok(TlsConfig::from_pem_files(CERT, key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn mismatched_key_is_rejected() {
        // EC key against the committed RSA certificate: every parse succeeds,
        // only the public-key comparison can catch this.
        let key = TempPem::new("ec-mismatch", EC_KEY_PKCS8);
        let message = err(TlsConfig::from_pem_files(CERT, key.str()));
        assert!(
            message.contains("cannot use the certificate chain"),
            "{message}"
        );
        assert!(message.contains(CERT), "{message}");
        assert!(message.contains(key.str()), "{message}");
    }

    #[test]
    fn parses_every_certificate_block_in_order() {
        let pem = format!("{EC_CERT}{EC_CERT}");
        let certs = ok(parse_cert_chain(&pem, "inline.pem"));
        assert_eq!(certs.len(), 2, "both blocks must be kept for the chain");
        assert_eq!(certs[0], certs[1]);
    }

    /// End-to-end: a real TLS handshake against [`serve`], over a real socket.
    #[tokio::test]
    async fn serves_a_request_over_tls() {
        use axum::Router;
        use axum::routing::get;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let cert = TempPem::new("e2e-cert", EC_CERT);
        let key = TempPem::new("e2e-key", EC_KEY_PKCS8);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));

        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await);
        let addr = ok(listener.local_addr());
        let app = Router::new().route("/", get(|| async { "hello tls" }));
        let server = tokio::spawn(serve(listener, app, tls));

        let mut roots = rustls::RootCertStore::empty();
        let der = ok(pem_blocks(EC_CERT, "CERTIFICATE")).remove(0);
        ok(roots.add(CertificateDer::from(der)));
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let name = ok(rustls::pki_types::ServerName::try_from("localhost"));

        ok(
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                let stream = ok(tokio::net::TcpStream::connect(addr).await);
                let mut stream = ok(connector.connect(name, stream).await);
                ok(stream
                    .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await);
                let mut response = Vec::new();
                ok(stream.read_to_end(&mut response).await);
                let response = String::from_utf8_lossy(&response);
                assert!(response.contains("200 OK"), "{response}");
                assert!(response.contains("hello tls"), "{response}");
            })
            .await,
        );

        server.abort();
    }

    #[test]
    fn pem_blocks_ignores_other_labels() {
        let pem = format!("{EC_CERT}{EC_KEY_PKCS8}");
        let certs = ok(pem_blocks(&pem, "CERTIFICATE"));
        let keys = ok(pem_blocks(&pem, "PRIVATE KEY"));
        assert_eq!(certs.len(), 1);
        assert_eq!(keys.len(), 1);
        assert_eq!(ok(pem_blocks(&pem, "NOT A LABEL")).len(), 0);
    }
}
