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
use std::time::Duration;

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
/// Queue of finished handshakes waiting for axum to take them.
type ReadyQueue<L> = Arc<
    std::sync::Mutex<
        std::collections::VecDeque<(TlsStream<<L as Listener>::Io>, <L as Listener>::Addr)>,
    >,
>;

pub struct TlsListener<L>
where
    L: Listener,
{
    inner: L,
    acceptor: TlsAcceptor,
    /// Handshakes that finished before axum asked for them. A queue, not a
    /// future: awaiting the handshake inside `accept()` would let one silent TCP
    /// connection stall the whole listener (`axum::serve` calls `accept()` in
    /// sequence).
    ready: ReadyQueue<L>,
    /// Woken when `ready` gains an entry.
    notify: Arc<tokio::sync::Notify>,
    /// In-flight handshakes, so a connection flood cannot spawn unbounded tasks.
    pending: Arc<std::sync::atomic::AtomicUsize>,
}

impl<L: Listener + Clone> Clone for TlsListener<L> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            acceptor: self.acceptor.clone(),
            ready: Arc::clone(&self.ready),
            notify: Arc::clone(&self.notify),
            pending: Arc::clone(&self.pending),
        }
    }
}

impl<L: Listener + std::fmt::Debug> std::fmt::Debug for TlsListener<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `TlsAcceptor` is not `Debug`; the wrapped listener is the only useful part.
        f.debug_struct("TlsListener")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<L: Listener> TlsListener<L> {
    /// Wraps `inner`, terminating every connection with `tls`.
    pub fn new(inner: L, tls: TlsConfig) -> Self {
        Self {
            inner,
            acceptor: tls.acceptor(),
            ready: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            notify: Arc::new(tokio::sync::Notify::new()),
            pending: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

/// How long a client may hold a connection without completing the handshake.
///
/// This is a denial-of-service guard, not a tuning knob: `axum::serve` awaits
/// `accept()` sequentially, so a handshake awaited *inline* would let one silent
/// TCP connection stall every future connection — the whole listener goes down
/// for the price of one socket.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Concurrent handshakes allowed. Each costs one task and one socket; the cap
/// keeps a connection flood from spawning tasks without bound.
const MAX_HANDSHAKES: usize = 1024;

impl<L> Listener for TlsListener<L>
where
    L: Listener,
    L::Io: Send + 'static,
    L::Addr: Clone + Send + 'static,
{
    type Io = TlsStream<L::Io>;
    type Addr = L::Addr;

    /// Accepts a connection, completing the TLS handshake off the accept path.
    ///
    /// Handshakes run in their own tasks and land in `ready`; the loop returns as
    /// soon as one is available, or takes the next TCP connection in the
    /// meantime. A client that connects and says nothing therefore costs one
    /// task and at most [`HANDSHAKE_TIMEOUT`], never the listener.
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Some(done) = self.take_ready() {
                return done;
            }
            // At the cap, wait for a slot instead of accepting more sockets.
            let at_cap = self.pending.load(std::sync::atomic::Ordering::Relaxed) >= MAX_HANDSHAKES;
            if at_cap {
                self.notify.notified().await;
                continue;
            }
            tokio::select! {
                biased;
                // A handshake finished while we were waiting for a new socket.
                () = self.notify.notified() => {}
                (stream, addr) = self.inner.accept() => {
                    self.spawn_handshake(stream, addr);
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

impl<L> TlsListener<L>
where
    L: Listener,
    L::Io: Send + 'static,
    L::Addr: Clone + Send + 'static,
{
    fn take_ready(&self) -> Option<(TlsStream<L::Io>, L::Addr)> {
        self.ready
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    fn spawn_handshake(&self, stream: L::Io, addr: L::Addr) {
        self.pending
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let acceptor = self.acceptor.clone();
        let ready = Arc::clone(&self.ready);
        let notify = Arc::clone(&self.notify);
        let pending = Arc::clone(&self.pending);
        tokio::spawn(async move {
            let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            match outcome {
                Ok(Ok(stream)) => {
                    ready
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push_back((stream, addr));
                }
                Ok(Err(err)) => debug!(error = %err, "tls handshake failed; connection dropped"),
                Err(_) => debug!("tls handshake timed out; connection dropped"),
            }
            pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            notify.notify_one();
        });
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
    L::Io: Send + 'static,
    L::Addr: Clone + Send + std::fmt::Debug + 'static,
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

    /// The throwaway certificate pair, generated on demand (see
    /// `scripts/gen-test-certs.sh`): a private key is deliberately not committed.
    const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/localhost.crt");
    const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/localhost.key");

    /// Ensure the pair exists, generating it with `openssl` when it does not.
    ///
    /// Returns false when openssl is unavailable, so the tests that need a real
    /// certificate can skip instead of failing on a machine without it.
    fn ensure_certs() -> bool {
        // Once, for the whole test binary: `cargo test` runs tests in parallel, and
        // the previous version let several of them generate the pair at the same
        // time — one read a half-written key and failed, while the test that owned
        // the generation passed. That made the unit gate order-dependent: a clean
        // checkout failed `cargo test` on 5 TLS tests.
        static ONCE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ONCE.get_or_init(|| {
            if std::path::Path::new(CERT).exists() && std::path::Path::new(KEY).exists() {
                return true;
            }
            let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/gen-test-certs.sh");
            std::process::Command::new("sh")
                .arg(script)
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
    }

    /// `ensure_certs()`, skipping the test (not failing) when openssl is missing.
    fn certs_or_skip() -> bool {
        if ensure_certs() {
            return true;
        }
        eprintln!("skipping: openssl is unavailable and test/certs is empty");
        false
    }

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

    /// A throwaway P-256 pair in three encodings, generated with openssl.
    ///
    /// The key material is deliberately not committed: a private key — even a
    /// self-signed test one — makes a repository unpublishable and asks to be
    /// copied into production. Skipped when openssl is unavailable.
    fn ec_pair() -> Option<(String, String, String)> {
        // Unique per call: tests run in parallel within one process, and a shared
        // directory let one test's certificate pair with another test's key (which
        // rustls correctly rejects as a mismatch).
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("anyhop-tls-ec-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let key = dir.join("k.pem");
        let run = |args: &[&str]| {
            std::process::Command::new("openssl")
                .args(args)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        let key_s = key.to_str()?.to_string();
        if !run(&[
            "ecparam",
            "-genkey",
            "-name",
            "prime256v1",
            "-noout",
            "-out",
            &key_s,
        ]) {
            return None;
        }
        let sec1 = std::fs::read_to_string(&key).ok()?;
        let pkcs8_path = dir.join("k8.pem");
        let pkcs8_s = pkcs8_path.to_str()?.to_string();
        if !run(&[
            "pkcs8", "-topk8", "-nocrypt", "-in", &key_s, "-out", &pkcs8_s,
        ]) {
            return None;
        }
        let pkcs8 = std::fs::read_to_string(&pkcs8_path).ok()?;
        // A self-signed certificate for this key, so the mismatch test has a cert.
        let cert_path = dir.join("c.pem");
        let cert_s = cert_path.to_str()?.to_string();
        // CA:FALSE + SAN=localhost: rustls refuses a CA certificate as a server
        // certificate, and the client connects with ServerName "localhost".
        if !run(&[
            "req",
            "-x509",
            "-new",
            "-key",
            &key_s,
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-out",
            &cert_s,
        ]) {
            return None;
        }
        let cert = std::fs::read_to_string(&cert_path).ok()?;
        let _ = std::fs::remove_dir_all(&dir);
        Some((cert, pkcs8, sec1))
    }

    #[test]
    fn loads_the_generated_localhost_pair() {
        if !ensure_certs() {
            eprintln!("skipping: openssl is unavailable and test/certs is empty");
            return;
        }
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
        if !certs_or_skip() {
            return;
        }
        let missing = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/no-such-file.crt");
        let message = err(TlsConfig::from_pem_files(missing, KEY));
        assert!(message.contains("cannot read tls cert"), "{message}");
        assert!(message.contains(missing), "{message}");
    }

    #[test]
    fn missing_key_file_names_the_path() {
        if !certs_or_skip() {
            return;
        }
        let missing = concat!(env!("CARGO_MANIFEST_DIR"), "/test/certs/no-such-file.key");
        let message = err(TlsConfig::from_pem_files(CERT, missing));
        assert!(message.contains("cannot read tls key"), "{message}");
        assert!(message.contains(missing), "{message}");
    }

    #[test]
    fn file_without_certificate_block_names_the_path() {
        if !certs_or_skip() {
            return;
        }
        let key_pem = ok(std::fs::read_to_string(KEY));
        let certless = TempPem::new("key-as-cert", &key_pem);
        let message = err(TlsConfig::from_pem_files(certless.str(), KEY));
        assert!(message.contains("no CERTIFICATE block"), "{message}");
        assert!(message.contains(certless.str()), "{message}");
    }

    #[test]
    fn file_without_key_block_names_the_path() {
        if !certs_or_skip() {
            return;
        }
        let cert_pem = ok(std::fs::read_to_string(CERT));
        let keyless = TempPem::new("cert-as-key", &cert_pem);
        let message = err(TlsConfig::from_pem_files(CERT, keyless.str()));
        assert!(message.contains("no private key block"), "{message}");
        assert!(message.contains(keyless.str()), "{message}");
    }

    #[test]
    fn garbage_key_reports_the_expected_formats() {
        if !certs_or_skip() {
            return;
        }
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
        if !certs_or_skip() {
            return;
        }
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
        let Some((cert_pem, pkcs8, _)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let cert = TempPem::new("ec-pkcs8-cert", &cert_pem);
        let key = TempPem::new("ec-pkcs8-key", &pkcs8);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn ec_sec1_key_is_accepted() {
        let Some((cert_pem, _, sec1)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let cert = TempPem::new("ec-sec1-cert", &cert_pem);
        let key = TempPem::new("ec-sec1-key", &sec1);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn rsa_pkcs1_key_is_accepted() {
        if !ensure_certs() {
            eprintln!("skipping: openssl is unavailable and test/certs is empty");
            return;
        }
        // Re-encode the generated key as PKCS#1 (`BEGIN RSA PRIVATE KEY`) with
        // openssl rather than committing a copy: a constant would silently stop
        // matching the certificate as soon as the pair is regenerated.
        let tmp = std::env::temp_dir().join(format!("anyhop-tls-{}-pkcs1.key", std::process::id()));
        let converted = std::process::Command::new("openssl")
            .args(["pkey", "-traditional", "-in", KEY, "-out"])
            .arg(&tmp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !converted {
            eprintln!("skipping: openssl cannot convert the key to PKCS#1");
            return;
        }
        let pem = ok(std::fs::read_to_string(&tmp));
        let _ = std::fs::remove_file(&tmp);
        let key = TempPem::new("rsa-pkcs1-key", &pem);
        let tls = ok(TlsConfig::from_pem_files(CERT, key.str()));
        let _acceptor = tls.acceptor();
    }

    #[test]
    fn mismatched_key_is_rejected() {
        if !certs_or_skip() {
            return;
        }
        // EC key against the committed RSA certificate: every parse succeeds,
        // only the public-key comparison can catch this.
        let Some((_, pkcs8, _)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let key = TempPem::new("ec-mismatch", &pkcs8);
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
        let Some((cert_pem, _, _)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let pem = format!("{cert_pem}{cert_pem}");
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

        let Some((cert_pem, pkcs8, _)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let cert = TempPem::new("e2e-cert", &cert_pem);
        let key = TempPem::new("e2e-key", &pkcs8);
        let tls = ok(TlsConfig::from_pem_files(cert.str(), key.str()));

        let listener = ok(tokio::net::TcpListener::bind("127.0.0.1:0").await);
        let addr = ok(listener.local_addr());
        let app = Router::new().route("/", get(|| async { "hello tls" }));
        let server = tokio::spawn(serve(listener, app, tls));

        let mut roots = rustls::RootCertStore::empty();
        let der = ok(pem_blocks(&cert_pem, "CERTIFICATE")).remove(0);
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
        let Some((cert_pem, pkcs8, _)) = ec_pair() else {
            eprintln!("skipping: openssl is unavailable");
            return;
        };
        let pem = format!("{cert_pem}{pkcs8}");
        let certs = ok(pem_blocks(&pem, "CERTIFICATE"));
        let keys = ok(pem_blocks(&pem, "PRIVATE KEY"));
        assert_eq!(certs.len(), 1);
        assert_eq!(keys.len(), 1);
        assert_eq!(ok(pem_blocks(&pem, "NOT A LABEL")).len(), 0);
    }
}
