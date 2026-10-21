//! Log formatting.
//!
//! `[server] log_format = "json"` switches to one JSON object per line for log
//! shippers. Implemented as a `FormatEvent` rather than tracing-subscriber's
//! `json` feature so the binary gains no extra dependency.

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// One line per event: `{"ts":<unix>,"level":"INFO","target":"anyhop","message":"…","<field>":…}`.
pub struct JsonFormat;

struct FieldVisitor(serde_json::Map<String, serde_json::Value>);

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::from(format!("{value:?}")),
        );
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::from(value));
    }
}

impl<S, N> FormatEvent<S, N> for JsonFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        let mut fields = FieldVisitor(serde_json::Map::new());
        event.record(&mut fields);

        let mut out = serde_json::Map::new();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        out.insert("ts".into(), serde_json::Value::from(ts.as_secs()));
        out.insert(
            "level".into(),
            serde_json::Value::from(meta.level().as_str()),
        );
        out.insert("target".into(), serde_json::Value::from(meta.target()));
        // `message` is just another field for tracing; hoist it for log pipelines.
        for (k, v) in fields.0 {
            out.insert(k, v);
        }
        writeln!(writer, "{}", serde_json::Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Every line must be valid JSON with the fields a log pipeline indexes on.
    #[test]
    fn events_are_emitted_as_one_json_object_per_line() {
        let buf = Buf::default();
        let subscriber = tracing_subscriber::fmt()
            .event_format(JsonFormat)
            .with_writer(buf.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(provider = "mock", attempt = 2u64, "attempt failed");
        });
        let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        let line = text.lines().next().expect("one line");
        let v: serde_json::Value = serde_json::from_str(line).expect("valid json");
        assert_eq!(v["level"], "INFO");
        assert_eq!(v["message"], "attempt failed");
        assert_eq!(v["provider"], "mock");
        assert_eq!(v["attempt"], 2);
        assert!(v["ts"].as_u64().unwrap_or(0) > 0);
    }
}
