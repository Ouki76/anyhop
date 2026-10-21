//! Dashboard tabs — one module per tab.

pub mod config;
pub mod events;
pub mod keys;
pub mod models;
pub mod overview;
pub mod providers;
pub mod quotas;
pub mod requests;
pub mod settings;

pub use config::ConfigTab;
pub use events::EventsTab;
pub use keys::ApiKeysTab;
pub use models::ModelsTab;
pub use overview::OverviewTab;
pub use providers::ProvidersTab;
pub use quotas::QuotasTab;
pub use requests::RequestsTab;
pub use settings::SettingsTab;
