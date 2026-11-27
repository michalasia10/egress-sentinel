//! Safe decision metadata persistence.

mod record;
mod store;

pub use record::{AuditError, DecisionAuditRecord};
pub use store::SqliteAuditStore;
