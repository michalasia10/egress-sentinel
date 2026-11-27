//! Safe decision metadata persistence.

mod store;

pub use store::{AuditError, SqliteAuditStore};
