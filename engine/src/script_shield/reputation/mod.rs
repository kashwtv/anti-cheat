//! Reputation database for URLs and domains used by Script Shield.
//!
//! Contains a built-in list of known-good and known-bad domains, plus a URL
//! risk scorer that combines domain reputation with structural analysis of the
//! URL itself.

pub mod domain_db;
pub mod url_risk;

pub use domain_db::{DomainCategory, DomainReputation, ReputationDb};
pub use url_risk::{UrlRiskScorer, UrlRiskFactor, UrlVerdict};
