pub mod game_db;
pub mod hash_db;
pub mod reputation;
pub mod whitelist;

pub use game_db::{GameDatabase, GameProcess};
pub use hash_db::{HashDatabase, ThreatEntry};
pub use reputation::{ReputationDatabase, SourceReputation};
pub use whitelist::{AddedBy, TrustLevel, WhitelistCategory, WhitelistDatabase, WhitelistEntry};

use std::path::Path;

use anyhow::Result;
use tracing::info;

/// Manages all database subsystems.
pub struct DatabaseManager {
    pub hash_db: HashDatabase,
    pub whitelist_db: WhitelistDatabase,
    pub game_db: GameDatabase,
    pub reputation_db: ReputationDatabase,
}

impl DatabaseManager {
    /// Initialize all databases in the given data directory.
    pub fn init(data_dir: impl AsRef<Path>) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        std::fs::create_dir_all(data_dir)?;

        let hash_db = HashDatabase::init(data_dir.join("hashes.db"))?;
        let whitelist_db = WhitelistDatabase::init(data_dir.join("whitelist.db"))?;
        let game_db = GameDatabase::init();
        let reputation_db = ReputationDatabase::init(data_dir.join("reputation.db"))?;

        info!("all databases initialized");
        Ok(Self {
            hash_db,
            whitelist_db,
            game_db,
            reputation_db,
        })
    }
}
