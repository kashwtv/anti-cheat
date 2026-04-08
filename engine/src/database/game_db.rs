use serde::{Deserialize, Serialize};

/// Represents a known game process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameProcess {
    pub executable_name: String,
    pub game_name: String,
    pub publisher: String,
    pub common_cheat_target: bool,
}

/// In-memory database of known game executables and protected system processes.
#[derive(Debug, Clone)]
pub struct GameDatabase {
    games: Vec<GameProcess>,
    system_processes: Vec<String>,
}

impl GameDatabase {
    /// Initialize the game database with a hardcoded list of known games and system processes.
    pub fn init() -> Self {
        let games = vec![
            // --- Valve / Source / Source 2 ---
            gp("csgo.exe", "Counter-Strike: Global Offensive", "Valve", true),
            gp("cs2.exe", "Counter-Strike 2", "Valve", true),
            gp("dota2.exe", "Dota 2", "Valve", true),
            gp("tf2.exe", "Team Fortress 2", "Valve", true),
            gp("left4dead2.exe", "Left 4 Dead 2", "Valve", false),
            gp("hl2.exe", "Half-Life 2", "Valve", false),
            gp("portal2.exe", "Portal 2", "Valve", false),
            // --- Riot Games ---
            gp("valorant.exe", "Valorant", "Riot Games", true),
            gp("VALORANT-Win64-Shipping.exe", "Valorant (Shipping)", "Riot Games", true),
            gp("league of legends.exe", "League of Legends", "Riot Games", true),
            gp("LeagueClient.exe", "League of Legends Client", "Riot Games", true),
            // --- Epic Games / Fortnite ---
            gp("fortnite.exe", "Fortnite", "Epic Games", true),
            gp("FortniteClient-Win64-Shipping.exe", "Fortnite (Shipping)", "Epic Games", true),
            gp("RocketLeague.exe", "Rocket League", "Psyonix", true),
            // --- Rockstar ---
            gp("gta5.exe", "Grand Theft Auto V", "Rockstar Games", true),
            gp("GTA5.exe", "Grand Theft Auto V", "Rockstar Games", true),
            gp("RDR2.exe", "Red Dead Redemption 2", "Rockstar Games", true),
            gp("PlayGTAV.exe", "Grand Theft Auto V Launcher", "Rockstar Games", true),
            // --- EA / Respawn ---
            gp("r5apex.exe", "Apex Legends", "Respawn Entertainment", true),
            gp("FIFA23.exe", "FIFA 23", "EA Sports", true),
            gp("bf2042.exe", "Battlefield 2042", "DICE", true),
            gp("starwarsbattlefrontii.exe", "Star Wars Battlefront II", "DICE", false),
            // --- Activision / Blizzard ---
            gp("cod.exe", "Call of Duty", "Activision", true),
            gp("ModernWarfare.exe", "Call of Duty: Modern Warfare", "Activision", true),
            gp("BlackOpsColdWar.exe", "Call of Duty: Black Ops Cold War", "Activision", true),
            gp("Warzone.exe", "Call of Duty: Warzone", "Activision", true),
            gp("overwatch.exe", "Overwatch 2", "Blizzard", true),
            gp("Overwatch.exe", "Overwatch 2", "Blizzard", true),
            gp("wow.exe", "World of Warcraft", "Blizzard", false),
            gp("Diablo IV.exe", "Diablo IV", "Blizzard", false),
            gp("destiny2.exe", "Destiny 2", "Bungie", true),
            // --- PUBG ---
            gp("TslGame.exe", "PUBG: Battlegrounds", "Krafton", true),
            gp("PUBG.exe", "PUBG: Battlegrounds", "Krafton", true),
            // --- Battlestate Games ---
            gp("EscapeFromTarkov.exe", "Escape From Tarkov", "Battlestate Games", true),
            // --- Facepunch ---
            gp("rust.exe", "Rust", "Facepunch Studios", true),
            gp("RustClient.exe", "Rust Client", "Facepunch Studios", true),
            // --- Bohemia Interactive ---
            gp("dayz.exe", "DayZ", "Bohemia Interactive", true),
            gp("DayZ_x64.exe", "DayZ (64-bit)", "Bohemia Interactive", true),
            gp("arma3.exe", "Arma 3", "Bohemia Interactive", true),
            gp("arma3_x64.exe", "Arma 3 (64-bit)", "Bohemia Interactive", true),
            // --- Ubisoft ---
            gp("rainbow6.exe", "Rainbow Six Siege", "Ubisoft", true),
            gp("RainbowSix.exe", "Rainbow Six Siege", "Ubisoft", true),
            gp("ACOdyssey.exe", "Assassin's Creed Odyssey", "Ubisoft", false),
            gp("TheDivision2.exe", "The Division 2", "Ubisoft", true),
            // --- Behaviour / Dead by Daylight ---
            gp("deadbydaylight.exe", "Dead by Daylight", "Behaviour Interactive", true),
            gp("DeadByDaylight-Win64-Shipping.exe", "Dead by Daylight (Shipping)", "Behaviour Interactive", true),
            // --- Starbreeze ---
            gp("payday2.exe", "Payday 2", "Starbreeze Studios", true),
            gp("payday3.exe", "Payday 3", "Starbreeze Studios", true),
            // --- Mojang / Microsoft ---
            gp("minecraft.exe", "Minecraft (Bedrock)", "Mojang Studios", false),
            gp("javaw.exe", "Minecraft (Java Edition)", "Mojang Studios", false),
            // --- Roblox ---
            gp("RobloxPlayerBeta.exe", "Roblox", "Roblox Corporation", true),
            gp("RobloxStudioBeta.exe", "Roblox Studio", "Roblox Corporation", false),
            // --- FiveM ---
            gp("FiveM.exe", "FiveM", "Cfx.re", true),
            gp("FiveM_b2802_GTAProcess.exe", "FiveM GTA Process", "Cfx.re", true),
            // --- Misc popular titles ---
            gp("eldenring.exe", "Elden Ring", "FromSoftware", false),
            gp("HuntShowdown.exe", "Hunt: Showdown", "Crytek", true),
            gp("Squad.exe", "Squad", "Offworld Industries", true),
            gp("Insurgency.exe", "Insurgency: Sandstorm", "New World Interactive", true),
            gp("HellLetLoose.exe", "Hell Let Loose", "Team17", true),
        ];

        let system_processes = vec![
            "svchost.exe",
            "explorer.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "services.exe",
            "dwm.exe",
            "smss.exe",
            "wininit.exe",
            "taskhost.exe",
            "taskhostw.exe",
            "RuntimeBroker.exe",
            "SearchIndexer.exe",
            "spoolsv.exe",
            "conhost.exe",
            "dllhost.exe",
            "sihost.exe",
            "fontdrvhost.exe",
            "WmiPrvSE.exe",
            "System",
            "Registry",
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "opera.exe",
            "brave.exe",
            "iexplore.exe",
            "MsMpEng.exe",
            "SecurityHealthService.exe",
            "NisSrv.exe",
            "MpCmdRun.exe",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            games,
            system_processes,
        }
    }

    /// Check whether a given executable name matches a known game process.
    pub fn is_game_process(&self, exe_name: &str) -> Option<&GameProcess> {
        let lower = exe_name.to_lowercase();
        self.games
            .iter()
            .find(|g| g.executable_name.to_lowercase() == lower)
    }

    /// List all known game processes.
    pub fn list_all(&self) -> &[GameProcess] {
        &self.games
    }

    /// Check whether the given executable is a common cheat target.
    pub fn is_cheat_target(&self, exe_name: &str) -> bool {
        self.is_game_process(exe_name)
            .map(|g| g.common_cheat_target)
            .unwrap_or(false)
    }

    /// Check whether the given executable is a protected system process.
    pub fn is_system_process(&self, exe_name: &str) -> bool {
        let lower = exe_name.to_lowercase();
        self.system_processes
            .iter()
            .any(|s| s.to_lowercase() == lower)
    }
}

/// Helper to construct a `GameProcess` entry concisely.
fn gp(exe: &str, name: &str, publisher: &str, cheat_target: bool) -> GameProcess {
    GameProcess {
        executable_name: exe.to_string(),
        game_name: name.to_string(),
        publisher: publisher.to_string(),
        common_cheat_target: cheat_target,
    }
}
