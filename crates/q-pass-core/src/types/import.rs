use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ImportFormat {
    Csv = 0,
    OnePassword = 1,
    Bitwarden = 2,
    LastPass = 3,
    Dashlane = 4,
    KeePass = 5,
    Chrome = 6,
    Firefox = 7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub url: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub folder: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    pub format: u8,
    pub total_records: u32,
    pub imported: u32,
    pub skipped: u32,
    pub errors: Vec<String>,
}
