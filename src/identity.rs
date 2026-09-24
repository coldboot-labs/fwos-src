//! FWOS-local Identity configuration, shared by the UI and Appliance console.
//!
//! This file is deliberately independent of network Desired state. Authentication
//! identifies a source-qualified principal; authorization checks its current
//! administrator grant and the appliance-wide assurance requirement.
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

const IDENTITY: &str = "/var/lib/fwos/identity.json";
const BOOTSTRAPPED: &str = "/var/lib/fwos/bootstrapped";
pub const LOCAL_SOURCE: &str = "local";
static ACCOUNT_WRITE_LOCK: Mutex<()> = Mutex::new(());
// libxcrypt's CRYPT_MAX_PASSPHRASE_SIZE is 512, including the terminating NUL.
pub const MAX_PASSWORD_BYTES: usize = 511;

#[link(name = "crypt")]
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
    fn crypt_gensalt_rn(
        prefix: *const libc::c_char,
        count: libc::c_ulong,
        random: *const libc::c_char,
        random_len: libc::c_int,
        output: *mut libc::c_char,
        output_size: libc::c_int,
    ) -> *mut libc::c_char;
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Principal {
    pub source: String,
    pub subject: String,
    pub username: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    Password,
    MultiFactor,
}

#[derive(Clone)]
pub struct Authentication {
    pub principal: Principal,
    pub assurance: Assurance,
    credential_version: u64,
}

#[derive(Serialize)]
pub struct Challenge {
    pub source: String,
    pub required_assurance: Assurance,
}

pub enum AuthenticationResult {
    Authenticated(Authentication),
    Challenge(Challenge),
    Denied,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    LocalPassword,
}

#[derive(Deserialize, Serialize)]
struct Source {
    id: String,
    kind: SourceKind,
}

#[derive(Deserialize, Serialize)]
struct LocalAccount {
    subject: String,
    source: String,
    username: String,
    password_hash: String,
    credential_version: u64,
    administrator: bool,
}

#[derive(Deserialize, Serialize)]
struct IdentityConfiguration {
    version: u32,
    sources: Vec<Source>,
    required_assurance: Assurance,
    accounts: Vec<LocalAccount>,
}

impl IdentityConfiguration {
    fn read() -> Result<Self, String> {
        let raw =
            fs::read(IDENTITY).map_err(|_| "Identity configuration unavailable".to_string())?;
        let config: Self = serde_json::from_slice(&raw)
            .map_err(|_| "Identity configuration invalid".to_string())?;
        if config.version != 1 {
            return Err("unsupported Identity configuration version".into());
        }
        let mut source_ids = std::collections::HashSet::new();
        if config
            .sources
            .iter()
            .any(|source| source.id.is_empty() || !source_ids.insert(source.id.as_str()))
        {
            return Err("invalid Authentication sources".into());
        }
        let mut subjects = std::collections::HashSet::new();
        let mut usernames = std::collections::HashSet::new();
        for account in &config.accounts {
            if !source_ids.contains(account.source.as_str())
                || account.subject.is_empty()
                || !valid_username(&account.username)
                || account.credential_version == 0
                || !account.password_hash.starts_with("$y$")
                || !subjects.insert((&account.source, &account.subject))
                || !usernames.insert((&account.source, &account.username))
            {
                return Err("invalid local accounts".into());
            }
        }
        Ok(config)
    }
}

/// Only Bootstrap may replace tentative identity. Completed ownership always
/// requires explicit authenticated account operations, never this function.
pub fn create_first_administrator(username: &str, password: &str) -> Result<(), String> {
    if Path::new(BOOTSTRAPPED).exists() {
        return Err("already bootstrapped".into());
    }
    if !valid_username(username) || !valid_password(password) {
        return Err("invalid administrator credentials".into());
    }
    let config = IdentityConfiguration {
        version: 1,
        sources: vec![Source {
            id: LOCAL_SOURCE.into(),
            kind: SourceKind::LocalPassword,
        }],
        required_assurance: Assurance::Password,
        accounts: vec![LocalAccount {
            source: LOCAL_SOURCE.into(),
            subject: random_token()?,
            username: username.into(),
            password_hash: hash_password(password)?,
            credential_version: 1,
            administrator: true,
        }],
    };
    write_configuration(&config)
}

/// A Bootstrap commit requires the tentative local administrator to be
/// readable and authorized as an administrator before ownership is recorded.
pub fn tentative_first_administrator_exists() -> bool {
    IdentityConfiguration::read().is_ok_and(|configuration| {
        configuration
            .accounts
            .iter()
            .any(|account| account.source == LOCAL_SOURCE && account.administrator)
    })
}

fn write_configuration(config: &IdentityConfiguration) -> Result<(), String> {
    let raw = serde_json::to_vec(config).map_err(|_| "encode Identity configuration")?;
    let parent = Path::new(IDENTITY).parent().ok_or("Identity directory")?;
    fs::create_dir_all(parent).map_err(|_| "create Identity directory")?;
    let temporary = parent.join(format!(".identity-{}.tmp", random_token()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| "create Identity configuration")?;
        file.write_all(&raw)
            .map_err(|_| "write Identity configuration")?;
        file.sync_all()
            .map_err(|_| "persist Identity configuration")?;
        fs::rename(&temporary, IDENTITY).map_err(|_| "publish Identity configuration")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "persist Identity directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn authenticate(source: &str, username: &str, password: &str) -> AuthenticationResult {
    // Tentative credentials are not appliance ownership.
    if !Path::new(BOOTSTRAPPED).exists() || !valid_password(password) {
        return AuthenticationResult::Denied;
    }
    let Ok(config) = IdentityConfiguration::read() else {
        return AuthenticationResult::Denied;
    };
    let Some(provider) = config.sources.iter().find(|provider| provider.id == source) else {
        return AuthenticationResult::Denied;
    };
    let account = match provider.kind {
        SourceKind::LocalPassword => config
            .accounts
            .iter()
            .find(|account| account.source == source && account.username == username),
    };
    // Missing usernames still perform the same yescrypt verification work.
    // Initialize this on both paths so the first request is not distinguishable.
    // This hash is not an account and can never grant authentication.
    static UNKNOWN_ACCOUNT_HASH: OnceLock<Result<String, String>> = OnceLock::new();
    let dummy = match UNKNOWN_ACCOUNT_HASH.get_or_init(|| hash_password("FWOS unmapped identity")) {
        Ok(hash) => hash,
        Err(_) => return AuthenticationResult::Denied,
    };
    let expected = account
        .map(|account| account.password_hash.as_str())
        .unwrap_or(dummy);
    let Ok(candidate) = crypt_password(password, expected) else {
        return AuthenticationResult::Denied;
    };
    if !eq_ct(candidate.as_bytes(), expected.as_bytes()) {
        return AuthenticationResult::Denied;
    }
    let Some(account) = account else {
        return AuthenticationResult::Denied;
    };
    // No second-factor implementation ships in v1. A stronger configured
    // requirement must fail closed instead of being bypassed via this source.
    if config.required_assurance > Assurance::Password {
        return AuthenticationResult::Challenge(Challenge {
            source: source.into(),
            required_assurance: config.required_assurance,
        });
    }
    AuthenticationResult::Authenticated(Authentication {
        principal: Principal {
            source: source.into(),
            subject: account.subject.clone(),
            username: account.username.clone(),
        },
        assurance: Assurance::Password,
        credential_version: account.credential_version,
    })
}

/// Re-check current grants on each operation. Removing an account, changing its
/// credentials, or raising assurance requirements invalidates prior sessions.
pub fn authorize_administrator(authentication: &Authentication) -> bool {
    if !Path::new(BOOTSTRAPPED).exists() {
        return false;
    }
    let Ok(config) = IdentityConfiguration::read() else {
        return false;
    };
    authorized_in(&config, authentication)
}

fn authorized_in(config: &IdentityConfiguration, authentication: &Authentication) -> bool {
    authentication.assurance >= config.required_assurance
        && config
            .sources
            .iter()
            .any(|source| source.id == authentication.principal.source)
        && config.accounts.iter().any(|account| {
            account.source == authentication.principal.source
                && account.subject == authentication.principal.subject
                && account.username == authentication.principal.username
                && account.credential_version == authentication.credential_version
                && account.administrator
        })
}

#[derive(Debug)]
pub enum AccountError {
    Forbidden,
    InvalidCredentials,
    AlreadyExists,
    NotFound,
    LastAdministrator,
    Storage,
}

pub fn list_local_administrators(
    authentication: &Authentication,
) -> Result<Vec<String>, AccountError> {
    if !Path::new(BOOTSTRAPPED).exists() {
        return Err(AccountError::Forbidden);
    }
    let config = IdentityConfiguration::read().map_err(|_| AccountError::Storage)?;
    if !authorized_in(&config, authentication) {
        return Err(AccountError::Forbidden);
    }
    let mut names: Vec<_> = config
        .accounts
        .iter()
        .filter(|account| account.source == LOCAL_SOURCE && account.administrator)
        .map(|account| account.username.clone())
        .collect();
    names.sort();
    Ok(names)
}

pub fn create_local_administrator(
    authentication: &Authentication,
    username: &str,
    password: &str,
) -> Result<(), AccountError> {
    if !valid_username(username) || !valid_password(password) {
        return Err(AccountError::InvalidCredentials);
    }
    let _guard = ACCOUNT_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !Path::new(BOOTSTRAPPED).exists() {
        return Err(AccountError::Forbidden);
    }
    let mut config = IdentityConfiguration::read().map_err(|_| AccountError::Storage)?;
    if !authorized_in(&config, authentication) {
        return Err(AccountError::Forbidden);
    }
    if !config
        .sources
        .iter()
        .any(|source| source.id == LOCAL_SOURCE && matches!(source.kind, SourceKind::LocalPassword))
    {
        return Err(AccountError::Storage);
    }
    if config
        .accounts
        .iter()
        .any(|account| account.source == LOCAL_SOURCE && account.username == username)
    {
        return Err(AccountError::AlreadyExists);
    }
    config.accounts.push(LocalAccount {
        source: LOCAL_SOURCE.into(),
        subject: random_token().map_err(|_| AccountError::Storage)?,
        username: username.into(),
        password_hash: hash_password(password).map_err(|_| AccountError::Storage)?,
        credential_version: 1,
        administrator: true,
    });
    write_configuration(&config).map_err(|_| AccountError::Storage)
}

pub fn change_local_administrator_password(
    authentication: &Authentication,
    username: &str,
    password: &str,
) -> Result<(), AccountError> {
    if !valid_password(password) {
        return Err(AccountError::InvalidCredentials);
    }
    let _guard = ACCOUNT_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !Path::new(BOOTSTRAPPED).exists() {
        return Err(AccountError::Forbidden);
    }
    let mut config = IdentityConfiguration::read().map_err(|_| AccountError::Storage)?;
    if !authorized_in(&config, authentication) {
        return Err(AccountError::Forbidden);
    }
    let Some(account) = config.accounts.iter_mut().find(|account| {
        account.source == LOCAL_SOURCE && account.username == username && account.administrator
    }) else {
        return Err(AccountError::NotFound);
    };
    let next_version = account
        .credential_version
        .checked_add(1)
        .ok_or(AccountError::Storage)?;
    account.password_hash = hash_password(password).map_err(|_| AccountError::Storage)?;
    account.credential_version = next_version;
    write_configuration(&config).map_err(|_| AccountError::Storage)
}

pub fn remove_local_administrator(
    authentication: &Authentication,
    username: &str,
) -> Result<(), AccountError> {
    let _guard = ACCOUNT_WRITE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !Path::new(BOOTSTRAPPED).exists() {
        return Err(AccountError::Forbidden);
    }
    let mut config = IdentityConfiguration::read().map_err(|_| AccountError::Storage)?;
    if !authorized_in(&config, authentication) {
        return Err(AccountError::Forbidden);
    }
    let Some(index) = config.accounts.iter().position(|account| {
        account.source == LOCAL_SOURCE && account.username == username && account.administrator
    }) else {
        return Err(AccountError::NotFound);
    };
    if config
        .accounts
        .iter()
        .filter(|account| account.source == LOCAL_SOURCE && account.administrator)
        .count()
        <= 1
    {
        return Err(AccountError::LastAdministrator);
    }
    config.accounts.remove(index);
    write_configuration(&config).map_err(|_| AccountError::Storage)
}

pub fn valid_username(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == '_')
        && name.len() <= 32
        && name != "root"
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Accept the same credential through HTTPS and the line-oriented console.
/// ASCII controls are terminal input commands, not usable password characters.
pub fn valid_password(password: &str) -> bool {
    !password.is_empty()
        && password.len() <= MAX_PASSWORD_BYTES
        && !password.bytes().any(|byte| byte.is_ascii_control())
}

pub fn random_token() -> Result<String, String> {
    let mut random = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| "secure randomness unavailable")?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn hash_password(password: &str) -> Result<String, String> {
    let prefix = CString::new("$y$").map_err(|_| "password hash prefix")?;
    let mut setting = [0 as libc::c_char; 192];
    // libxcrypt obtains the salt from OS randomness when rbytes is NULL.
    let generated = unsafe {
        crypt_gensalt_rn(
            prefix.as_ptr(),
            0,
            std::ptr::null(),
            0,
            setting.as_mut_ptr(),
            192,
        )
    };
    if generated.is_null() {
        return Err("generate password salt".into());
    }
    let setting = unsafe { CStr::from_ptr(generated) }.to_string_lossy();
    crypt_password(password, &setting)
}

fn crypt_password(password: &str, setting: &str) -> Result<String, String> {
    let password = CString::new(password).map_err(|_| "invalid password")?;
    let setting = CString::new(setting).map_err(|_| "invalid password hash")?;
    // crypt uses a process-wide output buffer. Copy it while holding this lock.
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let result = unsafe { crypt(password.as_ptr(), setting.as_ptr()) };
    if result.is_null() {
        return Err("password hashing failed".into());
    }
    let encoded = unsafe { CStr::from_ptr(result) }
        .to_string_lossy()
        .into_owned();
    if !encoded.starts_with("$y$") {
        return Err("password hashing failed".into());
    }
    Ok(encoded)
}

fn eq_ct(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.iter().zip(b) {
        difference |= left ^ right;
    }
    difference == 0
}

// Retained from the previous console password verifier as it moves to the
// shared module. New acceptance tests use the real appliance boundary.
#[cfg(test)]
mod tests {
    use super::eq_ct;

    #[test]
    fn eq_ct_matches_only_same_bytes() {
        assert!(eq_ct(b"abc", b"abc"));
        assert!(!eq_ct(b"abc", b"abd"));
        assert!(!eq_ct(b"ab", b"abc"));
    }
}
