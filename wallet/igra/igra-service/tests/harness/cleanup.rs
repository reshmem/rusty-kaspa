use std::env;
use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, OnceLock};

pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().expect("env lock")
}

pub struct ScopedEnvVar {
    key: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    pub fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let _guard = env_lock();
        let previous = env::var_os(key);
        env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        let _guard = env_lock();
        match self.previous.take() {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}

pub fn iroh_bind_tests_enabled() -> bool {
    matches!(env::var("IGRA_TEST_IROH_BIND").as_deref(), Ok("1"))
}
