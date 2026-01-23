//! Panic-safe secret cleanup.

use zeroize::Zeroize;

pub struct SecretPanicGuard<T: Zeroize> {
    secret: Option<T>,
}

impl<T: Zeroize> SecretPanicGuard<T> {
    pub fn new(secret: T) -> Self {
        Self { secret: Some(secret) }
    }

    pub fn get(&self) -> &T {
        self.secret.as_ref().expect("secret already taken")
    }

    pub fn take(&mut self) -> T {
        self.secret.take().expect("secret already taken")
    }
}

impl<T: Zeroize> Drop for SecretPanicGuard<T> {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.secret {
            secret.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_guard_take() {
        let data = vec![0x42u8; 32];
        let mut guard = SecretPanicGuard::new(data);
        let taken = guard.take();
        assert_eq!(taken.len(), 32);
    }

    #[test]
    #[should_panic(expected = "secret already taken")]
    fn test_panic_guard_double_take() {
        let data = vec![0x42u8; 32];
        let mut guard = SecretPanicGuard::new(data);
        let _first = guard.take();
        let _second = guard.take();
    }
}
