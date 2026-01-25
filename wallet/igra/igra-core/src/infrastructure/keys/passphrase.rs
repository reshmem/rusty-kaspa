use crate::foundation::ThresholdError;

pub fn prompt_hidden_input(prompt: &str) -> Result<String, ThresholdError> {
    #[cfg(target_family = "unix")]
    {
        prompt_hidden_input_unix(prompt)
    }
    #[cfg(not(target_family = "unix"))]
    {
        prompt_visible_input(prompt)
    }
}

#[cfg(not(target_family = "unix"))]
fn prompt_visible_input(prompt: &str) -> Result<String, ThresholdError> {
    use std::io::{self, Write};

    print!("{prompt}");
    io::stdout().flush().map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to flush stdout: {e}")))?;

    read_visible_input()
}

fn read_visible_input() -> Result<String, ThresholdError> {
    use std::io;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to read input: {e}")))?;

    Ok(input.trim().to_string())
}

#[cfg(target_family = "unix")]
fn prompt_hidden_input_unix(prompt: &str) -> Result<String, ThresholdError> {
    use libc::{tcgetattr, tcsetattr, ECHO, STDIN_FILENO, TCSANOW};
    use std::io::{self, Write};
    use std::mem::MaybeUninit;

    struct EchoGuard {
        original: libc::termios,
        active: bool,
    }

    impl Drop for EchoGuard {
        fn drop(&mut self) {
            if self.active {
                unsafe {
                    let rc = tcsetattr(STDIN_FILENO, TCSANOW, &self.original);
                    if rc != 0 {
                        log::warn!("failed to restore terminal echo after hidden input");
                    }
                }
            }
        }
    }

    print!("{prompt}");
    io::stdout().flush().map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to flush stdout: {e}")))?;

    let mut termios = MaybeUninit::<libc::termios>::uninit();
    let rc = unsafe { tcgetattr(STDIN_FILENO, termios.as_mut_ptr()) };
    if rc != 0 {
        return read_visible_input();
    }
    let mut termios = unsafe { termios.assume_init() };
    let original = termios;
    termios.c_lflag &= !ECHO;

    let set_rc = unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &termios) };
    if set_rc != 0 {
        return read_visible_input();
    }

    let _guard = EchoGuard { original, active: true };

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to read input: {e}")))?;

    // Newline was not echoed while ECHO was disabled.
    println!();

    Ok(input.trim().to_string())
}
