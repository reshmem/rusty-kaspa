use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::keys::prompt_hidden_input;
use igra_core::infrastructure::keys::{FileSecretStore, SecretBytes, SecretName, SecretStore};
use kaspa_bip32::{Language, Mnemonic};
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
enum Encoding {
    Utf8,
    Hex,
    Base64,
}

struct Args {
    path: PathBuf,
    passphrase: Option<String>,
    cmd: Command,
}

enum Command {
    Init,
    List,
    Get {
        name: String,
        unsafe_print: bool,
        encoding: Encoding,
    },
    Set {
        name: String,
        value: String,
        hex: bool,
        base64: bool,
    },
    Remove {
        name: String,
    },
    RotatePassphrase {
        secrets_file: Option<PathBuf>,
        old_passphrase: Option<String>,
        new_passphrase: Option<String>,
        old_passphrase_file: Option<PathBuf>,
        new_passphrase_file: Option<PathBuf>,
    },
    ImportMnemonic {
        profile: String,
        stdin: bool,
        phrase: Option<String>,
    },
    VerifyMnemonic {
        profile: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), ThresholdError> {
    let Args { path, passphrase, cmd } = parse_args()?;

    match cmd {
        Command::Init => {
            let passphrase = resolve_passphrase(passphrase)?;
            FileSecretStore::create(&path, &passphrase).await?;
            println!("created secrets file path={}", path.display());
            Ok(())
        }
        Command::List => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open(&path, &passphrase).await?;
            let mut names = store.list_secrets().await?;
            names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            for name in names {
                println!("{}", name);
            }
            Ok(())
        }
        Command::Get { name, unsafe_print, encoding } => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open(&path, &passphrase).await?;
            let secret_name = SecretName::new(name);
            let secret = store.get(&secret_name).await?;
            if !unsafe_print {
                println!("{}: [REDACTED {} bytes]", secret_name, secret.len());
                return Ok(());
            }
            match encoding {
                Encoding::Utf8 => {
                    let value = String::from_utf8(secret.expose_owned()).map_err(|err| {
                        ThresholdError::secret_decode_failed(secret_name.to_string(), "utf8", format!("invalid UTF-8: {}", err))
                    })?;
                    println!("{}", value);
                }
                Encoding::Hex => {
                    println!("0x{}", hex::encode(secret.expose_secret()));
                }
                Encoding::Base64 => {
                    use base64::engine::general_purpose::STANDARD;
                    use base64::Engine;
                    println!("{}", STANDARD.encode(secret.expose_secret()));
                }
            }
            Ok(())
        }
        Command::Set { name, value, hex, base64 } => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open_or_create(&path, &passphrase).await?;
            let secret_name = SecretName::new(name);
            let secret = if hex {
                let stripped = value.trim().trim_start_matches("0x");
                let bytes = hex::decode(stripped).map_err(|err| {
                    ThresholdError::secret_decode_failed(secret_name.to_string(), "hex", format!("hex decode failed: {}", err))
                })?;
                SecretBytes::new(bytes)
            } else if base64 {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine;
                let bytes = STANDARD.decode(value.trim()).map_err(|err| {
                    ThresholdError::secret_decode_failed(secret_name.to_string(), "base64", format!("base64 decode failed: {}", err))
                })?;
                SecretBytes::new(bytes)
            } else {
                SecretBytes::new(value.as_bytes().to_vec())
            };

            store.set(secret_name.clone(), secret).await?;
            store.save().await?;
            println!("set secret name={}", secret_name);
            Ok(())
        }
        Command::Remove { name } => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open(&path, &passphrase).await?;
            let secret_name = SecretName::new(name);
            store.remove(&secret_name).await?;
            store.save().await?;
            println!("removed secret name={}", secret_name);
            Ok(())
        }
        Command::RotatePassphrase { secrets_file, old_passphrase, new_passphrase, old_passphrase_file, new_passphrase_file } => {
            let secrets_file = secrets_file.unwrap_or(path);
            let old = resolve_old_passphrase(passphrase, old_passphrase, old_passphrase_file)?;
            let new = resolve_new_passphrase(new_passphrase, new_passphrase_file)?;
            let age_before_days = FileSecretStore::rotate_passphrase(&secrets_file, &old, &new).await?;
            println!("rotated passphrase secrets_file={} age_before_days={}", secrets_file.display(), age_before_days);
            Ok(())
        }
        Command::ImportMnemonic { profile, stdin, phrase } => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open_or_create(&path, &passphrase).await?;
            let profile = profile.trim().to_string();
            igra_core::infrastructure::config::validate_signer_profile(&profile)?;
            let phrase = read_mnemonic_phrase(stdin, phrase)?;
            let _mnemonic = Mnemonic::new(phrase.trim(), Language::English)
                .map_err(|err| ThresholdError::ConfigError(format!("invalid BIP39 mnemonic: {}", err)))?;
            let secret_name = SecretName::new(format!("igra.signer.mnemonic_{}", profile));
            store.set(secret_name.clone(), SecretBytes::new(phrase.as_bytes().to_vec())).await?;
            store.save().await?;
            println!("imported mnemonic profile={} secret_name={} path={}", profile, secret_name, path.display());
            Ok(())
        }
        Command::VerifyMnemonic { profile } => {
            let passphrase = resolve_passphrase(passphrase)?;
            let store = FileSecretStore::open(&path, &passphrase).await?;
            let profile = profile.trim().to_string();
            igra_core::infrastructure::config::validate_signer_profile(&profile)?;
            let secret_name = SecretName::new(format!("igra.signer.mnemonic_{}", profile));
            let secret = store.get(&secret_name).await?;
            let phrase = String::from_utf8(secret.expose_owned()).map_err(|err| {
                ThresholdError::secret_decode_failed(secret_name.to_string(), "utf8", format!("invalid UTF-8: {}", err))
            })?;
            let mnemonic = Mnemonic::new(phrase.trim(), Language::English)
                .map_err(|err| ThresholdError::ConfigError(format!("invalid BIP39 mnemonic: {}", err)))?;
            let word_count = mnemonic.phrase().split_whitespace().count();
            println!("mnemonic OK profile={} words={} secret_name={} path={}", profile, word_count, secret_name, path.display());
            Ok(())
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage:\n\
  secrets-admin [--path PATH] [--passphrase PASS] <command> [command-args]\n\
\n\
Global options:\n\
  --path PATH           Path to secrets file (default: ./secrets.bin)\n\
  --passphrase PASS     Passphrase (otherwise IGRA_SECRETS_PASSPHRASE or prompt)\n\
\n\
Commands:\n\
  init\n\
  list\n\
  get <name> [--unsafe-print] [--encoding hex|utf8|base64]\n\
  set <name> <value> [--hex|--base64]\n\
  remove <name>\n\
  import-mnemonic --profile signer-XX (--stdin | --phrase \"...\")\n\
  verify-mnemonic --profile signer-XX\n\
  rotate-passphrase [--secrets-file PATH] [--old-passphrase PASS|--old-passphrase-file PATH] [--new-passphrase PASS|--new-passphrase-file PATH]\n"
    );
}

fn parse_args() -> Result<Args, ThresholdError> {
    let mut path = PathBuf::from("./secrets.bin");
    let mut passphrase: Option<String> = None;

    let mut it = std::env::args().skip(1).peekable();
    while let Some(arg) = it.peek().cloned() {
        if !arg.starts_with('-') {
            break;
        }
        let arg = it.next().ok_or_else(|| ThresholdError::Message("internal: expected arg".to_string()))?;
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            "--path" => {
                let value = it.next().ok_or_else(|| ThresholdError::Message("--path requires a value".to_string()))?;
                path = PathBuf::from(value);
            }
            "--passphrase" => {
                let value = it.next().ok_or_else(|| ThresholdError::Message("--passphrase requires a value".to_string()))?;
                passphrase = Some(value);
            }
            _ => return Err(ThresholdError::Message(format!("unknown option: {}", arg))),
        }
    }

    let cmd = it.next().ok_or_else(|| {
        print_usage();
        ThresholdError::Message("missing command".to_string())
    })?;

    let cmd = match cmd.as_str() {
        "init" => Command::Init,
        "list" => Command::List,
        "get" => {
            let name = it.next().ok_or_else(|| ThresholdError::Message("get requires <name>".to_string()))?;
            let mut unsafe_print = false;
            let mut encoding = Encoding::Hex;
            while let Some(flag) = it.peek().cloned() {
                if !flag.starts_with('-') {
                    break;
                }
                let flag = it.next().ok_or_else(|| ThresholdError::Message("internal: expected get option".to_string()))?;
                match flag.as_str() {
                    "--unsafe-print" => unsafe_print = true,
                    "--encoding" => {
                        let value = it.next().ok_or_else(|| ThresholdError::Message("--encoding requires a value".to_string()))?;
                        encoding = match value.trim().to_ascii_lowercase().as_str() {
                            "hex" => Encoding::Hex,
                            "utf8" => Encoding::Utf8,
                            "base64" => Encoding::Base64,
                            _ => {
                                return Err(ThresholdError::Message(format!(
                                    "invalid --encoding value: {} (expected hex|utf8|base64)",
                                    value
                                )))
                            }
                        };
                    }
                    _ => return Err(ThresholdError::Message(format!("unknown get option: {}", flag))),
                }
            }
            Command::Get { name, unsafe_print, encoding }
        }
        "set" => {
            let name = it.next().ok_or_else(|| ThresholdError::Message("set requires <name>".to_string()))?;
            let value = it.next().ok_or_else(|| ThresholdError::Message("set requires <value>".to_string()))?;
            let mut hex = false;
            let mut base64 = false;
            while let Some(flag) = it.peek().cloned() {
                if !flag.starts_with('-') {
                    break;
                }
                let flag = it.next().ok_or_else(|| ThresholdError::Message("internal: expected set option".to_string()))?;
                match flag.as_str() {
                    "--hex" => hex = true,
                    "--base64" => base64 = true,
                    _ => return Err(ThresholdError::Message(format!("unknown set option: {}", flag))),
                }
            }
            if hex && base64 {
                return Err(ThresholdError::Message("set: --hex and --base64 are mutually exclusive".to_string()));
            }
            Command::Set { name, value, hex, base64 }
        }
        "remove" => {
            let name = it.next().ok_or_else(|| ThresholdError::Message("remove requires <name>".to_string()))?;
            Command::Remove { name }
        }
        "import-mnemonic" => {
            let mut profile: Option<String> = None;
            let mut stdin = false;
            let mut phrase: Option<String> = None;
            while let Some(flag) = it.peek().cloned() {
                if !flag.starts_with('-') {
                    break;
                }
                let flag =
                    it.next().ok_or_else(|| ThresholdError::Message("internal: expected import-mnemonic option".to_string()))?;
                match flag.as_str() {
                    "--profile" => {
                        let value = it.next().ok_or_else(|| ThresholdError::Message("--profile requires a value".to_string()))?;
                        profile = Some(value);
                    }
                    "--stdin" => stdin = true,
                    "--phrase" => {
                        let value = it.next().ok_or_else(|| ThresholdError::Message("--phrase requires a value".to_string()))?;
                        phrase = Some(value);
                    }
                    _ => return Err(ThresholdError::Message(format!("unknown import-mnemonic option: {}", flag))),
                }
            }
            let profile =
                profile.ok_or_else(|| ThresholdError::Message("import-mnemonic requires --profile signer-XX".to_string()))?;
            Command::ImportMnemonic { profile, stdin, phrase }
        }
        "verify-mnemonic" => {
            let mut profile: Option<String> = None;
            while let Some(flag) = it.peek().cloned() {
                if !flag.starts_with('-') {
                    break;
                }
                let flag =
                    it.next().ok_or_else(|| ThresholdError::Message("internal: expected verify-mnemonic option".to_string()))?;
                match flag.as_str() {
                    "--profile" => {
                        let value = it.next().ok_or_else(|| ThresholdError::Message("--profile requires a value".to_string()))?;
                        profile = Some(value);
                    }
                    _ => return Err(ThresholdError::Message(format!("unknown verify-mnemonic option: {}", flag))),
                }
            }
            let profile =
                profile.ok_or_else(|| ThresholdError::Message("verify-mnemonic requires --profile signer-XX".to_string()))?;
            Command::VerifyMnemonic { profile }
        }
        "rotate-passphrase" => {
            let mut secrets_file: Option<PathBuf> = None;
            let mut old_passphrase: Option<String> = None;
            let mut new_passphrase: Option<String> = None;
            let mut old_passphrase_file: Option<PathBuf> = None;
            let mut new_passphrase_file: Option<PathBuf> = None;

            while let Some(flag) = it.peek().cloned() {
                if !flag.starts_with('-') {
                    break;
                }
                let flag =
                    it.next().ok_or_else(|| ThresholdError::Message("internal: expected rotate-passphrase option".to_string()))?;
                match flag.as_str() {
                    "--secrets-file" | "--path" => {
                        let value = it.next().ok_or_else(|| ThresholdError::Message(format!("{flag} requires a value")))?;
                        secrets_file = Some(PathBuf::from(value));
                    }
                    "--old-passphrase" => {
                        let value =
                            it.next().ok_or_else(|| ThresholdError::Message("--old-passphrase requires a value".to_string()))?;
                        old_passphrase = Some(value);
                    }
                    "--new-passphrase" => {
                        let value =
                            it.next().ok_or_else(|| ThresholdError::Message("--new-passphrase requires a value".to_string()))?;
                        new_passphrase = Some(value);
                    }
                    "--old-passphrase-file" => {
                        let value =
                            it.next().ok_or_else(|| ThresholdError::Message("--old-passphrase-file requires a value".to_string()))?;
                        old_passphrase_file = Some(PathBuf::from(value));
                    }
                    "--new-passphrase-file" => {
                        let value =
                            it.next().ok_or_else(|| ThresholdError::Message("--new-passphrase-file requires a value".to_string()))?;
                        new_passphrase_file = Some(PathBuf::from(value));
                    }
                    _ => return Err(ThresholdError::Message(format!("unknown rotate-passphrase option: {}", flag))),
                }
            }

            Command::RotatePassphrase { secrets_file, old_passphrase, new_passphrase, old_passphrase_file, new_passphrase_file }
        }
        other => {
            print_usage();
            return Err(ThresholdError::Message(format!("unknown command: {}", other)));
        }
    };

    Ok(Args { path, passphrase, cmd })
}

fn read_mnemonic_phrase(stdin: bool, phrase: Option<String>) -> Result<String, ThresholdError> {
    match (stdin, phrase) {
        (true, Some(_)) => Err(ThresholdError::Message("use only one of --stdin or --phrase".to_string())),
        (false, None) => Err(ThresholdError::Message("import-mnemonic requires --stdin or --phrase".to_string())),
        (false, Some(value)) => Ok(value),
        (true, None) => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|err| ThresholdError::Message(format!("failed to read stdin: {}", err)))?;
            let trimmed = buf.trim().to_string();
            if trimmed.is_empty() {
                return Err(ThresholdError::Message("stdin is empty".to_string()));
            }
            Ok(trimmed)
        }
    }
}

fn resolve_passphrase(arg: Option<String>) -> Result<String, ThresholdError> {
    if let Some(pass) = arg {
        let trimmed = pass.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Ok(pass) = std::env::var("IGRA_SECRETS_PASSPHRASE") {
        let trimmed = pass.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    prompt_passphrase()
}

fn prompt_passphrase() -> Result<String, ThresholdError> {
    prompt_hidden_input("Enter secrets file passphrase: ")
}

fn resolve_old_passphrase(
    global_passphrase: Option<String>,
    old_passphrase: Option<String>,
    old_passphrase_file: Option<PathBuf>,
) -> Result<String, ThresholdError> {
    if let Some(pass) = old_passphrase {
        let trimmed = pass.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Some(path) = old_passphrase_file {
        return read_passphrase_file(&path);
    }

    resolve_passphrase(global_passphrase)
}

fn resolve_new_passphrase(new_passphrase: Option<String>, new_passphrase_file: Option<PathBuf>) -> Result<String, ThresholdError> {
    if let Some(pass) = new_passphrase {
        let trimmed = pass.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Some(path) = new_passphrase_file {
        return read_passphrase_file(&path);
    }

    let pass = prompt_hidden_input("Enter new secrets file passphrase: ")?;
    if pass.is_empty() {
        return Err(ThresholdError::Message("new passphrase must not be empty".to_string()));
    }
    let confirm = prompt_hidden_input("Confirm new secrets file passphrase: ")?;
    if pass != confirm {
        return Err(ThresholdError::Message("new passphrase confirmation does not match".to_string()));
    }
    Ok(pass)
}

fn read_passphrase_file(path: &PathBuf) -> Result<String, ThresholdError> {
    let data = std::fs::read_to_string(path).map_err(|e| {
        ThresholdError::secret_store_unavailable("file", format!("failed to read passphrase file {}: {}", path.display(), e))
    })?;
    let trimmed = data.trim().to_string();
    if trimmed.is_empty() {
        return Err(ThresholdError::secret_store_unavailable("file", format!("passphrase file is empty: {}", path.display())));
    }
    Ok(trimmed)
}
