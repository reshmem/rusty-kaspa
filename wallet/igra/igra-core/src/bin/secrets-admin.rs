use igra_core::foundation::ThresholdError;
use igra_core::infrastructure::keys::{FileSecretStore, SecretBytes, SecretName, SecretStore};
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
    Get { name: String, unsafe_print: bool, encoding: Encoding },
    Set { name: String, value: String, hex: bool, base64: bool },
    Remove { name: String },
}

#[tokio::main]
async fn main() -> Result<(), ThresholdError> {
    let args = parse_args()?;

    match args.cmd {
        Command::Init => {
            let passphrase = resolve_passphrase(args.passphrase)?;
            FileSecretStore::create(&args.path, &passphrase).await?;
            println!("created secrets file path={}", args.path.display());
            Ok(())
        }
        Command::List => {
            let passphrase = resolve_passphrase(args.passphrase)?;
            let store = FileSecretStore::open(&args.path, &passphrase).await?;
            let mut names = store.list_secrets().await?;
            names.sort_by(|a, b| a.as_str().cmp(b.as_str()));
            for name in names {
                println!("{}", name);
            }
            Ok(())
        }
        Command::Get { name, unsafe_print, encoding } => {
            let passphrase = resolve_passphrase(args.passphrase)?;
            let store = FileSecretStore::open(&args.path, &passphrase).await?;
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
            let passphrase = resolve_passphrase(args.passphrase)?;
            let store = FileSecretStore::open_or_create(&args.path, &passphrase).await?;
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
            store.save(&passphrase).await?;
            println!("set secret name={}", secret_name);
            Ok(())
        }
        Command::Remove { name } => {
            let passphrase = resolve_passphrase(args.passphrase)?;
            let store = FileSecretStore::open(&args.path, &passphrase).await?;
            let secret_name = SecretName::new(name);
            store.remove(&secret_name).await?;
            store.save(&passphrase).await?;
            println!("removed secret name={}", secret_name);
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
  remove <name>\n"
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
        let arg = it.next().unwrap_or_default();
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
                let flag = it.next().unwrap_or_default();
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
                let flag = it.next().unwrap_or_default();
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
        other => {
            print_usage();
            return Err(ThresholdError::Message(format!("unknown command: {}", other)));
        }
    };

    Ok(Args { path, passphrase, cmd })
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
    use std::io::{self, Write};

    print!("Enter secrets file passphrase: ");
    io::stdout().flush().map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to flush stdout: {}", e)))?;

    let mut passphrase = String::new();
    io::stdin()
        .read_line(&mut passphrase)
        .map_err(|e| ThresholdError::secret_store_unavailable("file", format!("failed to read passphrase: {}", e)))?;

    Ok(passphrase.trim().to_string())
}
