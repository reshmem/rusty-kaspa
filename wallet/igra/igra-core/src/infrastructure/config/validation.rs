use crate::domain::signing::SigningBackendKind;
use crate::infrastructure::config::types::AppConfig;
use kaspa_addresses::Address;

const MAX_SESSION_TIMEOUT_SECONDS: u64 = 600;

impl AppConfig {
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.service.pskt.sig_op_count == 0 {
            errors.push("pskt.sig_op_count must be > 0".to_string());
        }

        for addr in &self.service.pskt.source_addresses {
            if Address::try_from(addr.as_str()).is_err() {
                errors.push(format!("invalid pskt.source_addresses entry: {}", addr));
            }
        }

        if let Some(change) = self.service.pskt.change_address.as_ref() {
            if Address::try_from(change.as_str()).is_err() {
                errors.push(format!("invalid pskt.change_address: {}", change));
            }
        }

        if let Some(hd) = self.service.hd.as_ref() {
            match hd.key_type {
                crate::infrastructure::config::KeyType::HdMnemonic => {
                    if hd.encrypted_mnemonics.is_none() {
                        errors.push("service.hd.encrypted_mnemonics is required when service.hd.key_type=hd_mnemonic".to_string());
                    }
                }
                crate::infrastructure::config::KeyType::RawPrivateKey => {
                    if self.service.pskt.redeem_script_hex.trim().is_empty() {
                        errors.push("service.pskt.redeem_script_hex is required when service.hd.key_type=raw_private_key".to_string());
                    }
                }
            }
        }

        if let Some(addr) = self.runtime.test_recipient.as_ref() {
            if Address::try_from(addr.as_str()).is_err() {
                errors.push(format!("invalid runtime.test_recipient: {}", addr));
            }
        }
        if self.runtime.session_timeout_seconds == 0 {
            errors.push("runtime.session_timeout_seconds must be > 0".to_string());
        }
        if self.runtime.session_timeout_seconds > MAX_SESSION_TIMEOUT_SECONDS {
            errors.push(format!("runtime.session_timeout_seconds should not exceed {}", MAX_SESSION_TIMEOUT_SECONDS));
        }

        if let Some(group) = self.group.as_ref() {
            if group.threshold_m == 0 || group.threshold_n == 0 {
                errors.push("group.threshold_m and threshold_n must be > 0".to_string());
            }
            if group.threshold_m > group.threshold_n {
                errors.push("group.threshold_m cannot exceed threshold_n".to_string());
            }
            if group.member_pubkeys.is_empty() {
                errors.push("group.member_pubkeys must not be empty".to_string());
            }
            if !group.member_pubkeys.is_empty() && group.member_pubkeys.len() != group.threshold_n as usize {
                errors.push(format!(
                    "group.member_pubkeys count ({}) must match threshold_n ({})",
                    group.member_pubkeys.len(),
                    group.threshold_n
                ));
            }
            if group.session_timeout_seconds == 0 {
                errors.push("group.session_timeout_seconds must be > 0".to_string());
            }
            if group.session_timeout_seconds > MAX_SESSION_TIMEOUT_SECONDS {
                errors.push(format!("group.session_timeout_seconds should not exceed {}", MAX_SESSION_TIMEOUT_SECONDS));
            }

            // Enforce consistency between the configured redeem script and the group membership keys.
            //
            // We currently support Schnorr multisig only, where the redeem script encodes x-only 32-byte pubkeys.
            // If these drift (e.g. ECDSA-vs-Schnorr address mismatch), transactions will fail at runtime with txscript errors.
            let redeem_hex = self.service.pskt.redeem_script_hex.trim();
            if !redeem_hex.is_empty() {
                match hex::decode(redeem_hex) {
                    Ok(redeem) => match extract_schnorr_multisig_pubkeys(&redeem) {
                        Ok((m, n, pubkeys)) => {
                            if group.threshold_m as usize != m || group.threshold_n as usize != n {
                                errors.push(format!(
                                    "group.threshold_m/n ({}/{}) does not match redeem script m/n ({}/{})",
                                    group.threshold_m, group.threshold_n, m, n
                                ));
                            }
                            if group.member_pubkeys != pubkeys {
                                let expected = pubkeys.iter().map(hex::encode).collect::<Vec<_>>();
                                let actual = group.member_pubkeys.iter().map(hex::encode).collect::<Vec<_>>();
                                errors.push(format!(
                                    "group.member_pubkeys must exactly match the x-only pubkeys encoded in service.pskt.redeem_script_hex (expected {:?}, got {:?})",
                                    expected, actual
                                ));
                            }
                        }
                        Err(msg) => errors.push(format!("invalid pskt.redeem_script_hex: {msg}")),
                    },
                    Err(err) => errors.push(format!("invalid pskt.redeem_script_hex: {err}")),
                }
            }
        }

        if let crate::domain::FeePaymentMode::Split { recipient_parts, signer_parts } = self.service.pskt.fee_payment_mode {
            if recipient_parts == 0 && signer_parts == 0 {
                errors.push("pskt.fee_payment_mode split parts must not both be zero".to_string());
            }
        }

        if let (Some(min), Some(max)) = (self.policy.min_amount_sompi, self.policy.max_amount_sompi) {
            if min > max {
                errors.push(format!("policy.min_amount_sompi ({min}) cannot exceed policy.max_amount_sompi ({max})"));
            }
        }

        for entry in &self.layerzero.endpoint_pubkeys {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            match hex::decode(trimmed) {
                Ok(bytes) if bytes.len() == 33 || bytes.len() == 65 => {}
                Ok(_) => errors.push("layerzero.endpoint_pubkeys must be 33 or 65-byte secp256k1 keys".to_string()),
                Err(err) => errors.push(format!("invalid layerzero.endpoint_pubkeys entry: {}", err)),
            }
        }

        if self.signing.backend.parse::<SigningBackendKind>().is_err() {
            errors.push(format!("invalid signing.backend '{}'; valid options: threshold, musig2, mpc", self.signing.backend));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn extract_schnorr_multisig_pubkeys(redeem_script: &[u8]) -> Result<(usize, usize, Vec<Vec<u8>>), String> {
    fn decode_small_int(op: u8) -> Option<usize> {
        match op {
            0x00 => Some(0),
            0x51..=0x60 => Some((op - 0x50) as usize),
            _ => None,
        }
    }

    if redeem_script.len() < 3 {
        return Err("redeem script too short".to_string());
    }

    let mut p = 0usize;
    let m = decode_small_int(redeem_script[p]).ok_or_else(|| "bad multisig redeem script: invalid M opcode".to_string())?;
    p += 1;

    let mut pubkeys = Vec::new();
    while p < redeem_script.len() && redeem_script[p] == 0x20 {
        p += 1;
        if p + 32 > redeem_script.len() {
            return Err("bad multisig redeem script: truncated pubkey push".to_string());
        }
        pubkeys.push(redeem_script[p..p + 32].to_vec());
        p += 32;
    }

    if p >= redeem_script.len() {
        return Err("bad multisig redeem script: missing N opcode".to_string());
    }
    let n = decode_small_int(redeem_script[p]).ok_or_else(|| "bad multisig redeem script: invalid N opcode".to_string())?;
    p += 1;

    if p >= redeem_script.len() || redeem_script[p] != 0xae {
        return Err("bad multisig redeem script: missing OP_CHECKMULTISIG".to_string());
    }

    if n == 0 || m == 0 || m > n {
        return Err(format!("bad multisig redeem script: invalid threshold m={m} n={n}"));
    }
    if pubkeys.len() != n {
        return Err(format!("bad multisig redeem script: pubkey count {} does not match N {n}", pubkeys.len()));
    }

    Ok((m, n, pubkeys))
}
