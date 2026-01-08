use crate::config::types::AppConfig;
use kaspa_addresses::Address;

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

        if let Some(addr) = self.runtime.test_recipient.as_ref() {
            if Address::try_from(addr.as_str()).is_err() {
                errors.push(format!("invalid runtime.test_recipient: {}", addr));
            }
        }
        if self.runtime.session_timeout_seconds == 0 {
            errors.push("runtime.session_timeout_seconds must be > 0".to_string());
        }
        if self.runtime.session_timeout_seconds > 600 {
            errors.push("runtime.session_timeout_seconds should not exceed 600".to_string());
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
            if group.session_timeout_seconds > 600 {
                errors.push("group.session_timeout_seconds should not exceed 600".to_string());
            }
        }

        if let crate::model::FeePaymentMode::Split { recipient_parts, signer_parts } = self.service.pskt.fee_payment_mode {
            if recipient_parts == 0 && signer_parts == 0 {
                errors.push("pskt.fee_payment_mode split parts must not both be zero".to_string());
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

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
