#![no_main]

use igra_core::model::RequestDecision;
use igra_core::state_machine::{is_terminal, validate_transition};
use libfuzzer_sys::fuzz_target;

fn decision_from(byte: u8, reason: &str) -> RequestDecision {
    match byte % 6 {
        0 => RequestDecision::Pending,
        1 => RequestDecision::Approved,
        2 => RequestDecision::Rejected { reason: reason.to_string() },
        3 => RequestDecision::Expired,
        4 => RequestDecision::Finalized,
        _ => RequestDecision::Aborted { reason: reason.to_string() },
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mut iter = data.iter();
    let mut current = decision_from(*iter.next().unwrap_or(&0), "init");
    for (idx, byte) in iter.enumerate() {
        let reason = format!("reason-{idx}");
        let next = decision_from(*byte, &reason);
        let _ = validate_transition(&current, &next);
        let _ = is_terminal(&next);
        current = next;
    }
});
