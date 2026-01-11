use igra_core::foundation::SessionId;
use log::debug;
use std::collections::HashSet;

pub type ActiveSessions = tokio::sync::Mutex<HashSet<SessionId>>;

pub async fn mark_session_active(active: &ActiveSessions, session_id: SessionId) -> bool {
    let mut guard = active.lock().await;
    if guard.contains(&session_id) {
        debug!("session already active session_id={}", hex::encode(session_id.as_hash()));
        return false;
    }
    guard.insert(session_id);
    debug!("session marked active session_id={}", hex::encode(session_id.as_hash()));
    true
}

pub async fn clear_session_active(active: &ActiveSessions, session_id: SessionId) {
    let mut guard = active.lock().await;
    guard.remove(&session_id);
    debug!("session cleared active session_id={}", hex::encode(session_id.as_hash()));
}
