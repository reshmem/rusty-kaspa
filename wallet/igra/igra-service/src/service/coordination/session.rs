use igra_core::foundation::SessionId;
use std::collections::HashSet;
use tracing::debug;

pub type ActiveSessions = tokio::sync::Mutex<HashSet<SessionId>>;

pub async fn mark_session_active(active: &ActiveSessions, session_id: SessionId) -> bool {
    let mut guard = active.lock().await;
    if guard.contains(&session_id) {
        debug!(session_id = %hex::encode(session_id.as_hash()), "session already active");
        return false;
    }
    guard.insert(session_id);
    debug!(session_id = %hex::encode(session_id.as_hash()), "session marked active");
    true
}

pub async fn clear_session_active(active: &ActiveSessions, session_id: SessionId) {
    let mut guard = active.lock().await;
    guard.remove(&session_id);
    debug!(session_id = %hex::encode(session_id.as_hash()), "session cleared active");
}
