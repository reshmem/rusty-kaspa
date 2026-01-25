//! CRDT coordination (gossip merge + anti-entropy + signing + submission).

mod broadcast;
mod signing;
mod submission;
mod sync;
mod types;

pub use broadcast::{broadcast_local_state, handle_crdt_broadcast};
pub use sync::{handle_state_sync_request, handle_state_sync_response, run_anti_entropy_loop};
pub use types::CrdtHandlerContext;

pub(crate) use signing::maybe_sign_and_broadcast;
pub(crate) use submission::maybe_submit_and_broadcast;
