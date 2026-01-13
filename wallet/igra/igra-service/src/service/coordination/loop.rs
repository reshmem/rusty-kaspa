use crate::service::coordination::crdt_handler::{
    handle_crdt_broadcast, handle_state_sync_request, handle_state_sync_response, run_anti_entropy_loop,
};
use crate::service::flow::ServiceFlow;
use igra_core::foundation::{day_start_nanos, now_nanos, Hash32, PeerId, ThresholdError};
use igra_core::infrastructure::storage::Storage;
use igra_core::infrastructure::transport::iroh::traits::{Transport, TransportMessage};
use log::{debug, info, warn};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn run_coordination_loop(
    app_config: Arc<igra_core::infrastructure::config::AppConfig>,
    flow: Arc<ServiceFlow>,
    transport: Arc<dyn Transport>,
    storage: Arc<dyn Storage>,
    local_peer_id: PeerId,
    group_id: Hash32,
) -> Result<(), ThresholdError> {
    let mut subscription = transport.subscribe_group(group_id).await?;

    info!(
        "coordination loop started (CRDT) group_id={} peer_id={} network_id={} session_timeout_secs={} session_expiry_secs={:?} sig_op_count={} data_dir_set={} bootstrap_addr_count={}",
        hex::encode(group_id),
        local_peer_id,
        app_config.iroh.network_id,
        app_config.runtime.session_timeout_seconds,
        app_config.runtime.session_expiry_seconds,
        app_config.service.pskt.sig_op_count,
        !app_config.service.data_dir.trim().is_empty(),
        app_config.iroh.bootstrap_addrs.len()
    );

    struct AbortOnDrop(tokio::task::JoinHandle<()>);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let anti_entropy = tokio::spawn(run_anti_entropy_loop(storage.clone(), transport.clone(), local_peer_id.clone(), 5));
    let _anti_entropy_guard = AbortOnDrop(anti_entropy);

    let gc_interval_secs = app_config.runtime.crdt_gc_interval_seconds.unwrap_or(600);
    let gc_ttl_secs = app_config.runtime.crdt_gc_ttl_seconds.unwrap_or(24 * 60 * 60);
    let _gc_guard = if gc_interval_secs > 0 && gc_ttl_secs > 0 {
        let storage_for_gc = storage.clone();
        let metrics_for_gc = flow.metrics();
        let gc_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(gc_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = now_nanos();
                let cutoff_by_ttl = now.saturating_sub(gc_ttl_secs.saturating_mul(1_000_000_000));
                // Always keep current-day completions to preserve daily-volume enforcement accuracy.
                let floor = day_start_nanos(now);
                let cutoff = cutoff_by_ttl.min(floor);

                match storage_for_gc.cleanup_completed_event_crdts(cutoff) {
                    Ok(deleted) => {
                        if deleted > 0 {
                            info!("CRDT GC deleted completed states deleted={} cutoff_nanos={}", deleted, cutoff);
                            metrics_for_gc.inc_crdt_gc_deleted_total(deleted as u64);
                        }
                        if let Ok(stats) = storage_for_gc.crdt_storage_stats() {
                            metrics_for_gc.set_crdt_storage_stats(stats);
                        }
                    }
                    Err(err) => warn!("CRDT GC failed error={}", err),
                }
            }
        });
        Some(AbortOnDrop(gc_handle))
    } else {
        None
    };

    let mut last_activity = Instant::now();
    let mut idle_ticker = tokio::time::interval(Duration::from_secs(60));
    idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = idle_ticker.tick() => {
                let idle = last_activity.elapsed();
                if idle >= Duration::from_secs(60) {
                    info!(
                        "service idle, waiting for CRDT messages idle_seconds={} group_id_prefix={} peer_id={}",
                        idle.as_secs(),
                        hex::encode(&group_id[..8]),
                        local_peer_id
                    );
                }
            }
            item = subscription.next() => {
                let Some(item) = item else { break; };
                let envelope = match item {
                    Ok(envelope) => {
                        last_activity = Instant::now();
                        envelope
                    }
                    Err(err) => {
                        warn!("group stream error error={}", err);
                        continue;
                    }
                };

                debug!(
                    "group message received sender_peer_id={} seq_no={}",
                    envelope.sender_peer_id,
                    envelope.seq_no
                );

                match envelope.payload {
                    TransportMessage::EventStateBroadcast(broadcast) => {
                        if let Err(err) = handle_crdt_broadcast(
                            &app_config,
                            &flow,
                            &transport,
                            &storage,
                            &local_peer_id,
                            broadcast,
                        ).await {
                            warn!("CRDT handler error error={}", err);
                        }
                    }
                    TransportMessage::StateSyncRequest(req) => {
                        if let Err(err) = handle_state_sync_request(&transport, &storage, &local_peer_id, req).await {
                            warn!("state sync request handler error error={}", err);
                        }
                    }
                    TransportMessage::StateSyncResponse(resp) => {
                        if let Err(err) = handle_state_sync_response(
                            &app_config,
                            &flow,
                            &transport,
                            &storage,
                            &local_peer_id,
                            resp,
                        )
                        .await
                        {
                            warn!("state sync response handler error error={}", err);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
