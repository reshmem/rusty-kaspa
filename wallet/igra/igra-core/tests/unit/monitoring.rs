use igra_core::coordination::monitoring::TransactionMonitor;
use igra_core::rpc::UnimplementedRpc;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn monitor_confirms_after_threshold() {
    let rpc = Arc::new(UnimplementedRpc::new());
    rpc.set_blue_score(10);
    let monitor = TransactionMonitor::new(rpc.clone(), 5, Duration::from_millis(10));

    let task = tokio::spawn(async move { monitor.monitor_until_confirmed(8).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    rpc.set_blue_score(20);

    let result = task.await.expect("join").expect("monitor");
    assert!(result >= 13);
}
