use crate::foundation::Hash32;

/// Runtime configuration for the Iroh transport.
#[derive(Clone, Debug)]
pub struct IrohConfig {
    pub network_id: u8,
    pub group_id: Hash32,
    /// Bootstrap peers encoded as EndpointId strings.
    pub bootstrap_nodes: Vec<String>,
}
