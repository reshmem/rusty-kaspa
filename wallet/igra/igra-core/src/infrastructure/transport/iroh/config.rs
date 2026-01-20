use crate::foundation::GroupId;

/// Runtime configuration for the Iroh transport.
#[derive(Clone, Debug)]
pub struct IrohConfig {
    pub network_id: u8,
    pub group_id: GroupId,
    /// Bootstrap peers encoded as EndpointId strings.
    pub bootstrap_nodes: Vec<String>,
}
