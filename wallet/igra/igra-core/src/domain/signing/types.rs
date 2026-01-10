use crate::foundation::RequestId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PartialSigSubmit {
    pub request_id: RequestId,
    pub input_index: u32,
    pub pubkey: Vec<u8>,
    pub signature: Vec<u8>,
}

