use crate::foundation::ThresholdError;
use crate::infrastructure::storage::BatchTransaction;
use crate::storage_err;
use rocksdb::{WriteBatch, DB};

pub(super) struct RocksBatch<'a> {
    pub(super) db: &'a DB,
    pub(super) batch: WriteBatch,
}

impl<'a> BatchTransaction for RocksBatch<'a> {
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), ThresholdError> {
        self.batch.put(key, value);
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), ThresholdError> {
        self.batch.delete(key);
        Ok(())
    }

    fn commit(self: Box<Self>) -> Result<(), ThresholdError> {
        self.db.write(self.batch).map_err(|err| storage_err!("rocksdb", err))
    }

    fn rollback(self: Box<Self>) {
        drop(self);
    }
}
