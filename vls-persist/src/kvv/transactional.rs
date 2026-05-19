use crate::kvv::{KVVStore, KVV};
use alloc::collections::BTreeMap;
use lightning_signer::persist::{Error, Mutations, SignerId};
use lightning_signer::prelude::*;
use lightning_signer::SendSync;
use log::*;

/// An iterator over a transactional KVVStore range.
pub struct Iter(alloc::vec::IntoIter<KVV>);

impl Iterator for Iter {
    type Item = KVV;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// A KVVStore wrapper that batches writes locally between `enter` and `commit`.
///
/// Outside a transaction it passes writes straight through to the wrapped
/// store, so existing one-off persistence calls keep their current behavior.
pub struct TransactionalKVVStore<L: KVVStore> {
    inner: L,
    commit_log: Mutex<Option<BTreeMap<String, (u64, Vec<u8>)>>>,
}

impl<L: KVVStore> TransactionalKVVStore<L> {
    /// Create a new transactional wrapper around a local KVV store.
    pub fn new(inner: L) -> Self {
        Self { inner, commit_log: Mutex::new(None) }
    }

    fn do_get_version(
        &self,
        commit_log: &BTreeMap<String, (u64, Vec<u8>)>,
        key: &str,
    ) -> Result<Option<u64>, Error> {
        if let Some((version, _)) = commit_log.get(key) {
            Ok(Some(*version))
        } else {
            self.inner.get_version(key)
        }
    }

    fn do_get(
        &self,
        commit_log: &BTreeMap<String, (u64, Vec<u8>)>,
        key: &str,
    ) -> Result<Option<(u64, Vec<u8>)>, Error> {
        if let Some((version, value)) = commit_log.get(key) {
            Ok(Some((*version, value.clone())))
        } else {
            self.inner.get(key)
        }
    }
}

impl<L: KVVStore> SendSync for TransactionalKVVStore<L> {}

impl<L: KVVStore> KVVStore for TransactionalKVVStore<L> {
    type Iter = Iter;

    fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
        let version = self.get_version(key)?.map(|v| v + 1).unwrap_or(0);
        self.put_with_version(key, version, value)
    }

    fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error> {
        let mut commit_log_opt = self.commit_log.lock().unwrap();
        let Some(commit_log) = commit_log_opt.as_mut() else {
            return self.inner.put_with_version(key, version, value);
        };

        let existing = self.do_get(commit_log, key)?;
        if let Some((existing_version, existing_value)) = existing {
            if version < existing_version {
                error!("version mismatch for {}: {} < {}", key, version, existing_version);
                return Err(Error::VersionMismatch);
            } else if version == existing_version {
                if existing_value != value {
                    error!("value mismatch for {}: {}", key, version);
                    return Err(Error::VersionMismatch);
                }
                return Ok(());
            }
        }

        commit_log.insert(key.to_string(), (version, value));
        Ok(())
    }

    fn put_batch(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        let in_transaction = self.commit_log.lock().unwrap().is_some();
        if !in_transaction {
            return self.inner.put_batch(kvvs);
        }

        for kvv in kvvs.into_iter() {
            self.put_with_version(kvv.0.as_str(), kvv.1 .0, kvv.1 .1)?;
        }
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        if let Some(commit_log) = commit_log_opt.as_ref() {
            self.do_get(commit_log, key)
        } else {
            self.inner.get(key)
        }
    }

    fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        if let Some(commit_log) = commit_log_opt.as_ref() {
            self.do_get_version(commit_log, key)
        } else {
            self.inner.get_version(key)
        }
    }

    fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
        let mut result = self
            .inner
            .get_prefix(prefix)?
            .map(KVV::into_inner)
            .collect::<BTreeMap<String, (u64, Vec<u8>)>>();

        let commit_log_opt = self.commit_log.lock().unwrap();
        if let Some(commit_log) = commit_log_opt.as_ref() {
            for (key, version_value) in commit_log.iter() {
                if key.starts_with(prefix) {
                    result.insert(key.clone(), version_value.clone());
                }
            }
        }

        let kvvs = result
            .into_iter()
            .map(|(key, version_value)| KVV(key, version_value))
            .collect::<Vec<_>>();
        Ok(Iter(kvvs.into_iter()))
    }

    fn delete(&self, key: &str) -> Result<(), Error> {
        self.put(key, Vec::new())
    }

    fn clear_database(&self) -> Result<(), Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        if let Some(commit_log) = commit_log_opt.as_ref() {
            assert!(commit_log.is_empty(), "cannot clear database with pending commits");
        }
        self.inner.clear_database()
    }

    fn enter(&self) -> Result<(), Error> {
        let mut commit_log = self.commit_log.lock().unwrap();
        assert!(commit_log.is_none(), "cannot enter transaction twice");
        *commit_log = Some(BTreeMap::new());
        Ok(())
    }

    fn prepare(&self) -> Mutations {
        let commit_log_opt = self.commit_log.lock().unwrap();
        let Some(commit_log) = commit_log_opt.as_ref() else {
            return Mutations::new();
        };

        Mutations::from_vec(
            commit_log
                .iter()
                .map(|(key, (version, value))| (key.clone(), (*version, value.clone())))
                .collect(),
        )
    }

    fn commit(&self) -> Result<(), Error> {
        let mut commit_log_opt = self.commit_log.lock().unwrap();
        let Some(commit_log) = commit_log_opt.take() else {
            return Ok(());
        };

        if commit_log.is_empty() {
            return Ok(());
        }

        let kvvs = commit_log
            .into_iter()
            .map(|(key, (version, value))| KVV(key, (version, value)))
            .collect();
        self.inner.put_batch(kvvs)
    }

    fn put_batch_unlogged(&self, kvvs: Vec<KVV>) -> Result<(), Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        assert!(commit_log_opt.is_none(), "cannot put_batch_unlogged while in transaction");
        drop(commit_log_opt);
        self.inner.put_batch(kvvs)
    }

    fn reset_versions(&self) -> Result<(), Error> {
        let commit_log_opt = self.commit_log.lock().unwrap();
        assert!(commit_log_opt.is_none(), "cannot reset versions while in transaction");
        drop(commit_log_opt);
        self.inner.reset_versions()
    }

    fn signer_id(&self) -> SignerId {
        self.inner.signer_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kvv::memory::MemoryKVVStore;
    use crate::kvv::redb::RedbKVVStore;
    use test_log::test;

    struct FailingBatchStore(MemoryKVVStore);

    impl SendSync for FailingBatchStore {}

    impl KVVStore for FailingBatchStore {
        type Iter = <MemoryKVVStore as KVVStore>::Iter;

        fn put(&self, key: &str, value: Vec<u8>) -> Result<(), Error> {
            self.0.put(key, value)
        }

        fn put_with_version(&self, key: &str, version: u64, value: Vec<u8>) -> Result<(), Error> {
            self.0.put_with_version(key, version, value)
        }

        fn put_batch(&self, _kvvs: Vec<KVV>) -> Result<(), Error> {
            Err(Error::Internal("forced put_batch failure".to_string()))
        }

        fn get(&self, key: &str) -> Result<Option<(u64, Vec<u8>)>, Error> {
            self.0.get(key)
        }

        fn get_version(&self, key: &str) -> Result<Option<u64>, Error> {
            self.0.get_version(key)
        }

        fn get_prefix(&self, prefix: &str) -> Result<Self::Iter, Error> {
            self.0.get_prefix(prefix)
        }

        fn delete(&self, key: &str) -> Result<(), Error> {
            self.0.delete(key)
        }

        fn clear_database(&self) -> Result<(), Error> {
            self.0.clear_database()
        }

        fn reset_versions(&self) -> Result<(), Error> {
            self.0.reset_versions()
        }

        fn signer_id(&self) -> SignerId {
            self.0.signer_id()
        }
    }

    #[test]
    fn test_commit_batches_local_writes() {
        let signer_id = [1u8; 16];
        let store = TransactionalKVVStore::new(MemoryKVVStore::new(signer_id));

        store.enter().unwrap();
        store.put("node/state/1", vec![1]).unwrap();
        store.put("channel/1/1", vec![2]).unwrap();

        assert_eq!(store.get("node/state/1").unwrap().unwrap(), (0, vec![1]));
        assert_eq!(store.get("channel/1/1").unwrap().unwrap(), (0, vec![2]));
        assert_eq!(store.prepare().len(), 2);

        store.commit().unwrap();

        assert_eq!(store.get("node/state/1").unwrap().unwrap(), (0, vec![1]));
        assert_eq!(store.get("channel/1/1").unwrap().unwrap(), (0, vec![2]));
    }

    #[test]
    fn test_get_prefix_merges_pending_mutations() {
        let signer_id = [2u8; 16];
        let store = TransactionalKVVStore::new(MemoryKVVStore::new(signer_id));

        store.put("channel/a/one", vec![1]).unwrap();
        store.enter().unwrap();
        store.put("channel/a/two", vec![2]).unwrap();
        store.put("channel/a/one", vec![3]).unwrap();

        let entries =
            store.get_prefix("channel/a/").unwrap().map(KVV::into_inner).collect::<Vec<_>>();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("channel/a/one".to_string(), (1, vec![3])));
        assert_eq!(entries[1], ("channel/a/two".to_string(), (0, vec![2])));
    }

    #[test]
    fn test_commit_propagates_inner_batch_failure() {
        let signer_id = [3u8; 16];
        let store = TransactionalKVVStore::new(FailingBatchStore(MemoryKVVStore::new(signer_id)));

        store.enter().unwrap();
        store.put("node/state/1", vec![1]).unwrap();

        assert!(matches!(
            store.commit(),
            Err(Error::Internal(message)) if message == "forced put_batch failure"
        ));
    }

    #[test]
    fn test_drop_without_commit_does_not_persist() {
        let tempdir = tempfile::tempdir().unwrap();
        {
            let store = TransactionalKVVStore::new(RedbKVVStore::new(tempdir.path()));
            store.enter().unwrap();
            store.put("node/state/1", vec![1]).unwrap();
            store.put("channel/1/1", vec![2]).unwrap();
            assert_eq!(store.prepare().len(), 2);
        }

        let reopened = RedbKVVStore::new(tempdir.path());
        assert!(reopened.get("node/state/1").unwrap().is_none());
        assert!(reopened.get("channel/1/1").unwrap().is_none());
    }
}
