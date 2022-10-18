//! Define a type for a set of HasRelayIds objects that can be looked up by any
//! of their keys.

use tor_basic_utils::n_key_set;
use tor_llcrypto::pk::ed25519::Ed25519Identity;
use tor_llcrypto::pk::rsa::RsaIdentity;

use crate::{HasRelayIds, RelayIdRef};

n_key_set! {
    /// A set of objects that can be accessed by relay identity.
    ///
    /// No more than one object in the set can have any given relay identity.
    ///
    /// # Invariants
    ///
    /// Every object in the set MUST have at least one recognized relay
    /// identity; if it does not, it cannot be inserted.
    ///
    /// This set may panic or give incorrect results if the values can change their
    /// keys through interior mutability.
    ///
    #[derive(Clone, Debug)]
    pub struct[H:HasRelayIds] ByRelayIds[H] for H
    {
        (Option) rsa: RsaIdentity { rsa_identity() },
        (Option) ed25519: Ed25519Identity { ed_identity() },
    }
}

impl<H: HasRelayIds> ByRelayIds<H> {
    /// Return the value in this set (if any) that has the key `key`.
    pub fn by_id<'a, T>(&self, key: T) -> Option<&H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.by_rsa(rsa),
        }
    }

    /// Return the value in this set (if any) that has the key `key`.
    pub fn remove_by_id<'a, T>(&mut self, key: T) -> Option<H>
    where
        T: Into<RelayIdRef<'a>>,
    {
        match key.into() {
            RelayIdRef::Ed25519(ed) => self.remove_by_ed25519(ed),
            RelayIdRef::Rsa(rsa) => self.remove_by_rsa(rsa),
        }
    }

    /// Return the value in this set (if any) that has _all_ the relay IDs
    /// that `key` does.
    ///
    /// Return `None` if `key` has no relay IDs.
    pub fn by_all_ids<T>(&self, key: &T) -> Option<&H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        self.by_id(any_id)
            .filter(|val| val.has_all_relay_ids_from(key))
    }

    /// Remove the single value in this set (if any) that has _exactly the same_
    /// relay IDs that `key` does
    pub fn remove_exact<T>(&mut self, key: &T) -> Option<H>
    where
        T: HasRelayIds,
    {
        let any_id = key.identities().next()?;
        if self
            .by_id(any_id)
            .filter(|ent| ent.same_relay_ids(key))
            .is_some()
        {
            self.remove_by_id(any_id)
        } else {
            None
        }
    }

    /// Return a reference to every element in this set that shares _any_ ID
    /// with `key`.
    ///
    /// No element is returned more than once.
    pub fn all_overlapping<T>(&self, key: &T) -> Vec<&H>
    where
        T: HasRelayIds,
    {
        use by_address::ByAddress;
        use std::collections::HashSet;

        let mut items: HashSet<ByAddress<&H>> = HashSet::new();

        for ident in key.identities() {
            if let Some(found) = self.by_id(ident) {
                items.insert(ByAddress(found));
            }
        }

        items.into_iter().map(|by_addr| by_addr.0).collect()
    }
}

// TODO MSRV: Remove this `allow` once we no longer get a false positive
// for it on our MSRV.  1.56 is affected; 1.60 is not.
#[allow(unreachable_pub)]
pub use tor_basic_utils::n_key_set::Error as ByRelayIdsError;

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{RelayIds, RelayIdsBuilder};

    #[test]
    fn lookup() {
        let rsa1: RsaIdentity = (*b"12345678901234567890").into();
        let rsa2: RsaIdentity = (*b"abcefghijklmnopqrstu").into();
        let rsa3: RsaIdentity = (*b"abcefghijklmnopQRSTU").into();
        let ed1: Ed25519Identity = (*b"12345678901234567890123456789012").into();
        let ed2: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyzABCDEFG").into();
        let ed3: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyz1234567").into();

        let keys1 = RelayIdsBuilder::default()
            .rsa_identity(rsa1)
            .ed_identity(ed1)
            .build()
            .unwrap();

        let keys2 = RelayIdsBuilder::default()
            .rsa_identity(rsa2)
            .ed_identity(ed2)
            .build()
            .unwrap();

        let mut set = ByRelayIds::new();
        set.insert(keys1.clone());
        set.insert(keys2.clone());

        // Try by_id
        assert_eq!(set.by_id(&rsa1), Some(&keys1));
        assert_eq!(set.by_id(&ed1), Some(&keys1));
        assert_eq!(set.by_id(&rsa2), Some(&keys2));
        assert_eq!(set.by_id(&ed2), Some(&keys2));
        assert_eq!(set.by_id(&rsa3), None);
        assert_eq!(set.by_id(&ed3), None);

        // Try exact lookup
        assert_eq!(set.by_all_ids(&keys1), Some(&keys1));
        assert_eq!(set.by_all_ids(&keys2), Some(&keys2));
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .build()
                .unwrap();
            assert_eq!(set.by_all_ids(&search), Some(&keys1));
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .ed_identity(ed2)
                .build()
                .unwrap();
            assert_eq!(set.by_all_ids(&search), None);
        }

        // Try looking for overlap
        assert_eq!(set.all_overlapping(&keys1), vec![&keys1]);
        assert_eq!(set.all_overlapping(&keys2), vec![&keys2]);
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa1)
                .ed_identity(ed2)
                .build()
                .unwrap();
            let answer = set.all_overlapping(&search);
            assert_eq!(answer.len(), 2);
            assert!(answer.contains(&&keys1));
            assert!(answer.contains(&&keys2));
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa2)
                .build()
                .unwrap();
            assert_eq!(set.all_overlapping(&search), vec![&keys2]);
        }
        {
            let search = RelayIdsBuilder::default()
                .rsa_identity(rsa3)
                .build()
                .unwrap();
            assert_eq!(set.all_overlapping(&search), Vec::<&RelayIds>::new());
        }
    }

    #[test]
    fn remove_exact() {
        let rsa1: RsaIdentity = (*b"12345678901234567890").into();
        let rsa2: RsaIdentity = (*b"abcefghijklmnopqrstu").into();
        let ed1: Ed25519Identity = (*b"12345678901234567890123456789012").into();
        let ed2: Ed25519Identity = (*b"abcefghijklmnopqrstuvwxyzABCDEFG").into();

        let keys1 = RelayIdsBuilder::default()
            .rsa_identity(rsa1)
            .ed_identity(ed1)
            .build()
            .unwrap();

        let keys2 = RelayIdsBuilder::default()
            .rsa_identity(rsa2)
            .ed_identity(ed2)
            .build()
            .unwrap();

        let mut set = ByRelayIds::new();
        set.insert(keys1.clone());
        set.insert(keys2);
        assert_eq!(set.len(), 2);

        let removed = set.remove_exact(&keys1);
        assert_eq!(removed, Some(keys1));
        assert_eq!(set.len(), 1);

        {
            let search = RelayIdsBuilder::default().ed_identity(ed2).build().unwrap();
            let removed = set.remove_exact(&search);
            assert_eq!(removed, None);
            assert_eq!(set.len(), 1);
        }
    }
}
