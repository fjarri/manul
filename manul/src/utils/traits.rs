use alloc::collections::{BTreeMap, BTreeSet};

use crate::protocol::{Artifact, LocalError, Payload};

/// Implemented by collections allowing removal of a specific item.
pub trait Without<T> {
    /// Returns `self` with `item` removed.
    fn without(self, item: &T) -> Self;
}

impl<T: Ord> Without<T> for BTreeSet<T> {
    fn without(self, item: &T) -> Self {
        let mut set = self;
        set.remove(item);
        set
    }
}

impl<K: Ord, V> Without<K> for BTreeMap<K, V> {
    /// Returns `self` with the pair corresponding to the key `item` removed.
    fn without(self, item: &K) -> Self {
        let mut map = self;
        map.remove(item);
        map
    }
}

/// Implemented by map-like collections allowing mapping over values.
pub trait MapValues<OldV, NewV> {
    /// The type of the resulting map.
    type Result;

    /// Map over values of `self`, consuming it and returning the modified collection.
    fn map_values<F>(self, f: F) -> Self::Result
    where
        F: Fn(OldV) -> NewV;
}

/// Implemented by map-like collections allowing mapping over values.
pub trait MapValuesRef<OldV, NewV> {
    /// The type of the resulting map.
    type Result;

    /// Map over values of `self`, returning a new collection.
    fn map_values_ref<F>(&self, f: F) -> Self::Result
    where
        F: Fn(&OldV) -> NewV;
}

impl<K: Ord, OldV, NewV> MapValues<OldV, NewV> for BTreeMap<K, OldV> {
    type Result = BTreeMap<K, NewV>;

    fn map_values<F>(self, f: F) -> Self::Result
    where
        F: Fn(OldV) -> NewV,
    {
        self.into_iter().map(|(key, value)| (key, f(value))).collect()
    }
}

impl<K: Ord + Clone, OldV, NewV> MapValuesRef<OldV, NewV> for BTreeMap<K, OldV> {
    type Result = BTreeMap<K, NewV>;

    fn map_values_ref<F>(&self, f: F) -> Self::Result
    where
        F: Fn(&OldV) -> NewV,
    {
        self.iter().map(|(key, value)| (key.clone(), f(value))).collect()
    }
}

/// Implemented by map-like collections allowing mapping over boxed values downcasting them to concrete types.
pub trait MapDowncast {
    /// The resulting type (parametrized by the concrete type of the value).
    type Result<T>;

    /// Attempt to downcast all the values in the map.
    ///
    /// Returns an error if one of the boxed values is not of the type `T`.
    fn try_map_downcast<T: 'static>(self) -> Result<Self::Result<T>, LocalError>;
}

impl<K: Ord> MapDowncast for BTreeMap<K, Payload> {
    type Result<T> = BTreeMap<K, T>;
    fn try_map_downcast<T: 'static>(self) -> Result<Self::Result<T>, LocalError> {
        self.into_iter()
            .map(|(k, payload)| payload.downcast::<T>().map(|v| (k, v)))
            .collect::<Result<_, _>>()
    }
}

impl<K: Ord> MapDowncast for BTreeMap<K, Artifact> {
    type Result<T> = BTreeMap<K, T>;
    fn try_map_downcast<T: 'static>(self) -> Result<BTreeMap<K, T>, LocalError> {
        self.into_iter()
            .map(|(k, artifact)| artifact.downcast::<T>().map(|v| (k, v)))
            .collect::<Result<_, _>>()
    }
}
