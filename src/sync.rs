use crate::map::{AttosMap, OpenConfig};
use crate::error::AttosError;
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::path::Path;

/// The Client manages lock-free hot-swapping of the AttosMap.
pub struct AttosClient {
    current_map: Arc<ArcSwap<AttosMap>>,
    config: OpenConfig,
}

impl AttosClient {
    /// Initializes the sync engine with an initial map.
    pub fn new(initial_map: AttosMap, config: OpenConfig) -> Self {
        let current_map = Arc::new(ArcSwap::from_pointee(initial_map));
        Self { current_map, config }
    }

    /// Gets a lock-free reference to the current AttosMap.
    /// This resolves in ~1ns and allows zero-allocation lookups.
    #[inline(always)]
    pub fn read(&self) -> arc_swap::Guard<Arc<AttosMap>> {
        self.current_map.load()
    }

    /// Reloads the map from a new file path and hot-swaps it.
    /// The old map will be dropped once all active readers release their guards.
    pub fn reload<P: AsRef<Path>>(&self, path: P) -> Result<(), AttosError> {
        let new_map = AttosMap::open_with_config(path, self.config)?;
        self.current_map.store(Arc::new(new_map));
        Ok(())
    }
}
