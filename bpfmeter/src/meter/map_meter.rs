use std::{
    collections::HashMap,
    os::fd::{AsFd, AsRawFd},
};

use anyhow::{Result, bail};
use aya::maps::{self, MapType};
use aya_obj::generated::{bpf_attr, bpf_cmd};
use log::error;
use serde_with::serde_as;
use tokio::sync::mpsc::Sender;

use crate::meter::{BpfRawStats, BpfStatsInfo, Meter};

const TARGET_MAP_TYPES: [MapType; 4] = [
    MapType::Hash,
    MapType::PerCpuHash,
    MapType::LruHash,
    MapType::LruPerCpuHash,
];

/// Measures Map usage of the ebpf program
pub struct MapMeter;

/// Serializable Map usage information
#[serde_as]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BpfMapStatsInfo {
    /// Map max size
    #[serde(skip_serializing, skip_deserializing)]
    pub max_size: u32,

    /// Current number of elements in the map
    pub size: u32,
}

impl MapMeter {
    pub fn new() -> Self {
        Self {}
    }
}

impl Meter for MapMeter {
    fn get_id_name_entity_mapping() -> HashMap<u32, String> {
        maps::loaded_maps()
            .filter_map(|p| p.ok())
            .map(|p| (p.id(), p.name_as_str().map(|x| x.to_string()).unwrap()))
            .collect()
    }

    async fn collect_raw_stats(
        map_list_ids: &[u32],
        base_stats: &BpfRawStats,
        tx: Sender<BpfRawStats>,
    ) -> Result<()> {
        let map_iter = maps::loaded_maps();
        for map in map_iter
            .filter_map(|p| p.ok())
            .filter(|p| map_list_ids.is_empty() || map_list_ids.contains(&p.id()))
            .filter(|p| TARGET_MAP_TYPES.contains(&p.map_type().unwrap()))
        {
            let mut attr = unsafe { std::mem::zeroed::<bpf_attr>() };
            let mut next_key = vec![0u8; map.key_size() as usize];
            let mut prev_key = vec![0u8; map.key_size() as usize];

            let u = unsafe { &mut attr.__bindgen_anon_2 };
            let map_fd = map.fd().unwrap();
            let borrowed = map_fd.as_fd();
            u.map_fd = borrowed.as_raw_fd() as u32;

            u.key = 0;
            u.__bindgen_anon_1.next_key = next_key.as_mut_ptr() as u64;

            let mut map_entries = 0;
            while unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    bpf_cmd::BPF_MAP_GET_NEXT_KEY,
                    &mut attr,
                    std::mem::size_of::<bpf_attr>(),
                ) == 0
            } {
                map_entries += 1;
                prev_key.copy_from_slice(&next_key);
                attr.__bindgen_anon_2.key = prev_key.as_mut_ptr() as u64;
            }
            // Check error
            if let Some(error) = std::io::Error::last_os_error().raw_os_error()
                && error != libc::ENOENT
            {
                error!("Failed to get next key: {error}")
            }

            let mut bpf_map_stats = base_stats.clone();
            bpf_map_stats.map_entries = map_entries;
            bpf_map_stats.id = map.id();
            bpf_map_stats.name = map.name_as_str().unwrap_or("unknown").to_string();
            bpf_map_stats.map_max_entries = map.max_entries();

            if let Err(e) = tx.send(bpf_map_stats).await {
                bail!("Failed to send program to channel: {e}");
            }
        }
        Ok(())
    }

    fn generate_stats_info(&mut self, raw_stats: &BpfRawStats) -> Option<BpfStatsInfo> {
        let export_stats = BpfMapStatsInfo {
            max_size: raw_stats.map_max_entries,
            size: raw_stats.map_entries,
        };
        Some(BpfStatsInfo::Map(export_stats))
    }
}
