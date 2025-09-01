use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use tokio::sync::mpsc::Sender;

use crate::meter::{cpu_meter::BpfCPUStatsInfo, map_meter::BpfMapStatsInfo};

pub mod cpu_meter;
pub mod map_meter;

/// Stores ebpf program/map stats
#[derive(Debug, Clone, Default)]
pub struct BpfRawStats {
    /// Ebpf program/map id
    pub id: u32,
    /// Ebpf program/map name
    pub name: String,
    /// Tick number
    pub tick: u64,
    /// Time the program/map stats were received
    pub time_recieved: Duration,

    /// Number of times the program was run before the current tick
    pub run_count: u64,
    /// Time the program was run before the current tick
    pub run_time: Duration,

    /// Map current size
    pub map_entries: u32,
    /// Map max size
    pub map_max_entries: u32,
}

#[derive(Clone, Debug)]
pub struct BpfInfo<'a> {
    /// Ebpf map id
    pub id: u32,
    /// Ebpf map name
    pub name: &'a str,
    /// Measurement number
    #[allow(dead_code)]
    pub tick: u64,

    pub stats: BpfStatsInfo,
}

/// Contains information about ebpf program/map stats to be exported in table format
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum BpfStatsInfo {
    Cpu(BpfCPUStatsInfo),
    Map(BpfMapStatsInfo),
}

/// Trait for measuring ebpf program/map stats
pub trait Meter {
    /// Returns a mapping of ebpf program/map id to name
    fn get_id_name_entity_mapping() -> HashMap<u32, String>;

    /// Asynchronously collects ebpf program/map stats and sends it to the channel
    ///
    /// # Arguments
    ///
    /// * `prog_list_ids` - List of ebpf program/map ids to collect stats for.
    ///   If empty, all programs/maps are collected.
    ///
    /// * `base_stats` - Base stats with additional information
    ///
    /// * `tx` - Channel to send stats to
    fn collect_raw_stats(
        prog_list_ids: &[u32],
        base_raw_stats: &BpfRawStats,
        tx: Sender<BpfRawStats>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Generates BpfStatsInfo from BpfRawStats that can be serialized
    ///
    /// # Arguments
    ///
    /// * `raw_stats` - BpfRawStats to generate BpfStatsInfo from
    fn generate_stats_info(&mut self, raw_stats: &BpfRawStats) -> Option<BpfStatsInfo>;
}
