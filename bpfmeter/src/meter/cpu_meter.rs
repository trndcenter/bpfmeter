use std::{collections::HashMap, ops::Sub, time::Duration};

use anyhow::{Result, bail};
use aya::programs;
use log::warn;
use serde_with::DurationSecondsWithFrac;
use serde_with::serde_as;
use tokio::sync::mpsc::Sender;

use crate::{
    meter::BpfStatsInfo,
    meter::{BpfRawStats, Meter},
};

/// Measures CPU usage of the ebpf program
pub struct CpuMeter {
    /// Map of bpf program ids to previous BpfRawStats to calculate cpu usage
    bpf_prog_info_map: HashMap<u32, BpfRawStats>,
}

/// Serializable CPU usage information
#[serde_as]
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct BpfCPUStatsInfo {
    /// CPU usage in the interval between two measurements with time adjustments applied
    pub exact_cpu_usage: f32,
    /// Time spent in the ebpf program starting from the first measurement
    #[serde_as(as = "DurationSecondsWithFrac<String>")]
    pub run_time: Duration,
    /// Number of times the ebpf program was run starting from the first measurement
    pub run_count: u64,
}

impl CpuMeter {
    pub fn new() -> Self {
        Self {
            bpf_prog_info_map: HashMap::new(),
        }
    }
}

impl Meter for CpuMeter {
    fn get_id_name_entity_mapping() -> HashMap<u32, String> {
        programs::loaded_programs()
            .filter_map(|p| p.ok())
            .map(|p| (p.id(), p.name_as_str().map(|x| x.to_string()).unwrap()))
            .collect()
    }

    async fn collect_raw_stats(
        prog_list_ids: &[u32],
        base_stats: &BpfRawStats,
        tx: Sender<BpfRawStats>,
    ) -> Result<()> {
        let bpf_program_iter = programs::loaded_programs();
        for program in bpf_program_iter
            .filter_map(|p| p.ok())
            .filter(|p| prog_list_ids.is_empty() || prog_list_ids.contains(&p.id()))
        {
            if tx.capacity() == 0 {
                warn!("Channel is full, result may be inaccurate");
            }
            let mut bpf_program_stats = base_stats.clone();
            bpf_program_stats.id = program.id();
            bpf_program_stats.name = program.name_as_str().unwrap_or("unknown").to_string();
            bpf_program_stats.run_count = program.run_count();
            bpf_program_stats.run_time = program.run_time();

            if let Err(e) = tx.send(bpf_program_stats).await {
                bail!("Failed to send program to channel: {e}");
            }
        }
        Ok(())
    }

    fn generate_stats_info(&mut self, raw_stats: &BpfRawStats) -> Option<BpfStatsInfo> {
        // Find previous info for the particular program id
        let Some(prev_stats) = self.bpf_prog_info_map.get_mut(&raw_stats.id) else {
            let id = raw_stats.id;
            self.bpf_prog_info_map.insert(id, raw_stats.clone());
            // Nothing to return, we should have at least two measurements to calculate cpu usage
            return None;
        };

        // Calculate run time in the interval between two measurements
        let run_time_diff = raw_stats.run_time - prev_stats.run_time;

        // Calculate cpu usage
        let interval = raw_stats.time_recieved.sub(prev_stats.time_recieved);
        let cpu_usage = run_time_diff.as_secs_f32() / interval.as_secs_f32();

        let export_stats = BpfCPUStatsInfo {
            exact_cpu_usage: cpu_usage,
            run_time: raw_stats.run_time,
            run_count: raw_stats.run_count,
        };
        // Set current info as previous info
        *prev_stats = raw_stats.clone();

        Some(BpfStatsInfo::Cpu(export_stats))
    }
}
