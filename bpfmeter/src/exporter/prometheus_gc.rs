use std::{
    collections::HashSet,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use aya::{maps::loaded_maps, programs::loaded_programs};
use tokio::task::JoinHandle;

use crate::exporter::prometheus_exporter::{EBPFMetrics, Labels};

/// Garbage collector for Prometheus exporter
#[derive(Debug, Default)]
pub struct PromGC {
    /// Period of garbage collection
    period: Duration,
    /// Handle to waiting task
    waker_handle: Option<JoinHandle<()>>,
    /// Flag to indicate if garbage collection is needed
    collect_needed: Arc<AtomicBool>,
    /// Set of currently used maps
    used_maps: HashSet<MapLabels>,
    /// Set of currently used cpus
    used_progs: HashSet<ProgLabels>,
}

/// eBPF map identifiers
#[derive(Debug, Default, Hash, Eq, PartialEq)]
struct MapLabels {
    id: u32,
    name: String,
    max_size: u32,
}

/// eBPF programs identifiers
#[derive(Debug, Default, Hash, Eq, PartialEq)]
struct ProgLabels {
    id: u32,
    name: String,
}

impl PromGC {
    pub fn new(period: Duration) -> Self {
        Self {
            period,
            waker_handle: None,
            collect_needed: Arc::new(AtomicBool::new(false)),
            used_maps: HashSet::new(),
            used_progs: HashSet::new(),
        }
    }

    /// Start garbage collection
    pub fn start(&mut self) {
        if self.waker_handle.is_some() {
            return;
        }

        let collect_needed = self.collect_needed.clone();
        let period: Duration = self.period;
        self.waker_handle = Some(tokio::spawn(async move {
            loop {
                tokio::time::sleep(period).await;
                collect_needed.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    /// Add map to currently used map which will not be garbage collected
    /// on next garbage collection cycle
    ///
    /// # Arguments
    ///
    /// * `id` - eBPF map id
    ///
    /// * `name` - eBPF map name
    ///
    /// * `max_size` - eBPF map max size
    pub fn add_exported_map(&mut self, id: u32, name: &str, max_size: u32) {
        self.used_maps.insert(MapLabels {
            id,
            name: name.to_string(),
            max_size,
        });
    }

    /// Add program to currently used cpu which will not be garbage collected
    /// on next garbage collection cycle
    ///
    /// # Arguments
    ///
    /// * `id` - eBPF program id
    ///
    /// * `name` - eBPF program name
    pub fn add_exported_program(&mut self, id: u32, name: &str) {
        self.used_progs.insert(ProgLabels {
            id,
            name: name.to_string(),
        });
    }

    /// Check if garbage collection is needed
    pub fn collect_needed(&self) -> bool {
        self.collect_needed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Garbage collect metrics of maps and programs which are not used anymore
    ///
    /// # Arguments
    ///
    /// * `metrics` - metrics to garbage collect
    ///
    /// * `static_labels` - static labels to add to metrics
    pub fn collect(&mut self, metrics: &mut EBPFMetrics, static_labels: &Labels) {
        self.collect_needed
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let mut labels = static_labels.clone();

        let current_map_ids = loaded_maps()
            .filter_map(|p| p.ok())
            .map(|p| p.id())
            .collect::<Vec<u32>>();
        for map in self
            .used_maps
            .extract_if(|map| !current_map_ids.contains(&map.id))
        {
            labels.push(("ebpf_map_id".to_string(), map.id.to_string()));
            labels.push(("ebpf_map_name".to_string(), map.name.clone()));
            labels.push(("ebpf_map_max_size".to_string(), map.max_size.to_string()));
            metrics.map_size.remove(&labels);
            labels.pop();
            labels.pop();
            labels.pop();
        }

        let current_prog_ids = loaded_programs()
            .filter_map(|p| p.ok())
            .map(|p| p.id())
            .collect::<Vec<u32>>();
        for prog in self
            .used_progs
            .extract_if(|prog| !current_prog_ids.contains(&prog.id))
        {
            labels.push(("ebpf_id".to_string(), prog.id.to_string()));
            labels.push(("ebpf_name".to_string(), prog.name.clone()));
            metrics.cpu_usage.remove(&labels);
            metrics.run_time.remove(&labels);
            metrics.event_count.remove(&labels);
            labels.pop();
            labels.pop();
        }
    }
}

impl Drop for PromGC {
    fn drop(&mut self) {
        if let Some(handle) = self.waker_handle.take() {
            handle.abort();
        }
    }
}
