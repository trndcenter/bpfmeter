use std::fmt::Display;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, atomic::AtomicU32};

use anyhow::{Context, Result};
use axum::routing::get;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use clap::ValueEnum;
use log::info;
use prometheus_client::{
    encoding::text::encode,
    metrics::{family::Family, gauge::Gauge},
    registry::Registry,
};
use tokio::sync::Mutex;

use crate::exporter::prometheus_gc::PromGC;
use crate::exporter::{BpfStatsInfo, Exporter};
use crate::meter::BpfInfo;

/// Exports BpfInfo to prometheus format and starts prometheus exporter
#[derive(Debug, Default)]
pub struct PrometheusExporter {
    /// Static labels to be added to all metrics
    static_lables: Labels,
    /// Metrics to be exported
    metrics: EBPFMetrics,
    /// Garbage collector for prometheus metrics
    gc: Option<PromGC>,
}

#[derive(Debug, Default)]
pub struct EBPFMetrics {
    /// Map of bpf program ids to cpu usage
    pub cpu_usage: Family<Labels, Gauge<f32, AtomicU32>>,
    /// Map of bpf program ids to run time
    pub run_time: Family<Labels, Gauge<f32, AtomicU32>>,
    /// Map of bpf program ids to event count
    pub event_count: Family<Labels, Gauge<u64, AtomicU64>>,
    /// Map of bpf program ids to map size
    pub map_size: Family<Labels, Gauge<u32, AtomicU32>>,
}

/// Prometheus export metric type
#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum PromExportType {
    /// CPU usage in percent
    CPUUsage,
    /// Accumulated run time in seconds
    RunTime,
    /// Number of times the ebpf program was run
    EventCount,
    /// Size of ebpf map
    MapSize,
}

impl Display for PromExportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromExportType::CPUUsage => write!(f, "cpu-usage"),
            PromExportType::RunTime => write!(f, "run-time"),
            PromExportType::EventCount => write!(f, "event-count"),
            PromExportType::MapSize => write!(f, "map-size"),
        }
    }
}

/// Vector of OpenMetrics labels and their values, format: [(label, value), (label, value), ...]
pub type Labels = Vec<(String, String)>;

/// Application state for prometheus exporter
#[derive(Debug)]
pub struct AppState {
    pub registry: Registry,
}

impl PrometheusExporter {
    /// Creates a new PrometheusExporter
    ///
    /// # Arguments
    ///
    /// * `labels` - Static labels to be added to all metrics
    ///
    /// * `gc` - Garbage collector for prometheus metrics
    pub fn new(labels: Labels, gc: Option<PromGC>) -> Self {
        Self {
            static_lables: labels,
            metrics: Default::default(),
            gc,
        }
    }

    /// Starts prometheus exporter on localhost
    ///
    /// # Arguments
    ///
    /// * `port` - Port to start exporter on
    ///
    /// * `expoting_types` - Types of metrics to export
    pub async fn start_local_server(
        &mut self,
        port: u16,
        expoting_types: &[PromExportType],
    ) -> Result<()> {
        let mut state = AppState {
            registry: Registry::default(),
        };
        if expoting_types.contains(&PromExportType::CPUUsage) {
            state.registry.register(
                "ebpf_cpu_usage",
                "CPU Usage of bpf programs",
                self.metrics.cpu_usage.clone(),
            );
        }
        if expoting_types.contains(&PromExportType::RunTime) {
            state.registry.register(
                "ebpf_run_time",
                "Time spent in the ebpf program starting from the first measurement (seconds)",
                self.metrics.run_time.clone(),
            );
        }
        if expoting_types.contains(&PromExportType::EventCount) {
            state.registry.register(
                "ebpf_event_count",
                "Number of times the ebpf program was run starting from the first measurement",
                self.metrics.event_count.clone(),
            );
        }
        if expoting_types.contains(&PromExportType::MapSize) {
            state.registry.register(
                "ebpf_map_size",
                "Current size of ebpf map",
                self.metrics.map_size.clone(),
            );
        }

        let state = Arc::new(Mutex::new(state));

        let router = Router::new()
            .route("/metrics", get(metrics_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
            .await
            .with_context(|| "Error while starting prometheus exporter")?;

        tokio::spawn(async move {
            info!("Prometheus node exporter is running at port: {port}");
            axum::serve(listener, router).await
        });

        if let Some(gc) = self.gc.as_ref() {
            gc.start();
        }

        Ok(())
    }
}

/// Handler for GET requests to /metrics endpoint
async fn metrics_handler(State(state): State<Arc<Mutex<AppState>>>) -> impl IntoResponse {
    let state = state.lock().await;
    let mut buffer = String::new();
    encode(&mut buffer, &state.registry).unwrap();

    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )
        .body(Body::from(buffer))
        .unwrap()
}

impl Exporter for PrometheusExporter {
    fn export_info(&mut self, data: &BpfInfo) -> Result<()> {
        let mut labels = self.static_lables.clone();
        match &data.stats {
            BpfStatsInfo::Cpu(stats) => {
                labels.push(("ebpf_id".to_string(), data.id.to_string()));
                labels.push(("ebpf_name".to_string(), data.name.to_string()));
                self.metrics
                    .cpu_usage
                    .get_or_create(&labels)
                    .set(stats.exact_cpu_usage);
                self.metrics
                    .run_time
                    .get_or_create(&labels)
                    .set(stats.run_time.as_secs_f32());
                self.metrics
                    .event_count
                    .get_or_create(&labels)
                    .set(stats.run_count);
                if let Some(gc) = self.gc.as_mut() {
                    gc.add_exported_program(data.id, data.name);
                }
            }
            BpfStatsInfo::Map(stats) => {
                labels.push(("ebpf_map_id".to_string(), data.id.to_string()));
                labels.push(("ebpf_map_name".to_string(), data.name.to_string()));
                labels.push(("ebpf_map_max_size".to_string(), stats.max_size.to_string()));
                self.metrics.map_size.get_or_create(&labels).set(stats.size);
                if let Some(gc) = self.gc.as_mut() {
                    gc.add_exported_map(data.id, data.name, stats.max_size);
                }
            }
        }

        if let Some(gc) = self.gc.as_mut()
            && gc.collect_needed()
        {
            gc.collect(&mut self.metrics, &self.static_lables);
        }

        Ok(())
    }
}
