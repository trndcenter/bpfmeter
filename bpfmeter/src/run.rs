use crate::config::RunArgs;
use crate::exporter::prometheus_exporter::PromExportType;
use crate::exporter::{Exporter, file_exporter, prometheus_exporter};
use crate::meter::{self, BpfInfo, BpfRawStats, Meter};

use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Ok, Result, bail};
use aya::sys;
use log::{error, info, warn};
use tokio::runtime::Builder;
use tokio::select;
use tokio::sync::mpsc;

pub fn run(args: &RunArgs) -> Result<()> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        // Create exporters for cpu and map meters
        let cpu_exporter: &RefCell<dyn Exporter> = if let Some(ref output_dir) = args.output_mode.output_dir {
            let file_exporter = file_exporter::FileExporter::new(args.cpu_period, "prog", output_dir);
            &RefCell::new(file_exporter)
        } else {
            let mut prom_exporter = prometheus_exporter::PrometheusExporter::new(
                args.output_mode.prometheus.labels.clone().unwrap_or_default(),
            );
            prom_exporter
                .start_local_server(args.output_mode.prometheus.port, &args.output_mode.prometheus.export_types)
                .await?;

            &RefCell::new(prom_exporter)
        };
        let map_exporter: &RefCell<dyn Exporter> = if let Some(ref output_dir) = args.output_mode.output_dir {
            // File exporter is different for cpu and map meters
            let file_exporter = file_exporter::FileExporter::new(args.map_period, "map", output_dir);
            &RefCell::new(file_exporter)
        } else {
            if args.enable_maps && !args.output_mode.prometheus.export_types.contains(&PromExportType::MapSize) {
                warn!("Map size is not exported to prometheus, but maps are enabled. Make sure you have enabled map size export type");
            }
            // Prometheus exporter is the same for both meters
            cpu_exporter
        };

        // Create meters for cpu and map meters
        tokio::pin! {
            let cpu_future = measure(args.cpu_period, args.channel_capacity, meter::cpu_meter::CpuMeter::new(), cpu_exporter,args.ticks, args.bpf_programs.as_ref());
            let map_future = measure(args.map_period, args.channel_capacity, meter::map_meter::MapMeter::new(), map_exporter,args.ticks, args.bpf_maps.as_ref());
        }
        let mut status = Ok(());
        let (mut cpu_ready, mut map_ready) = (args.disable_cpu, !args.enable_maps);

        // If something is disabled then it is ready
        if cpu_ready && map_ready {
            bail!("Nothing to measure, enable at least one of cpu or map meters");
        }

        info!("Starting measurements");

        loop {
            select! {
                res = &mut cpu_future, if !cpu_ready  => {
                    info!("CPU measurements finished");
                    cpu_ready = true;
                    status = res;
                },
                res = &mut map_future, if !map_ready => {
                    info!("Map measurements finished");
                    map_ready = true;
                    status = res
                },
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C pressed, exiting");
                    break;
                }
            }

            if cpu_ready && map_ready {
                info!("All measurements finished");
                break;
            }
        }
        status
    })
}

async fn measure<M: Meter>(
    period: Duration,
    channel_capacity: usize,
    mut meter: M,
    exporter: &RefCell<dyn Exporter>,
    ticks: Option<u64>,
    requested_ids: Option<&Vec<u32>>,
) -> Result<()> {
    let _fd = sys::enable_stats(sys::Stats::RunTime)
        .with_context(|| "Failed to enable run time stats")?;

    let requested_bpf_program_ids = if let Some(requested_ids) = requested_ids {
        // Create mapping of ebpf program/map ids to their names
        let mut bpf_id_name_map: HashMap<_, _> = M::get_id_name_entity_mapping();
        bpf_id_name_map.retain(|&k, _| requested_ids.contains(&k));

        // Check that some of the ebpf programs/maps are now loaded
        if !requested_ids
            .iter()
            .map(|id| (id, bpf_id_name_map.contains_key(id)))
            .inspect(|(id, exists)| {
                if !*exists {
                    warn!("Ebpf program {id} not found")
                }
            })
            .any(|(_, exists)| exists)
        {
            bail!("No ebpf programs with specified ids found");
        }

        requested_ids
    } else {
        &Vec::new()
    };

    let (tx, mut rx) = mpsc::channel(channel_capacity);

    let prog_list_ids = requested_bpf_program_ids.clone();
    tokio::spawn(async move {
        let timer = Instant::now();

        'monitor: for tick in 0.. {
            let cur_time = timer.elapsed();

            let bpf_program_stats = BpfRawStats {
                tick,
                time_recieved: cur_time,
                ..Default::default()
            };

            if let Err(err) =
                M::collect_raw_stats(&prog_list_ids, &bpf_program_stats, tx.clone()).await
            {
                error!("Stopping monitoring: {err}");
                break 'monitor;
            }

            if let Some(tick_bound) = ticks
                && tick >= tick_bound
            {
                break;
            }

            // Adjust period to the actual time spent in the loop
            let elapsed = timer.elapsed() - cur_time;
            // Elapsed time may be greater than period, so we must use checked_sub and set wait_time to zero
            let wait_time = period.checked_sub(elapsed).unwrap_or_default();
            tokio::time::sleep(wait_time).await;
        }
    });

    // Receive results from channel
    while let Some(cur_stats) = rx.recv().await {
        if let Some(stats_info) = meter.generate_stats_info(&cur_stats) {
            let export_info = BpfInfo {
                id: cur_stats.id,
                name: &cur_stats.name,
                tick: cur_stats.tick,
                stats: stats_info,
            };
            exporter.borrow_mut().export_info(&export_info)?;
        }
    }

    Ok(())
}
