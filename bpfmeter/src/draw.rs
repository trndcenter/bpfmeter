use std::{collections::HashMap, fs::File, io::BufReader, path::PathBuf, time::SystemTime};

use crate::{
    config::{DrawArgs, DrawType},
    meter::cpu_meter::BpfCPUStatsInfo,
};
use anyhow::{Context, Result, bail};
use humantime::format_rfc3339_seconds;
use log::info;
use plotters::prelude::*;

const USAGE_MAX_TICKS: [f32; 6] = [1.0f32, 5.0f32, 10.0f32, 20.0f32, 50.0f32, 100.0f32];

pub fn draw(args: &DrawArgs) -> Result<()> {
    let bpf_data_paths = args
        .input_dir
        .read_dir()?
        .flatten()
        .filter(|e| e.path().extension().unwrap_or_default() == "csv")
        .map(|e| e.path())
        .collect::<Vec<_>>();

    if bpf_data_paths.is_empty() {
        bail!(
            "No bpf data csv files found in {}",
            args.input_dir.display()
        );
    }

    let draw_func = match args.draw_type {
        DrawType::CPUUsage => draw_cpu_usage,
        DrawType::EventCount => draw_event_count,
    };

    if args.multiple {
        for path in bpf_data_paths {
            draw_func(&[path], &args.output_dir)?;
        }
        Ok(())
    } else {
        draw_func(&bpf_data_paths, &args.output_dir)
    }
}

fn draw_cpu_usage(files: &[PathBuf], output_dir: &std::path::Path) -> Result<()> {
    let mut file_readers_map: HashMap<String, Vec<(u64, f32)>> = HashMap::new();
    let (mut max_time, mut max_usage) = (0u64, 0.0f32);

    let (output_svg, factor, time_unit) =
        get_parameters_from_filenames(files, output_dir, "cpu_usage")?;

    for file in files {
        let time_cpu = csv::Reader::from_reader(BufReader::new(File::open(file)?))
            .deserialize()
            .filter_map(|r: std::result::Result<BpfCPUStatsInfo, csv::Error>| r.ok())
            .enumerate()
            .map(
                |(
                    idx,
                    BpfCPUStatsInfo {
                        exact_cpu_usage: cpu_usage,
                        ..
                    },
                )| (idx as u64 * factor, cpu_usage * 100.0),
            )
            .collect::<Vec<(u64, f32)>>();
        if time_cpu.is_empty() {
            continue;
        }
        max_time = max_time.max(time_cpu.iter().map(|(time, _)| *time).max().unwrap_or(0));
        max_usage = max_usage.max(
            time_cpu
                .iter()
                .map(|(_, usage)| *usage)
                .fold(0.0f32, |f1, f2| f1.max(f2)),
        );
        let bpf_program_name = file
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once("_")
            .unwrap()
            .0
            .to_string();
        file_readers_map.insert(bpf_program_name, time_cpu);
    }

    if file_readers_map.is_empty() {
        bail!("No bpf data csv files found in {:?}", files);
    }

    // Calculate image shapes
    let max_usage_bound = max_usage * 1.5;
    max_usage = USAGE_MAX_TICKS
        .iter()
        .find(|&&x| x > max_usage_bound)
        .copied()
        .unwrap_or(100.0f32);
    let usage_step = max_usage / 10.0; // 10 ticks on y axis
    let time_step = (max_time / 20).max(1); // 20 ticks on x axis

    let root = SVGBackend::new(&output_svg, (1920, 1080)).into_drawing_area();
    root.fill(&WHITE)?;

    // Title: 80, Body: 920, Footer: 80
    let (title, body) = root.split_vertically(80);
    let (body, footer) = body.split_vertically(920);

    title.titled(
        "eBPF programs CPU usage",
        ("sans-serif", 50).into_font().color(&BLACK),
    )?;

    footer.titled(
        &format!(
            "Data Sources {}...",
            files
                .iter()
                .take(3)
                .map(|x| x.display().to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        ("sans-serif", 10).into_font().color(&BLACK.mix(0.5)),
    )?;

    // Calculate avg, min and max usage
    let mut overall_usage = Vec::new();
    for (_, data) in file_readers_map.iter() {
        if overall_usage.len() < data.len() {
            overall_usage.resize(data.len(), 0.0f32);
        }

        overall_usage
            .iter_mut()
            .zip(data.iter())
            .for_each(|(a, b)| {
                *a += b.1;
            });
    }
    let avg_overall_usage = overall_usage.iter().sum::<f32>() / overall_usage.len() as f32;
    let min_overall_usage = *overall_usage
        .iter()
        .min_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();
    let max_overall_usage = *overall_usage
        .iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();

    let mut chart = ChartBuilder::on(&body)
        .caption(
            format!(
                "Overall usage: Avg: {avg_overall_usage:.2}%, Min: {min_overall_usage:.2}%, Max: {max_overall_usage:.2}%"
            ),
            ("sans-serif", (3).percent_height()),
        )
        .set_label_area_size(LabelAreaPosition::Left, (8).percent())
        .set_label_area_size(LabelAreaPosition::Bottom, (4).percent())
        .margin((1).percent())
        .build_cartesian_2d(
            (0u64..max_time).step(time_step),
            (0f32..max_usage).step(usage_step),
        )?;

    chart
        .configure_mesh()
        .x_desc(format!("Time ({time_unit})"))
        .y_desc("CPU Usage %")
        .draw()?;

    for (idx, (bpf_program_name, data)) in file_readers_map.into_iter().enumerate() {
        let color = Palette99::pick(idx).mix(0.9);
        chart
            .draw_series(LineSeries::new(data, color.stroke_width(3)))?
            .label(bpf_program_name)
            .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], color.filled()));
    }

    chart.configure_series_labels().border_style(BLACK).draw()?;

    // To avoid the IO failure being ignored silently, we manually call the present function
    root.present()
        .with_context(|| format!("Unable to write result to file {}", output_svg.display()))?;

    info!("Image saved to {}", output_svg.display());

    Ok(())
}

fn draw_event_count(files: &[PathBuf], output_dir: &std::path::Path) -> Result<()> {
    let mut file_readers_map: HashMap<String, Vec<(u64, u64)>> = HashMap::new();
    let (mut max_time, mut max_run_count) = (0u64, 0u64);

    let (output_svg, factor, time_unit) =
        get_parameters_from_filenames(files, output_dir, "event_count")?;

    for file in files {
        let mut prog_events_count = csv::Reader::from_reader(BufReader::new(File::open(file)?))
            .deserialize()
            .filter_map(|r: std::result::Result<BpfCPUStatsInfo, csv::Error>| r.ok())
            .enumerate()
            .map(|(idx, BpfCPUStatsInfo { run_count, .. })| (idx as u64 * factor, run_count))
            .collect::<Vec<(u64, u64)>>();
        // Calculate the event count between two measurements
        if prog_events_count.is_empty() {
            continue;
        } else {
            prog_events_count = prog_events_count
                .windows(2)
                .map(|w| (w[0].0, w[1].1 - w[0].1))
                .collect();
        }
        max_time = max_time.max(
            prog_events_count
                .iter()
                .map(|(time, _)| *time)
                .max()
                .unwrap_or(0),
        );
        max_run_count = max_run_count.max(
            prog_events_count
                .iter()
                .map(|(_, run_count)| *run_count)
                .max()
                .unwrap_or_default(),
        );
        let bpf_program_name = file
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .rsplit_once("_")
            .unwrap()
            .0
            .to_string();
        file_readers_map.insert(bpf_program_name, prog_events_count);
    }

    if file_readers_map.is_empty() {
        bail!("No bpf data csv files found in {:?}", files);
    }

    // Calculate image shapes
    let max_run_count = max_run_count * 3 / 2;
    let run_count_step = max_run_count / 10; // 10 ticks on y axis
    let time_step = (max_time / 20).max(1); // 20 ticks on x axis

    let root = SVGBackend::new(&output_svg, (1920, 1080)).into_drawing_area();
    root.fill(&WHITE)?;

    // Title: 80, Body: 920, Footer: 80
    let (title, body) = root.split_vertically(80);
    let (body, footer) = body.split_vertically(920);

    title.titled(
        "eBPF programs event count",
        ("sans-serif", 50).into_font().color(&BLACK),
    )?;

    footer.titled(
        &format!(
            "Data Sources {}...",
            files
                .iter()
                .take(3)
                .map(|x| x.display().to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        ("sans-serif", 10).into_font().color(&BLACK.mix(0.5)),
    )?;

    // Calculate avg, min and max number of events
    let mut overall_usage = Vec::new();
    for (_, data) in file_readers_map.iter() {
        if overall_usage.len() < data.len() {
            overall_usage.resize(data.len(), 0u64);
        }

        overall_usage
            .iter_mut()
            .zip(data.iter())
            .for_each(|(a, b)| {
                *a += b.1;
            });
    }
    let avg_overall_usage = overall_usage.iter().sum::<u64>() / overall_usage.len() as u64;
    let min_overall_usage = *overall_usage
        .iter()
        .min_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();
    let max_overall_usage = *overall_usage
        .iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap())
        .unwrap();

    let mut chart = ChartBuilder::on(&body)
        .caption(
            format!(
                "Overall events: Avg: {avg_overall_usage:.2}, Min: {min_overall_usage:.2}, Max: {max_overall_usage:.2}"
            ),
            ("sans-serif", (3).percent_height()),
        )
        .set_label_area_size(LabelAreaPosition::Left, (8).percent())
        .set_label_area_size(LabelAreaPosition::Bottom, (4).percent())
        .margin((1).percent())
        .build_cartesian_2d(
            (0u64..max_time).step(time_step),
            (0u64..max_run_count).step(run_count_step),
        )?;

    chart
        .configure_mesh()
        .x_desc(format!("Time ({time_unit})"))
        .y_desc("Event count")
        .draw()?;

    for (idx, (bpf_program_name, data)) in file_readers_map.into_iter().enumerate() {
        let color = Palette99::pick(idx).mix(0.9);
        chart
            .draw_series(LineSeries::new(data, color.stroke_width(3)))?
            .label(bpf_program_name)
            .legend(move |(x, y)| Rectangle::new([(x, y - 5), (x + 10, y + 5)], color.filled()));
    }

    chart.configure_series_labels().border_style(BLACK).draw()?;

    // To avoid the IO failure being ignored silently, we manually call the present function
    root.present()
        .with_context(|| format!("Unable to write result to file {}", output_svg.display()))?;

    info!("Image saved to {}", output_svg.display());

    Ok(())
}

/// Get the output svg file name, multiply factor and the time unit from the first file
/// or use the default values.
///
/// # Arguments
///
/// * `files` - The input csv files
///
/// * `output_dir` - The output directory to save results
///
/// * `file_suffix` - The suffix of the output svg file
fn get_parameters_from_filenames(
    files: &[PathBuf],
    output_dir: &std::path::Path,
    file_suffix: &str,
) -> Result<(PathBuf, u64, &'static str)> {
    if files.is_empty() {
        bail!("No files to draw");
    }
    let file_stem = files
        .first()
        .context("No files to draw")?
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap();
    let Some((program_name, period)) = file_stem.rsplit_once('_') else {
        bail!(
            "File name of csv should be in format <bpf_id>_<bpf_name>_prog_<measurement_period>.csv, given: {}",
            file_stem
        );
    };

    let time = format_rfc3339_seconds(SystemTime::now()).to_string();
    let mut output_svg = if files.len() == 1 {
        PathBuf::from([time.as_str(), program_name, file_suffix].join("_"))
    } else {
        PathBuf::from([time.as_str(), "bpf_programs", file_suffix].join("_"))
    }
    .with_extension("svg");
    output_svg = output_dir.join(output_svg);

    let (factor, time_unit) = if period.ends_with("ms") {
        (
            period
                .trim_end_matches("ms")
                .parse::<u64>()
                .with_context(|| format!("Invalid measurement period: {period}"))?,
            "ms",
        )
    } else if period.ends_with("s") {
        (
            period
                .trim_end_matches("s")
                .parse::<u64>()
                .with_context(|| format!("Invalid measurement period: {period}"))?,
            "s",
        )
    } else {
        bail!("Invalid measurement period: {}", period);
    };

    for file in files {
        let other_period = file
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
            .split("_")
            .last()
            .unwrap();
        if other_period != period {
            bail!(
                "All files should have the same measurement period, given: {} and {}",
                other_period,
                period
            );
        }
    }

    Ok((output_svg, factor, time_unit))
}
