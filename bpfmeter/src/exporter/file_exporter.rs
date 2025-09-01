use std::{collections::HashMap, path::Path};

use crate::{exporter::Exporter, meter::BpfInfo};
use anyhow::{Ok, Result};
use log::debug;

/// Exports BpfProgramInfo to file
pub struct FileExporter {
    /// Period of time between two measurements (ticks)
    period: std::time::Duration,
    /// Map of bpf program ids to csv writers
    writers: HashMap<u32, csv::Writer<std::fs::File>>,
    /// Directory to write the file to
    output_dir: std::path::PathBuf,
    /// Suffix to add to the filenames
    filename_suffix: String,
}

impl FileExporter {
    /// Creates a new FileExporter
    ///
    /// # Arguments
    ///
    /// * `period` - Period of time between two measurements (ticks)
    ///
    /// * `suffix` - Suffix to add to the filenames
    ///
    /// * `output_dir` - Directory to write the files to
    pub fn new(period: std::time::Duration, suffix: &str, output_dir: &Path) -> Self {
        Self {
            period,
            writers: HashMap::new(),
            output_dir: output_dir.to_path_buf(),
            filename_suffix: suffix.into(),
        }
    }

    /// Adds a new writer to the exporter
    ///
    /// # Arguments
    ///
    /// * `output_dir` - Directory to write the file to
    ///
    /// * `bpf_id` - Bpf program id
    ///
    /// * `bpf_name` - Bpf program name
    fn add_writer(&mut self, bpf_id: u32, bpf_name: &str) -> Result<()> {
        let file = self.output_dir.join(format!(
            "{bpf_id}_{bpf_name}_{}_{:?}.csv",
            self.filename_suffix, self.period
        ));
        debug!("Writing measurements to file: {file:?}");
        let writer = csv::Writer::from_path(file)?;
        self.writers.insert(bpf_id, writer);
        Ok(())
    }
}

impl Drop for FileExporter {
    fn drop(&mut self) {
        for writer in self.writers.values_mut() {
            if let Err(e) = writer.flush() {
                debug!("Failed to flush writer: {e}");
            }
        }
    }
}

impl Exporter for FileExporter {
    fn export_info(&mut self, info: &BpfInfo) -> Result<()> {
        if !self.writers.contains_key(&info.id) {
            self.add_writer(info.id, info.name)?;
        }
        let writer: &mut csv::Writer<std::fs::File> = self.writers.get_mut(&info.id).unwrap();
        writer.serialize(&info.stats)?;
        Ok(())
    }
}
