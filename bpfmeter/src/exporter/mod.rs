pub mod file_exporter;
pub mod prometheus_exporter;
pub mod prometheus_gc;

use anyhow::Result;

use crate::meter::BpfInfo;
use crate::meter::BpfStatsInfo;

/// Exports BpfProgramInfo to some storage (e.g. file, database, etc.)
pub trait Exporter {
    /// Exports BpfProgramInfo to storage
    ///
    /// # Arguments
    ///
    /// * `data` - BpfProgramInfo to export
    fn export_info(&mut self, data: &BpfInfo) -> Result<()>;
}
