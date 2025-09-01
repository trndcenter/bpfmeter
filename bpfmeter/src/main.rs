mod config;
#[cfg(feature = "draw")]
mod draw;
mod exporter;
mod meter;
mod run;

use anyhow::Result;
use log::LevelFilter;
use std::time::SystemTime;

fn setup_logger(level: LevelFilter) -> Result<(), fern::InitError> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {}] {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

fn main() -> Result<()> {
    // Init config
    let config = &*config::CONFIG;
    setup_logger(config.log_level.parse()?)?;

    match &config.command {
        config::SubCommands::Run(args) => run::run(args),
        #[cfg(feature = "draw")]
        config::SubCommands::Draw(args) => draw::draw(args),
    }
}
