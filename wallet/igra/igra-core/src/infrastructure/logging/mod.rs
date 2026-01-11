//! Logging infrastructure using `log` + `log4rs`.
//!
//! This replaces the previous `tracing_subscriber` initialization and aligns IGRA with the
//! logging stack used by rusty-kaspa.

mod consts;

pub use consts::*;

use log::LevelFilter;
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        rolling_file::{
            policy::compound::{roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger, CompoundPolicy},
            RollingFileAppender,
        },
    },
    config::{Appender, Logger, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
    Config,
};
use std::io::IsTerminal;
use std::path::PathBuf;

const CONSOLE_APPENDER: &str = "stderr";
const LOG_FILE_APPENDER: &str = "log_file";
const ERR_LOG_FILE_APPENDER: &str = "err_log_file";

/// Initialize the IGRA logger with optional file output.
///
/// # Arguments
/// - `log_dir`: Optional directory for log files. If `None`, only console output is used.
/// - `filters`: Filter expression (e.g. `"info"` for IGRA crates, `"igra_core=debug"`, `"iroh=debug"`, `"root=info"`).
///
/// # Filtering Strategy (Whitelist)
/// - Root level defaults to OFF (suppresses all external crates completely)
/// - `igra_core` and `igra_service` are whitelisted at the requested app level (default INFO)
/// - User can opt-in specific 3rd party crates via `<crate>=<level>` (e.g. `"iroh=info"`)
/// - User can opt-in *all* 3rd party logs by explicitly setting `root=<level>` (e.g. `"root=info"`)
///
/// Notes:
/// - The logger is global; repeated calls are ignored.
/// - Console output goes to stderr.
pub fn init_logger(log_dir: Option<&str>, filters: &str) {
    let app_level = parse_app_level(filters);
    let root_level = parse_root_override(filters).unwrap_or(LevelFilter::Off);
    let module_levels = parse_module_levels(filters);

    let use_ansi = std::io::stderr().is_terminal();
    let console_pattern = if use_ansi { LOG_LINE_PATTERN_COLORED } else { LOG_LINE_PATTERN };

    let console = ConsoleAppender::builder()
        .target(Target::Stderr)
        .encoder(Box::new(PatternEncoder::new(console_pattern)))
        .build();

    let mut config_builder = Config::builder().appender(Appender::builder().build(CONSOLE_APPENDER, Box::new(console)));

    let mut root_appenders: Vec<&str> = vec![CONSOLE_APPENDER];

    if let Some(dir) = log_dir.filter(|s| !s.trim().is_empty()) {
        let dir = dir.trim();
        let log_path = PathBuf::from(dir).join(LOG_FILE_NAME);
        let archive_pattern = PathBuf::from(dir).join(format!("{LOG_FILE_NAME}.{{}}.gz"));

        let roller = FixedWindowRoller::builder()
            .base(1)
            .build(archive_pattern.to_str().unwrap_or("igra.log.{}.gz"), LOG_FILE_MAX_ROLLS)
            .unwrap();
        let trigger = SizeTrigger::new(LOG_FILE_MAX_SIZE);
        let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

        let file_appender = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(LOG_LINE_PATTERN)))
            .build(log_path, Box::new(policy))
            .unwrap();

        config_builder = config_builder.appender(Appender::builder().build(LOG_FILE_APPENDER, Box::new(file_appender)));
        root_appenders.push(LOG_FILE_APPENDER);

        let err_log_path = PathBuf::from(dir).join(ERR_LOG_FILE_NAME);
        let err_archive_pattern = PathBuf::from(dir).join(format!("{ERR_LOG_FILE_NAME}.{{}}.gz"));

        let err_roller = FixedWindowRoller::builder()
            .base(1)
            .build(err_archive_pattern.to_str().unwrap_or("igra_err.log.{}.gz"), LOG_FILE_MAX_ROLLS)
            .unwrap();
        let err_trigger = SizeTrigger::new(LOG_FILE_MAX_SIZE);
        let err_policy = CompoundPolicy::new(Box::new(err_trigger), Box::new(err_roller));

        let err_file_appender = RollingFileAppender::builder()
            .encoder(Box::new(PatternEncoder::new(LOG_LINE_PATTERN)))
            .build(err_log_path, Box::new(err_policy))
            .unwrap();

        config_builder = config_builder.appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Warn)))
                .build(ERR_LOG_FILE_APPENDER, Box::new(err_file_appender)),
        );
        root_appenders.push(ERR_LOG_FILE_APPENDER);
    }

    let appender_names: Vec<String> = root_appenders.iter().map(|name| (*name).to_string()).collect();

    // Whitelist our crates at the requested app level (unless user explicitly set them)
    for crate_name in WHITELISTED_CRATES {
        if !module_levels.iter().any(|(m, _)| m == *crate_name) {
            config_builder = config_builder.logger(
                Logger::builder()
                    .appenders(appender_names.clone())
                    .additive(false)
                    .build(*crate_name, app_level),
            );
        }
    }

    // Apply user-specified module levels (these override whitelist)
    for (module, level) in &module_levels {
        config_builder = config_builder.logger(
            Logger::builder()
                .appenders(appender_names.clone())
                .additive(false)
                .build(module, *level),
        );
    }

    let config = config_builder.build(Root::builder().appenders(root_appenders).build(root_level)).unwrap();
    let _ = log4rs::init_config(config);
}

fn parse_app_level(filters: &str) -> LevelFilter {
    for part in filters.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !part.contains('=') {
            if let Ok(level) = part.parse() {
                return level;
            }
        }
    }
    LevelFilter::Info
}

fn parse_root_override(filters: &str) -> Option<LevelFilter> {
    for part in filters.split(',') {
        let part = part.trim();
        let Some((module, level_str)) = part.split_once('=') else {
            continue;
        };
        if module.trim() != "root" {
            continue;
        }
        let level_str = level_str.trim();
        if level_str.is_empty() {
            continue;
        }
        if let Ok(level) = level_str.parse() {
            return Some(level);
        }
    }
    None
}

fn parse_module_levels(filters: &str) -> Vec<(String, LevelFilter)> {
    let mut result = Vec::new();
    for part in filters.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((module, level_str)) = part.split_once('=') {
            let module = module.trim();
            let level_str = level_str.trim();
            if module.is_empty() || level_str.is_empty() {
                continue;
            }
            if module == "root" {
                continue;
            }
            if let Ok(level) = level_str.parse() {
                result.push((module.to_string(), level));
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_app_level() {
        assert_eq!(parse_app_level("info"), LevelFilter::Info);
        assert_eq!(parse_app_level("debug"), LevelFilter::Debug);
        assert_eq!(parse_app_level("info,igra=debug"), LevelFilter::Info);
        assert_eq!(parse_app_level("igra=debug"), LevelFilter::Info);
        assert_eq!(parse_app_level(""), LevelFilter::Info);
    }

    #[test]
    fn test_parse_module_levels() {
        let levels = parse_module_levels("info,igra_core=debug,igra_service=trace");
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], ("igra_core".to_string(), LevelFilter::Debug));
        assert_eq!(levels[1], ("igra_service".to_string(), LevelFilter::Trace));
    }

    #[test]
    fn test_parse_root_override() {
        assert_eq!(parse_root_override("info"), None);
        assert_eq!(parse_root_override("root=warn"), Some(LevelFilter::Warn));
        assert_eq!(parse_root_override("root=error,igra_core=debug"), Some(LevelFilter::Error));
    }
}
