use anyhow::Result;
use colored::*;
use env_logger::Builder;
use log::{Level, LevelFilter};
use std::io::Write;

/// Инициализирует логгер с цветными уровнями логирования
pub fn init() -> Result<()> {
    let mut builder = Builder::new();

    builder
        .format(|buf, record| {
            let level_str = match record.level() {
                Level::Error => "ERROR".red().bold(),
                Level::Warn => "WARNING".yellow().bold(),
                Level::Info => "INFO".green(),
                Level::Debug => "DEBUG".blue(),
                Level::Trace => "TRACE".normal(),
            };

            writeln!(
                buf,
                "{} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                level_str,
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();

    Ok(())
}

/// Выводит командную информацию, которая выделяется особым цветом
pub fn command_info(message: &str) {
    println!("{} {}", "[COMMAND]".magenta().bold(), message.cyan().bold());
}

/// Выводит сообщение об успешном завершении с зеленым цветом
pub fn success(message: &str) {
    println!("{} {}", "[SUCCESS]".green().bold(), message);
}

/// Выводит сообщение о пароле генерации с особым цветом
pub fn password_info(password: &str) {
    println!(
        "{} {}",
        "[GENERATED PASSWORD]".magenta().bold().on_yellow(),
        password.white().bold().on_blue()
    );
}
