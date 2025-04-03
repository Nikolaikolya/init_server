use anyhow::Result;
use colored::*;
use env_logger::{Builder, Env};
use log::LevelFilter;

/// Инициализирует логирование
///
/// # Returns
/// * `Result<()>` - Успех или ошибка инициализации
///
/// # Examples
/// ```rust
/// logger::init()?;
/// ```
pub fn init() -> Result<()> {
    let env = Env::default()
        .filter_or("RUST_LOG", "info")
        .write_style_or("RUST_LOG_STYLE", "always");

    Builder::from_env(env)
        .format_timestamp_secs()
        .format_module_path(true)
        .filter(None, LevelFilter::Info)
        .init();

    Ok(())
}

/// Логирует информацию о пароле в безопасном режиме
///
/// # Arguments
/// * `message` - Сообщение для логирования
///
/// # Examples
/// ```rust
/// logger::password_info("Сгенерирован пароль: 123456");
/// ```
pub fn password_info(message: &str) {
    println!(
        "{} {}",
        "[GENERATED PASSWORD]".magenta().bold(),
        message.cyan().bold()
    );
}

/// Логирует успешное выполнение команды
///
/// # Arguments
/// * `message` - Сообщение для логирования
///
/// # Examples
/// ```rust
/// logger::success("Команда успешно выполнена");
/// ```
pub fn success(message: &str) {
    println!("{} {}", "[SUCCESS]".green().bold(), message);
}
