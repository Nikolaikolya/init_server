use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod backup;
mod bash_script;
mod config;
mod docker;
mod logger;
mod nginx;
mod security;
mod server;
mod utils;

/// Утилита автоматизированной настройки серверов на базе Ubuntu 24
///
/// Предоставляет инструменты для настройки пользователей, SSH, Docker, Nginx,
/// SSL-сертификатов, GitLab Runners и других компонентов для быстрого и безопасного
/// развертывания серверной инфраструктуры
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Автоматический режим настройки без запросов пользователю
    #[arg(short, long)]
    auto: bool,

    /// Имя пользователя для создания (если не указан, будет создан пользователь 'admin')
    #[arg(short, long)]
    user: Option<String>,

    /// SSH-ключ для добавления пользователю (если не указан, будет запрошен интерактивно)
    #[arg(long)]
    ssh_key: Option<String>,

    /// Настройка только для IP (без доменов)
    #[arg(long)]
    ip_only: bool,

    /// Включить настройку GitLab Runners
    #[arg(long)]
    setup_runners: bool,
}

/// Команды, поддерживаемые утилитой
#[derive(Subcommand)]
enum Commands {
    /// Инициализация сервера (создание пользователя, настройка SSH, Docker, Nginx и т.д.)
    Init,

    /// Удаление настроек сервера (остановка контейнеров, удаление директорий, восстановление SSH)
    Uninstall,

    /// Генерация bash скриптов для автоматизации процессов настройки, обновления и бэкапа
    GenerateScripts {
        /// Путь для сохранения скриптов (по умолчанию /usr/local/bin)
        #[arg(short, long, default_value = "/usr/local/bin")]
        output_dir: String,

        /// Директория для бэкапов (по умолчанию /var/backups/server)
        #[arg(short, long, default_value = "/var/backups/server")]
        backup_dir: String,
    },
}

/// Точка входа программы
///
/// Обрабатывает аргументы командной строки и вызывает соответствующие функции.
/// Поддерживает три основные команды: инициализация сервера, удаление настроек
/// и генерация bash-скриптов.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Инициализация логгера
    logger::init()?;

    info!("Запуск скрипта настройки сервера");

    match &cli.command {
        Some(Commands::Init) => {
            server::init_server(
                cli.auto,
                cli.user,
                cli.ssh_key,
                cli.ip_only,
                cli.setup_runners,
            )
            .await?;
        }
        Some(Commands::Uninstall) => {
            server::uninstall_server().await?;
        }
        Some(Commands::GenerateScripts {
            output_dir,
            backup_dir,
        }) => {
            info!("Генерация bash скриптов...");

            // Формируем пути для скриптов
            let setup_script_path = format!("{}/server-setup.sh", output_dir);
            let update_script_path = format!("{}/server-update.sh", output_dir);
            let backup_script_path = format!("{}/server-backup.sh", output_dir);

            // Генерируем скрипты
            bash_script::generate_setup_script(
                &setup_script_path,
                cli.auto,
                cli.user.as_deref(),
                cli.ssh_key.as_deref(),
                cli.ip_only,
                cli.setup_runners,
            )
            .await?;

            bash_script::generate_update_script(&update_script_path).await?;
            bash_script::generate_backup_script(&backup_script_path, &backup_dir).await?;

            info!("Все скрипты успешно сгенерированы:");
            info!("  - Скрипт установки: {}", setup_script_path);
            info!("  - Скрипт обновления: {}", update_script_path);
            info!("  - Скрипт бэкапа: {}", backup_script_path);
        }
        None => {
            // Если команда не указана, запускаем инициализацию сервера
            // с соответствующими параметрами
            if cli.auto {
                server::init_server(true, cli.user, cli.ssh_key, cli.ip_only, cli.setup_runners)
                    .await?;
            } else {
                server::init_server(false, None, None, false, false).await?;
            }
        }
    }

    Ok(())
}
