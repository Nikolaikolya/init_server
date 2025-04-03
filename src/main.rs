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

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Автоматический режим настройки
    #[arg(short, long)]
    auto: bool,

    /// Имя пользователя для создания
    #[arg(short, long)]
    user: Option<String>,

    /// SSH-ключ для добавления пользователю
    #[arg(long)]
    ssh_key: Option<String>,

    /// Настройка только для IP (без доменов)
    #[arg(long)]
    ip_only: bool,

    /// Настройка GitLab Runners
    #[arg(long)]
    setup_runners: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Инициализация сервера
    Init,
    /// Удаление настроек сервера
    Uninstall,
    /// Генерация bash скриптов
    GenerateScripts {
        /// Путь для сохранения скриптов
        #[arg(short, long, default_value = "/usr/local/bin")]
        output_dir: String,

        /// Директория для бэкапов
        #[arg(short, long, default_value = "/var/backups/server")]
        backup_dir: String,
    },
}

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
