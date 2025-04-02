use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod backup;
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
