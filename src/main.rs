use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info};

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
    command: Commands,

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

    /// Пароль для пользователя (только для ручного режима)
    #[arg(long)]
    password: Option<String>,
}

/// Команды, поддерживаемые утилитой
#[derive(Subcommand)]
enum Commands {
    /// Инициализация сервера (создание пользователя, настройка SSH, Docker, Nginx и т.д.)
    Init {
        /// Автоматический режим
        #[arg(long)]
        auto: bool,

        /// Имя пользователя
        #[arg(long)]
        user: Option<String>,

        /// SSH ключ
        #[arg(long)]
        ssh_key: Option<String>,

        /// Использовать только IP (без доменов)
        #[arg(long)]
        ip_only: bool,

        /// Настроить GitLab Runners
        #[arg(long)]
        setup_runners: bool,

        /// Пароль для пользователя (только для ручного режима)
        #[arg(long)]
        password: Option<String>,
    },

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
    // Инициализируем логирование
    logger::init()?;

    let cli = Cli::parse();

    info!("Запуск скрипта настройки сервера");

    match cli.command {
        Commands::Init {
            auto,
            user,
            ssh_key,
            ip_only,
            setup_runners,
            password,
        } => {
            if auto && password.is_some() {
                error!("Пароль нельзя задать в автоматическом режиме");
                return Ok(());
            }
            server::init_server(auto, user, ssh_key, ip_only, setup_runners, password).await?;
        }
        Commands::Uninstall => {
            server::uninstall_server().await?;
        }
        Commands::GenerateScripts {
            output_dir,
            backup_dir,
        } => {
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
    }

    Ok(())
}
