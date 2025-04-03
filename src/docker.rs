use anyhow::{Context, Result};
use log::{error, info, warn};
use tokio::{fs, process::Command};

use crate::{config, security, utils};

/// Устанавливает Docker и Docker Compose
pub async fn install_docker(user: &str) -> Result<()> {
    info!("Начало установки Docker...");

    // Установка зависимостей
    for pkg in &["fail2ban"] {
        utils::install_package(pkg).await?;
    }

    // Добавление GPG ключа Docker
    info!("Добавление GPG ключа Docker...");
    let output = Command::new("sh")
        .arg("-c")
        .arg("curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg")
        .output()
        .await
        .context("Не удалось добавить GPG ключ Docker")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка добавления GPG ключа: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка добавления GPG ключа: {}", stderr));
    }

    // Добавление репозитория Docker
    info!("Добавление репозитория Docker...");
    let cmd = r#"echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null"#;

    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .context("Не удалось добавить репозиторий Docker")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка добавления репозитория: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка добавления репозитория: {}", stderr));
    }

    // Обновление списка пакетов
    utils::update_system().await?;

    // Установка Docker
    info!("Установка Docker Engine...");
    for pkg in &["docker-ce", "docker-compose"] {
        utils::install_package(pkg).await?;
    }

    // Добавление пользователя в группу docker
    if user != "root" {
        info!("Добавление пользователя {} в группу docker...", user);

        let output = Command::new("usermod")
            .args(["-aG", "docker", user])
            .output()
            .await
            .with_context(|| {
                format!("Не удалось добавить пользователя {} в группу docker", user)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка добавления пользователя в группу docker: {}", stderr);
        }
    }

    // Логируем событие установки Docker
    let audit_log = security::AuditLog::new(
        "docker_install",
        user,
        Some("Docker Engine and Docker Compose installation"),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Docker успешно установлен");

    Ok(())
}

/// Проверяет существование Docker сети
pub async fn check_network_exists(network_name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["network", "ls", "--format", "{{.Name}}"])
        .output()
        .await
        .context("Не удалось получить список Docker сетей")?;

    let networks = String::from_utf8_lossy(&output.stdout);
    Ok(networks.lines().any(|line| line == network_name))
}

/// Создает Docker сеть
pub async fn create_docker_network(network_name: &str, user: &str) -> Result<()> {
    // Проверяем существование сети
    if check_network_exists(network_name).await? {
        info!("Docker сеть {} уже существует", network_name);
        return Ok(());
    }

    security::execute_command_with_audit(
        "docker",
        &["network", "create", network_name],
        user,
        &format!("Создание Docker сети {}", network_name),
    )
    .await?;

    info!("Docker сеть {} успешно создана", network_name);
    Ok(())
}

/// Очищает старые контейнеры
pub async fn cleanup_containers(user: &str) -> Result<()> {
    info!("Очистка неиспользуемых контейнеров...");

    // Останавливаем запущенные контейнеры
    let output = Command::new("docker")
        .args(["ps", "-aq"])
        .output()
        .await
        .context("Не удалось получить список контейнеров")?;

    let containers = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !containers.is_empty() {
        let output = Command::new("docker")
            .args(["stop", &containers])
            .output()
            .await
            .context("Не удалось остановить контейнеры")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка при остановке контейнеров: {}", stderr);
        }
    }

    // Удаляем все контейнеры
    let output = Command::new("docker")
        .args(["rm", "-f", &containers])
        .output()
        .await
        .context("Не удалось удалить контейнеры")?;

    if !output.status.success() && !containers.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ошибка при удалении контейнеров: {}", stderr);
    }

    // Удаляем неиспользуемые образы
    let output = Command::new("docker")
        .args(["image", "prune", "-a", "-f"])
        .output()
        .await
        .context("Не удалось удалить неиспользуемые образы")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ошибка при удалении образов: {}", stderr);
    }

    // Удаляем неиспользуемые тома
    let output = Command::new("docker")
        .args(["volume", "prune", "-f"])
        .output()
        .await
        .context("Не удалось удалить неиспользуемые тома")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ошибка при удалении томов: {}", stderr);
    }

    // Удаляем неиспользуемые сети
    let output = Command::new("docker")
        .args(["network", "prune", "-f"])
        .output()
        .await
        .context("Не удалось удалить неиспользуемые сети")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ошибка при удалении сетей: {}", stderr);
    }

    // Логируем событие очистки
    let audit_log = security::AuditLog::new(
        "docker_cleanup",
        user,
        Some("Docker cleanup (containers, images, volumes, networks)"),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Очистка Docker завершена");

    Ok(())
}

/// Настраивает GitLab Runners
pub async fn setup_gitlab_runners(names: &[String], token: &str, user: &str) -> Result<()> {
    for name in names {
        info!("Настройка GitLab Runner: {}", name);

        // Создаем директорию для конфигурации
        let config_dir =
            config::get_full_path(user, &format!("{}/{}", config::GITLAB_RUNNER_DIR, name));
        fs::create_dir_all(&config_dir)
            .await
            .with_context(|| format!("Не удалось создать директорию {}", config_dir))?;

        // Формируем пути для монтирования
        let config_mount = format!("{}:/etc/gitlab-runner", config_dir);
        let docker_sock_mount = "/var/run/docker.sock:/var/run/docker.sock";
        let cache_mount = "/cache:/cache";

        // Запускаем контейнер с GitLab Runner
        let container_args = vec![
            "run",
            "-d",
            "--restart",
            "always",
            "--name",
            name,
            "-v",
            &config_mount,
            "-v",
            docker_sock_mount,
            "-v",
            cache_mount,
            "--network",
            "server-network",
            "gitlab/gitlab-runner:latest",
        ];

        security::execute_command_with_audit(
            "docker",
            &container_args,
            user,
            &format!("Запуск контейнера GitLab Runner {}", name),
        )
        .await?;

        // Регистрируем runner
        let register_args = vec![
            "exec",
            "-i",
            name,
            "gitlab-runner",
            "register",
            "--non-interactive",
            "--url",
            "https://gitlab.com/",
            "--registration-token",
            token,
            "--executor",
            "docker",
            "--docker-image",
            "docker:stable",
            "--description",
            name,
            "--docker-volumes",
            "/var/run/docker.sock:/var/run/docker.sock",
            "--docker-volumes",
            "/cache:/cache",
        ];

        security::execute_command_with_audit(
            "docker",
            &register_args,
            user,
            &format!("Регистрация GitLab Runner {}", name),
        )
        .await?;

        info!("GitLab Runner {} успешно настроен", name);
    }

    Ok(())
}
