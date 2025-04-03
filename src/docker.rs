use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::path::Path;
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

/// Создает сеть Docker с указанным именем
pub async fn create_docker_network(network_name: &str, user: &str) -> Result<()> {
    info!("Создание Docker сети: {}", network_name);

    // Проверяем, существует ли сеть
    let output = Command::new("docker")
        .args([
            "network",
            "ls",
            "--filter",
            &format!("name={}", network_name),
            "--format",
            "{{.Name}}",
        ])
        .output()
        .await
        .with_context(|| format!("Не удалось проверить наличие сети {}", network_name))?;

    let networks = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if networks.contains(network_name) {
        info!("Сеть {} уже существует", network_name);
        return Ok(());
    }

    // Создаем новую сеть
    let output = Command::new("docker")
        .args(["network", "create", network_name])
        .output()
        .await
        .with_context(|| format!("Не удалось создать сеть {}", network_name))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка создания сети: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка создания сети: {}", stderr));
    }

    // Логируем событие создания сети
    let audit_log = security::AuditLog::new(
        "docker_network_create",
        user,
        Some(&format!("docker network create {}", network_name)),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Сеть {} успешно создана", network_name);

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

/// Создает и запускает GitLab Runners
pub async fn setup_gitlab_runners(
    runner_names: &[String],
    registration_token: &str,
    user: &str,
) -> Result<()> {
    info!("Настройка GitLab Runners...");

    // Создаем директорию для конфигурации
    let config_dir = config::get_full_path(user, config::GITLAB_RUNNER_DIR);
    fs::create_dir_all(&config_dir)
        .await
        .context("Не удалось создать директорию для конфигурации GitLab Runners")?;

    for runner_name in runner_names {
        info!("Настройка GitLab Runner: {}", runner_name);

        let runner_config_dir = format!("{}/{}", config_dir, runner_name);
        fs::create_dir_all(&runner_config_dir)
            .await
            .with_context(|| {
                format!(
                    "Не удалось создать директорию для конфигурации GitLab Runner {}",
                    runner_name
                )
            })?;

        // Запуск GitLab Runner в Docker
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                runner_name,
                "--restart",
                "always",
                "-v",
                &format!("{}:/etc/gitlab-runner", runner_config_dir),
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                "/cache:/cache",
                "gitlab/gitlab-runner:latest",
            ])
            .output()
            .await
            .with_context(|| format!("Не удалось запустить GitLab Runner {}", runner_name))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("Ошибка запуска GitLab Runner {}: {}", runner_name, stderr);
            return Err(anyhow::anyhow!(
                "Ошибка запуска GitLab Runner {}: {}",
                runner_name,
                stderr
            ));
        }

        // Регистрация GitLab Runner
        let output = Command::new("docker")
            .args([
                "exec",
                runner_name,
                "gitlab-runner",
                "register",
                "--non-interactive",
                "--url",
                "https://gitlab.com/",
                "--registration-token",
                registration_token,
                "--executor",
                "docker",
                "--docker-image",
                "alpine:latest",
                "--description",
                runner_name,
                "--tag-list",
                "docker,linux",
                "--run-untagged",
                "--locked=false",
            ])
            .output()
            .await
            .with_context(|| {
                format!("Не удалось зарегистрировать GitLab Runner {}", runner_name)
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Ошибка регистрации GitLab Runner {}: {}",
                runner_name, stderr
            );
            return Err(anyhow::anyhow!(
                "Ошибка регистрации GitLab Runner {}: {}",
                runner_name,
                stderr
            ));
        }

        info!("GitLab Runner {} успешно настроен", runner_name);
    }

    info!("Все GitLab Runners успешно настроены");

    Ok(())
}
