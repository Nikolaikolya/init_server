use std::{fs, io::ErrorKind, path::Path};

use anyhow::{Context, Result};
use log::{error, info};

use crate::security;

/// Проверяет наличие директории server-settings в домашней директории пользователя
pub async fn check_home_settings_dir(user: &str) -> Result<String> {
    let home_dir = format!("/home/{}", user);
    let settings_dir = format!("{}/server-settings", home_dir);

    // Проверяем существование директории
    match fs::metadata(&settings_dir) {
        Ok(_) => Ok(settings_dir),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Если директория не найдена в домашней директории пользователя, ищем в текущей директории
            match fs::metadata("server-settings") {
                Ok(_) => Ok("server-settings".to_string()),
                Err(e) => Err(anyhow::anyhow!(
                    "Директория server-settings не найдена: {}",
                    e
                )),
            }
        }
        Err(e) => Err(anyhow::anyhow!(
            "Ошибка проверки директории server-settings: {}",
            e
        )),
    }
}

/// Останавливает Docker контейнеры, созданные при настройке сервера
pub async fn stop_containers(settings_dir: &str, user: &str) -> Result<()> {
    info!("Останавливаем Docker контейнеры...");

    let compose_dir = format!("{}/nginx", settings_dir);
    let compose_file = format!("{}/docker-compose.yml", compose_dir);

    if Path::new(&compose_file).exists() {
        // Пытаемся остановить контейнеры с помощью docker-compose
        let result = security::execute_command_with_audit(
            "docker-compose",
            &["-f", &compose_file, "down"],
            user,
            "Остановка Docker контейнеров",
        )
        .await;

        if let Err(e) = result {
            error!(
                "Не удалось остановить контейнеры через docker-compose: {}",
                e
            );
            // Пытаемся использовать альтернативную команду
            security::execute_command_with_audit(
                "docker",
                &["stop", "nginx", "certbot"],
                user,
                "Альтернативная остановка Docker контейнеров",
            )
            .await?;
        }

        info!("Docker контейнеры успешно остановлены");
    } else {
        info!("Файл docker-compose.yml не найден, пропускаем остановку контейнеров");
    }

    Ok(())
}

/// Удаляет контейнеры GitLab Runners
pub async fn remove_gitlab_runners(settings_dir: &str, user: &str) -> Result<()> {
    info!("Удаление GitLab Runners...");

    let runners_dir = format!("{}/gitlab-runners/conf", settings_dir);
    if !Path::new(&runners_dir).exists() {
        info!("Директория GitLab Runners не найдена, пропускаем удаление");
        return Ok(());
    }

    // Получаем список контейнеров GitLab Runners
    let output = security::execute_command_with_audit(
        "docker",
        &[
            "ps",
            "-a",
            "--filter",
            "name=gitlab-runner",
            "--format",
            "{{.Names}}",
        ],
        user,
        "Получение списка контейнеров GitLab Runners",
    )
    .await?;

    // Если есть контейнеры, удаляем их
    if !output.is_empty() {
        let runner_names: Vec<&str> = output.lines().collect();

        for runner in runner_names {
            if let Err(e) = security::execute_command_with_audit(
                "docker",
                &["rm", "-f", runner],
                user,
                &format!("Удаление контейнера {}", runner),
            )
            .await
            {
                error!("Не удалось удалить контейнер {}: {}", runner, e);
            }
        }

        info!("GitLab Runners успешно удалены");
    } else {
        info!("GitLab Runners не найдены, пропускаем удаление");
    }

    Ok(())
}

/// Удаляет Docker сеть, созданную при настройке сервера
pub async fn remove_docker_network(user: &str) -> Result<()> {
    info!("Удаление Docker сети...");

    if let Err(e) = security::execute_command_with_audit(
        "docker",
        &["network", "rm", "server-network"],
        user,
        "Удаление Docker сети server-network",
    )
    .await
    {
        error!("Не удалось удалить Docker сеть: {}", e);
    } else {
        info!("Docker сеть успешно удалена");
    }

    Ok(())
}

/// Восстанавливает SSH конфигурацию из бекапа
pub async fn restore_ssh_config(user: &str) -> Result<()> {
    info!("Восстановление SSH конфигурации...");

    let ssh_config_path = "/etc/ssh/sshd_config";
    let backup_path = format!("{}.bak", ssh_config_path);

    if Path::new(&backup_path).exists() {
        // Копируем бекап обратно
        security::execute_command_with_audit(
            "cp",
            &[&backup_path, ssh_config_path],
            user,
            "Восстановление SSH конфигурации из бекапа",
        )
        .await?;

        // Перезапускаем SSH сервис
        security::execute_command_with_audit(
            "systemctl",
            &["restart", "sshd"],
            user,
            "Перезапуск SSH сервиса",
        )
        .await?;

        info!("SSH конфигурация успешно восстановлена");
    } else {
        info!("Бекап SSH конфигурации не найден, пропускаем восстановление");
    }

    Ok(())
}

/// Удаляет директории, созданные при настройке сервера
pub async fn remove_server_settings(settings_dir: &str, _user: &str) -> Result<()> {
    info!("Удаление директорий сервера...");

    if !Path::new(settings_dir).exists() {
        info!(
            "Директория {} не найдена, пропускаем удаление",
            settings_dir
        );
        return Ok(());
    }

    // Рекурсивно удаляем директорию настроек
    fs::remove_dir_all(settings_dir)
        .with_context(|| format!("Не удалось удалить директорию {}", settings_dir))?;

    info!("Директории сервера успешно удалены");

    Ok(())
}
