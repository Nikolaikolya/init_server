use std::{
    fs::{self, File},
    io::ErrorKind,
    path::Path,
    process::Stdio,
};

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password};
use log::{debug, error, info, warn};
use tokio::process::Command;

use crate::{backup, config, config::ServerConfig, docker, logger, nginx, security, utils};

// Модуль для логики удаления сервера
mod uninstall_helpers {
    use super::*;

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
}

/// Изменяет пароль для пользователя root
async fn change_root_password(user: &str) -> Result<()> {
    info!("Изменение пароля для root пользователя...");

    // Проверяем, запущен ли скрипт от имени root
    if !utils::is_root() {
        return Err(anyhow::anyhow!("Скрипт должен быть запущен от имени root"));
    }

    // Автоматически генерируем надежный пароль в автоматическом режиме
    // Определяем, запущены ли мы в автоматическом режиме
    let is_auto_mode = user == "root";

    let password = if is_auto_mode {
        // В автоматическом режиме генерируем пароль
        let generated_password = ServerConfig::generate_strong_password(12)?;

        logger::password_info(&format!(
            "Сгенерирован надежный пароль для root: {}",
            &generated_password
        ));

        // Пишем пароль в файл для дальнейшего использования
        let password_file = "root_password.txt";
        fs::write(password_file, &generated_password)
            .with_context(|| format!("Не удалось записать пароль в файл {}", password_file))?;

        info!("Пароль root сохранен в файле {}", password_file);

        generated_password
    } else {
        // В ручном режиме запрашиваем пароль у пользователя
        let mut password = String::new();
        loop {
            password = Password::new()
                .with_prompt("Введите новый пароль для root (или оставьте пустым для генерации)")
                .allow_empty_password(true)
                .interact()?;

            if password.is_empty() {
                password = ServerConfig::generate_strong_password(12)?;
                logger::password_info(&format!("Сгенерирован надежный пароль: {}", &password));
                break;
            }

            // Проверяем надежность пароля
            if let Err(e) = security::check_password_strength(&password) {
                error!("Пароль не соответствует требованиям: {}", e);
                continue;
            }

            // Просим подтвердить пароль
            let confirmation = Password::new()
                .with_prompt("Подтвердите пароль")
                .interact()?;

            if password != confirmation {
                error!("Пароли не совпадают, попробуйте еще раз");
                continue;
            }

            break;
        }

        password
    };

    // Устанавливаем пароль для root
    let shadow_hash = security::hash_password(&password)?;
    security::execute_command_with_audit(
        "usermod",
        &["-p", &shadow_hash, "root"],
        "root",
        "Изменение пароля root пользователя",
    )
    .await?;

    info!("Пароль для root пользователя успешно изменен");

    Ok(())
}

/// Создает нового пользователя с правами sudo
async fn create_user(username: &str, user: &str) -> Result<String> {
    info!("Создание пользователя {}...", username);

    // Проверяем существование пользователя
    let user_exists = security::execute_command_with_audit(
        "id",
        &["-u", username],
        user,
        &format!("Проверка существования пользователя {}", username),
    )
    .await
    .is_ok();

    if user_exists {
        info!("Пользователь {} уже существует", username);
        return Ok(username.to_string());
    }

    // Создаем пользователя
    security::execute_command_with_audit(
        "useradd",
        &["-m", "-s", "/bin/bash", username],
        user,
        &format!("Создание пользователя {}", username),
    )
    .await?;

    // Определяем, запущены ли мы в автоматическом режиме
    let is_auto_mode = user == "root";

    // Устанавливаем пароль для пользователя
    let password = if is_auto_mode {
        // В автоматическом режиме генерируем пароль
        let generated_password = ServerConfig::generate_strong_password(12)?;

        logger::password_info(&format!(
            "Сгенерирован надежный пароль для {}: {}",
            username, &generated_password
        ));

        // Пишем пароль в файл для дальнейшего использования
        let password_file = format!("{}_password.txt", username);
        fs::write(&password_file, &generated_password)
            .with_context(|| format!("Не удалось записать пароль в файл {}", password_file))?;

        info!(
            "Пароль пользователя {} сохранен в файле {}",
            username, password_file
        );

        generated_password
    } else {
        // В ручном режиме запрашиваем пароль у пользователя
        let mut password = String::new();
        loop {
            password = Password::new()
                .with_prompt(&format!(
                    "Введите пароль для {} (или оставьте пустым для генерации)",
                    username
                ))
                .allow_empty_password(true)
                .interact()?;

            if password.is_empty() {
                password = ServerConfig::generate_strong_password(12)?;
                logger::password_info(&format!("Сгенерирован надежный пароль: {}", &password));
                break;
            }

            // Проверяем надежность пароля
            if let Err(e) = security::check_password_strength(&password) {
                error!("Пароль не соответствует требованиям: {}", e);
                continue;
            }

            // Просим подтвердить пароль
            let confirmation = Password::new()
                .with_prompt("Подтвердите пароль")
                .interact()?;

            if password != confirmation {
                error!("Пароли не совпадают, попробуйте еще раз");
                continue;
            }

            break;
        }

        password
    };

    // Устанавливаем пароль для пользователя
    let shadow_hash = security::hash_password(&password)?;
    security::execute_command_with_audit(
        "usermod",
        &["-p", &shadow_hash, username],
        user,
        &format!("Установка пароля для пользователя {}", username),
    )
    .await?;

    // Добавляем пользователя в группу sudo
    security::execute_command_with_audit(
        "usermod",
        &["-aG", "sudo", username],
        user,
        &format!("Добавление пользователя {} в группу sudo", username),
    )
    .await?;

    info!(
        "Пользователь {} успешно создан и добавлен в группу sudo",
        username
    );

    Ok(username.to_string())
}

/// Настраивает SSH доступ для пользователя
async fn setup_ssh_access(username: &str, ssh_key: Option<&str>, user: &str) -> Result<()> {
    info!("Настройка SSH доступа для пользователя {}...", username);

    // Создаем бекап файла sshd_config
    let sshd_config_path = "/etc/ssh/sshd_config";
    backup::backup_file(sshd_config_path).await?;

    // Читаем текущий конфиг
    let sshd_config = fs::read_to_string(sshd_config_path)
        .with_context(|| format!("Не удалось прочитать файл: {}", sshd_config_path))?;

    // Модифицируем параметры
    let mut new_config = String::new();
    let mut permit_root_login_set = false;
    let mut password_auth_set = false;
    let mut pubkey_auth_set = false;

    for line in sshd_config.lines() {
        if line.starts_with("PermitRootLogin") {
            new_config.push_str("PermitRootLogin no\n");
            permit_root_login_set = true;
        } else if line.starts_with("PasswordAuthentication") {
            new_config.push_str("PasswordAuthentication no\n");
            password_auth_set = true;
        } else if line.starts_with("PubkeyAuthentication") {
            new_config.push_str("PubkeyAuthentication yes\n");
            pubkey_auth_set = true;
        } else if line.starts_with("AuthorizedKeysFile") {
            new_config.push_str("AuthorizedKeysFile .ssh/authorized_keys\n");
        } else {
            new_config.push_str(line);
            new_config.push('\n');
        }
    }

    // Добавляем отсутствующие параметры
    if !permit_root_login_set {
        new_config.push_str("PermitRootLogin no\n");
    }
    if !password_auth_set {
        new_config.push_str("PasswordAuthentication no\n");
    }
    if !pubkey_auth_set {
        new_config.push_str("PubkeyAuthentication yes\n");
    }

    // Записываем новый конфиг
    fs::write(sshd_config_path, new_config)
        .with_context(|| format!("Не удалось записать файл: {}", sshd_config_path))?;

    // Создаем .ssh директорию для пользователя
    let ssh_dir = format!("/home/{}/.ssh", username);
    fs::create_dir_all(&ssh_dir)
        .with_context(|| format!("Не удалось создать директорию: {}", ssh_dir))?;

    // Добавляем SSH ключ, если он предоставлен
    if let Some(key) = ssh_key {
        let auth_keys_file = format!("{}/authorized_keys", ssh_dir);
        fs::write(&auth_keys_file, key)
            .with_context(|| format!("Не удалось записать SSH ключ в файл: {}", auth_keys_file))?;

        info!("SSH ключ добавлен для пользователя {}", username);
    } else if user != "root" {
        // В ручном режиме запрашиваем SSH ключ
        let ssh_key = Input::<String>::new()
            .with_prompt("Введите публичный SSH ключ для пользователя")
            .allow_empty(true)
            .interact()?;

        if !ssh_key.is_empty() {
            let auth_keys_file = format!("{}/authorized_keys", ssh_dir);
            fs::write(&auth_keys_file, ssh_key).with_context(|| {
                format!("Не удалось записать SSH ключ в файл: {}", auth_keys_file)
            })?;

            info!("SSH ключ добавлен для пользователя {}", username);
        } else {
            warn!("SSH ключ не предоставлен, доступ по паролю будет отключен!");
        }
    }

    // Устанавливаем правильные права на .ssh директорию и файлы
    security::set_permissions(&ssh_dir, "700", username, username).await?;
    let auth_keys_file = format!("{}/authorized_keys", ssh_dir);
    if Path::new(&auth_keys_file).exists() {
        security::set_permissions(&auth_keys_file, "600", username, username).await?;
    }

    // Перезапускаем SSH службу
    let output = Command::new("systemctl")
        .args(["restart", "sshd"])
        .output()
        .await
        .context("Не удалось перезапустить службу SSH")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка перезапуска службы SSH: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка перезапуска службы SSH: {}", stderr));
    }

    // Логируем событие настройки SSH
    let audit_log = security::AuditLog::new(
        "ssh_setup",
        user,
        Some(&format!("Setup SSH access for user {}", username)),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("SSH доступ успешно настроен для пользователя {}", username);

    Ok(())
}

/// Настраивает домены для Nginx
async fn setup_domains(
    domains: &[String],
    admin_email: &str,
    ip_only: bool,
    user: &str,
) -> Result<()> {
    if ip_only {
        info!("Настройка с использованием только IP-адреса (без доменов)");
        return Ok(());
    }

    info!("Настройка доменов для Nginx...");

    if domains.is_empty() {
        warn!("Список доменов пуст, пропускаем настройку");
        return Ok(());
    }

    for domain_str in domains {
        let domain_config = nginx::DomainConfig::from_string(domain_str)
            .with_context(|| format!("Неверный формат конфигурации домена: {}", domain_str))?;

        if domain_config.is_static {
            nginx::configure_domain_static(&domain_config, user).await?;
        } else {
            nginx::configure_domain_proxy(&domain_config, user).await?;
        }

        // Генерируем SSL сертификат для домена
        nginx::generate_ssl_cert(&domain_config.domain, admin_email, user).await?;
    }

    // Настраиваем автоматическое обновление сертификатов
    nginx::setup_certbot_renewal(user).await?;

    // Логируем событие настройки доменов
    let audit_log = security::AuditLog::new(
        "domains_setup",
        user,
        Some(&format!("Setup domains: {}", domains.join(", "))),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Домены успешно настроены");

    Ok(())
}

/// Настраивает GitLab Runners
async fn setup_runners(names: &[String], user: &str) -> Result<()> {
    if names.is_empty() {
        info!("Список GitLab Runners пуст, пропускаем настройку");
        return Ok(());
    }

    let token = if user == "root" {
        // В автоматическом режиме используем токен из конфига
        let config = ServerConfig::default();
        "default_token".to_string() // Здесь должен быть токен из конфига
    } else {
        // В ручном режиме запрашиваем токен у пользователя
        Input::<String>::new()
            .with_prompt("Введите токен регистрации GitLab Runner")
            .interact()?
    };

    // Настраиваем GitLab Runners
    docker::setup_gitlab_runners(names, &token, user).await?;

    Ok(())
}

/// Инициализирует сервер с заданными параметрами
pub async fn init_server(
    auto_mode: bool,
    user_name: Option<String>,
    ssh_key: Option<String>,
    ip_only: bool,
    setup_runners_enabled: bool,
) -> Result<()> {
    info!("Начало инициализации сервера...");

    // Проверяем, запущен ли скрипт от имени root
    if !utils::is_root() {
        return Err(anyhow::anyhow!("Скрипт должен быть запущен от имени root"));
    }

    // Обрабатываем ошибки и делаем откат при необходимости
    let result = try_init_server(
        auto_mode,
        user_name,
        ssh_key,
        ip_only,
        setup_runners_enabled,
    )
    .await;

    if let Err(e) = &result {
        error!("Произошла ошибка при инициализации сервера: {}", e);

        // Спрашиваем пользователя, хочет ли он откатить изменения
        if !auto_mode {
            let rollback = Confirm::new()
                .with_prompt("Произошла ошибка. Хотите откатить все изменения?")
                .default(true)
                .interact()?;

            if rollback {
                info!("Откат изменений...");
                if let Err(rollback_err) = uninstall_server().await {
                    error!("Ошибка при откате изменений: {}", rollback_err);
                } else {
                    info!("Изменения успешно откачены.");
                }
            }
        } else {
            // В автоматическом режиме делаем откат автоматически
            info!("Автоматический откат изменений...");
            if let Err(rollback_err) = uninstall_server().await {
                error!("Ошибка при откате изменений: {}", rollback_err);
            } else {
                info!("Изменения успешно откачены.");
            }
        }
    }

    result
}

// Основная функция инициализации, выделенная для обработки ошибок
async fn try_init_server(
    auto_mode: bool,
    user_name: Option<String>,
    ssh_key: Option<String>,
    ip_only: bool,
    setup_runners_enabled: bool,
) -> Result<()> {
    // Создаем необходимые директории
    ServerConfig::create_directories()?;

    // В автоматическом режиме используем переданные параметры или значения по умолчанию
    let (username, ssh_key_str) = if auto_mode {
        (
            user_name.unwrap_or_else(|| "admin".to_string()),
            ssh_key.clone(),
        )
    } else {
        // В ручном режиме запрашиваем параметры у пользователя
        let username = Input::<String>::new()
            .with_prompt("Введите имя нового пользователя")
            .default("admin".to_string())
            .interact()?;

        let ssh_key_str = Input::<String>::new()
            .with_prompt(
                "Введите публичный SSH ключ для пользователя (оставьте пустым для генерации)",
            )
            .allow_empty(true)
            .interact()
            .ok();

        (username, ssh_key_str)
    };

    // Создаем пользователя и настраиваем SSH доступ
    let user = create_user(&username, "root").await?;
    setup_ssh_access(&user, ssh_key_str.as_deref(), "root").await?;

    // Убедимся, что директории создаются в домашней директории пользователя
    let home_dir = format!("/home/{}", user);
    let settings_dir = format!("{}/server-settings", home_dir);

    // Создаем директорию server-settings в домашней директории пользователя
    fs::create_dir_all(&settings_dir)
        .with_context(|| format!("Не удалось создать директорию {}", settings_dir))?;

    // Устанавливаем правильные права доступа на директорию (только для Linux)
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&settings_dir, fs::Permissions::from_mode(0o755)).with_context(
            || {
                format!(
                    "Не удалось установить права доступа на директорию {}",
                    settings_dir
                )
            },
        )?;
    }

    // На Windows просто пропускаем установку прав
    #[cfg(not(target_os = "linux"))]
    {
        // Windows не поддерживает установку прав доступа в стиле Unix
        info!("Пропускаем установку прав доступа на директорию (не поддерживается на Windows)");
    }

    // Изменяем владельца директории
    security::execute_command_with_audit(
        "chown",
        &["-R", &format!("{}:{}", user, user), &settings_dir],
        "root",
        "Изменение владельца директории server-settings",
    )
    .await?;

    // Обновляем систему
    utils::update_system().await?;

    // Устанавливаем Docker
    docker::install_docker(&user).await?;

    // Создаем сеть Docker
    docker::create_docker_network("server-network", &user).await?;

    // Устанавливаем Nginx и Certbot
    nginx::setup_nginx(&user).await?;

    // Настраиваем домены и SSL сертификаты
    let domains = if auto_mode {
        if ip_only {
            Vec::new()
        } else {
            let config = ServerConfig::default();
            config.domains
        }
    } else {
        // В ручном режиме запрашиваем домены у пользователя
        let domains_input = Input::<String>::new()
            .with_prompt(
                "Введите домены в формате 'domain:port' или 'domain:static', разделенные запятыми",
            )
            .allow_empty(true)
            .interact()?;

        if domains_input.is_empty() {
            Vec::new()
        } else {
            domains_input
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        }
    };

    let email = if auto_mode {
        let config = ServerConfig::default();
        config.admin_email
    } else {
        // В ручном режиме запрашиваем email у пользователя
        Input::<String>::new()
            .with_prompt("Введите email администратора для SSL сертификатов")
            .default("admin@example.com".to_string())
            .interact()?
    };

    setup_domains(&domains, &email, ip_only, &user).await?;

    // Настраиваем GitLab Runners, если требуется
    if setup_runners_enabled {
        let runner_names = if auto_mode {
            let config = ServerConfig::default();
            config.gitlab_runners
        } else {
            // В ручном режиме запрашиваем имена раннеров у пользователя
            let runners_input = Input::<String>::new()
                .with_prompt("Введите имена GitLab Runners, разделенные запятыми")
                .allow_empty(true)
                .interact()?;

            if runners_input.is_empty() {
                Vec::new()
            } else {
                runners_input
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect()
            }
        };

        setup_runners(&runner_names, &user).await?;
    }

    // Настраиваем брандмауэр
    let config = ServerConfig::default();
    if config.enable_firewall {
        security::configure_firewall(&config.allowed_ports, &user).await?;
    }

    // Меняем пароль для root
    if auto_mode {
        change_root_password("root").await?;
    } else {
        let change_root_pwd = Confirm::new()
            .with_prompt("Хотите изменить пароль для root?")
            .default(false)
            .interact()?;

        if change_root_pwd {
            change_root_password(&user).await?;
        }
    }

    // Очищаем старые бекапы
    backup::clean_old_backups(5).await?;

    info!("Инициализация сервера успешно завершена!");

    Ok(())
}

/// Удаляет настройки сервера
pub async fn uninstall_server() -> Result<()> {
    info!("Начало удаления настроек сервера...");

    // Получаем подтверждение от пользователя
    let confirmed = Confirm::new()
        .with_prompt(
            "Вы уверены, что хотите удалить все настройки сервера? Это действие необратимо.",
        )
        .default(false)
        .interact()?;

    if !confirmed {
        info!("Удаление отменено");
        return Ok(());
    }

    // Определяем текущего пользователя для логирования
    let current_user = "root"; // Скрипт должен запускаться от имени root

    // Ищем директорию с настройками сервера
    let settings_dir = match uninstall_helpers::check_home_settings_dir(current_user).await {
        Ok(dir) => dir,
        Err(e) => {
            warn!("Не удалось найти директорию с настройками сервера: {}", e);
            // Используем значение по умолчанию
            "server-settings".to_string()
        }
    };

    // Останавливаем контейнеры
    if let Err(e) = uninstall_helpers::stop_containers(&settings_dir, current_user).await {
        warn!("Ошибка при остановке контейнеров: {}", e);
        // Продолжаем процесс удаления
    }

    // Удаляем GitLab Runners
    if let Err(e) = uninstall_helpers::remove_gitlab_runners(&settings_dir, current_user).await {
        warn!("Ошибка при удалении GitLab Runners: {}", e);
        // Продолжаем процесс удаления
    }

    // Удаляем Docker сеть
    if let Err(e) = uninstall_helpers::remove_docker_network(current_user).await {
        warn!("Ошибка при удалении Docker сети: {}", e);
        // Продолжаем процесс удаления
    }

    // Восстанавливаем SSH конфигурацию
    if let Err(e) = uninstall_helpers::restore_ssh_config(current_user).await {
        warn!("Ошибка при восстановлении SSH конфигурации: {}", e);
        // Продолжаем процесс удаления
    }

    // Удаляем директории с настройками
    if let Err(e) = uninstall_helpers::remove_server_settings(&settings_dir, current_user).await {
        warn!("Ошибка при удалении директорий с настройками: {}", e);
        // Продолжаем процесс удаления
    }

    info!("Удаление настроек сервера успешно завершено");

    Ok(())
}
