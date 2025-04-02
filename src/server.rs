use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password};
use log::{debug, error, info, warn};
use std::{fs, path::Path};
use tokio::process::Command;

use crate::{backup, config, config::ServerConfig, docker, logger, nginx, security, utils};

/// Меняет пароль для root пользователя
async fn change_root_password(user: &str) -> Result<()> {
    info!("Смена пароля для root пользователя...");

    let password = if user == "root" {
        // Генерируем случайный пароль в автоматическом режиме
        let generated_password = ServerConfig::generate_strong_password(16);
        logger::password_info(&generated_password);

        // Сохраняем пароль в файл
        let password_file = "server-settings/root_password.txt";
        fs::write(password_file, &generated_password)
            .with_context(|| format!("Не удалось сохранить пароль в файл: {}", password_file))?;

        // Устанавливаем безопасные права на файл
        security::set_permissions(password_file, "600", user, user).await?;

        generated_password
    } else {
        // В ручном режиме запрашиваем пароль у пользователя
        let password = Password::new()
            .with_prompt("Введите новый пароль для root")
            .with_confirmation("Повторите пароль", "Пароли не совпадают")
            .interact()?;

        // Проверяем сложность пароля
        if !security::check_password_strength(&password) {
            return Err(anyhow::anyhow!("Пароль не соответствует требованиям безопасности (минимум 8 символов, прописные, строчные буквы и цифры)"));
        }

        password
    };

    // Меняем пароль для root
    let passwd_cmd = format!("echo 'root:{}' | chpasswd", password);
    let output = Command::new("sh")
        .arg("-c")
        .arg(passwd_cmd)
        .output()
        .await
        .context("Не удалось сменить пароль для root")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка смены пароля для root: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка смены пароля для root: {}", stderr));
    }

    // Логируем событие смены пароля
    let audit_log =
        security::AuditLog::new("root_password_change", user, None, "success", None, None);

    security::log_audit_event(audit_log, None).await?;

    info!("Пароль для root успешно изменен");

    Ok(())
}

/// Создает нового пользователя с правами sudo
async fn create_user(username: &str, user: &str) -> Result<String> {
    info!("Создание пользователя: {}", username);

    // Проверяем, существует ли пользователь
    let output = Command::new("id")
        .arg(username)
        .output()
        .await
        .with_context(|| {
            format!(
                "Не удалось проверить существование пользователя {}",
                username
            )
        })?;

    // Если пользователь уже существует, возвращаем ошибку
    if output.status.success() {
        info!("Пользователь {} уже существует", username);
        return Ok(username.to_string());
    }

    // Создаем пользователя
    let output = Command::new("useradd")
        .args(["-m", "-s", "/bin/bash", username])
        .output()
        .await
        .with_context(|| format!("Не удалось создать пользователя {}", username))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка создания пользователя {}: {}", username, stderr);
        return Err(anyhow::anyhow!(
            "Ошибка создания пользователя {}: {}",
            username,
            stderr
        ));
    }

    // Генерируем или запрашиваем пароль
    let password = if user == "root" {
        // Генерируем случайный пароль в автоматическом режиме
        let generated_password = ServerConfig::generate_strong_password(16);
        logger::password_info(&generated_password);

        // Сохраняем пароль в файл
        let password_file = format!("server-settings/{}_password.txt", username);
        fs::write(&password_file, &generated_password)
            .with_context(|| format!("Не удалось сохранить пароль в файл: {}", password_file))?;

        // Устанавливаем безопасные права на файл
        security::set_permissions(&password_file, "600", user, user).await?;

        generated_password
    } else {
        // В ручном режиме запрашиваем пароль у пользователя
        let password = Password::new()
            .with_prompt(format!("Введите пароль для пользователя {}", username))
            .with_confirmation("Повторите пароль", "Пароли не совпадают")
            .interact()?;

        // Проверяем сложность пароля
        if !security::check_password_strength(&password) {
            return Err(anyhow::anyhow!("Пароль не соответствует требованиям безопасности (минимум 8 символов, прописные, строчные буквы и цифры)"));
        }

        password
    };

    // Устанавливаем пароль для пользователя
    let passwd_cmd = format!("echo '{}:{}' | chpasswd", username, password);
    let output = Command::new("sh")
        .arg("-c")
        .arg(passwd_cmd)
        .output()
        .await
        .with_context(|| format!("Не удалось установить пароль для пользователя {}", username))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "Ошибка установки пароля для пользователя {}: {}",
            username, stderr
        );
        return Err(anyhow::anyhow!(
            "Ошибка установки пароля для пользователя {}: {}",
            username,
            stderr
        ));
    }

    // Добавляем пользователя в группу sudo
    let output = Command::new("usermod")
        .args(["-aG", "sudo", username])
        .output()
        .await
        .with_context(|| {
            format!(
                "Не удалось добавить пользователя {} в группу sudo",
                username
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "Ошибка добавления пользователя {} в группу sudo: {}",
            username, stderr
        );
        return Err(anyhow::anyhow!(
            "Ошибка добавления пользователя {} в группу sudo: {}",
            username,
            stderr
        ));
    }

    // Логируем событие создания пользователя
    let audit_log = security::AuditLog::new(
        "user_create",
        user,
        Some(&format!("Create user {} with sudo privileges", username)),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

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

    // Проверяем, запущен ли скрипт от имени root
    if !utils::is_root() {
        return Err(anyhow::anyhow!("Скрипт должен быть запущен от имени root"));
    }

    let confirm = if Confirm::new()
        .with_prompt(
            "Вы уверены, что хотите удалить все настройки сервера? Это действие необратимо.",
        )
        .default(false)
        .interact()?
    {
        true
    } else {
        info!("Операция отменена пользователем");
        return Ok(());
    };

    if confirm {
        // Останавливаем контейнеры
        let output = Command::new("docker-compose")
            .args([
                "-f",
                &format!("{}/docker-compose.yml", config::SERVER_SETTINGS_DIR),
                "down",
            ])
            .current_dir(config::SERVER_SETTINGS_DIR)
            .output()
            .await
            .context("Не удалось остановить контейнеры")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка остановки контейнеров: {}", stderr);
        }

        // Удаляем GitLab Runners
        let output = Command::new("docker")
            .args([
                "ps",
                "-a",
                "--filter",
                "name=gitlab-runner",
                "--format",
                "{{.Names}}",
            ])
            .output()
            .await
            .context("Не удалось получить список GitLab Runners")?;

        let runners = String::from_utf8_lossy(&output.stdout);
        for runner in runners.lines() {
            if !runner.is_empty() {
                let output = Command::new("docker")
                    .args(["rm", "-f", runner])
                    .output()
                    .await
                    .with_context(|| format!("Не удалось удалить GitLab Runner {}", runner))?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Ошибка удаления GitLab Runner {}: {}", runner, stderr);
                }
            }
        }

        // Удаляем сеть Docker
        let output = Command::new("docker")
            .args(["network", "rm", "server-network"])
            .output()
            .await
            .context("Не удалось удалить сеть Docker")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Ошибка удаления сети Docker: {}", stderr);
        }

        // Удаляем директорию с настройками
        fs::remove_dir_all(config::SERVER_SETTINGS_DIR)
            .context("Не удалось удалить директорию с настройками")?;

        // Удаляем cron-задачу для обновления сертификатов
        let cron_file = "/etc/cron.d/certbot-renewal";
        if Path::new(cron_file).exists() {
            fs::remove_file(cron_file)
                .with_context(|| format!("Не удалось удалить файл: {}", cron_file))?;
        }

        // Восстанавливаем конфигурацию SSH
        let sshd_config_path = "/etc/ssh/sshd_config";
        let backup_path = format!("server-settings/backups/sshd_config_*");

        let output = Command::new("ls")
            .args(["-t", &backup_path])
            .output()
            .await
            .context("Не удалось найти бекап файла sshd_config")?;

        let backups = String::from_utf8_lossy(&output.stdout);
        if let Some(newest_backup) = backups.lines().next() {
            if !newest_backup.is_empty() {
                fs::copy(newest_backup, sshd_config_path).with_context(|| {
                    format!(
                        "Не удалось восстановить файл sshd_config из бекапа: {}",
                        newest_backup
                    )
                })?;

                let output = Command::new("systemctl")
                    .args(["restart", "sshd"])
                    .output()
                    .await
                    .context("Не удалось перезапустить службу SSH")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Ошибка перезапуска службы SSH: {}", stderr);
                }
            }
        }

        info!("Удаление настроек сервера успешно завершено");
    }

    Ok(())
}
