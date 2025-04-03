use crate::config;
use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use tokio::process::Command;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: DateTime<Local>,
    pub action: String,
    pub user: String,
    pub command: Option<String>,
    pub status: String,
    pub details: Option<String>,
    pub ip_address: Option<String>,
}

impl AuditLog {
    pub fn new(
        action: &str,
        user: &str,
        command: Option<&str>,
        status: &str,
        details: Option<&str>,
        ip_address: Option<&str>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Local::now(),
            action: action.to_string(),
            user: user.to_string(),
            command: command.map(|s| s.to_string()),
            status: status.to_string(),
            details: details.map(|s| s.to_string()),
            ip_address: ip_address.map(|s| s.to_string()),
        }
    }
}

/// Записывает информацию аудита в журнал
pub async fn log_audit_event(audit_log: AuditLog, log_file: Option<&Path>) -> Result<()> {
    let audit_path = if let Some(file) = log_file {
        file.to_path_buf()
    } else {
        let settings_path = config::get_full_path(&audit_log.user, config::AUDIT_DIR);
        std::path::PathBuf::from(format!("{}/audit_log.json", settings_path))
    };

    // Создаем директорию для аудита, если она не существует
    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Не удалось создать директорию для аудита: {:?}", parent))?;
    }

    let log_json =
        serde_json::to_string(&audit_log).with_context(|| "Не удалось сериализовать лог аудита")?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .with_context(|| format!("Не удалось открыть файл журнала аудита: {:?}", audit_path))?;

    writeln!(file, "{}", log_json).with_context(|| "Не удалось записать лог аудита в файл")?;

    debug!("Записан аудит: {} - {}", audit_log.action, audit_log.status);

    Ok(())
}

/// Выполняет команду и записывает её в аудит
pub async fn execute_command_with_audit(
    command: &str,
    args: &[&str],
    user: &str,
    action_description: &str,
) -> Result<String> {
    let full_command = format!("{} {}", command, args.join(" "));

    info!("Выполнение команды: {}", full_command);

    // Выполняем команду
    let output = Command::new(command)
        .args(args)
        .output()
        .await
        .with_context(|| format!("Не удалось выполнить команду: {}", full_command))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_status = output.status.code().unwrap_or(-1);

    let status = if output.status.success() {
        "success"
    } else {
        "error"
    };
    let details = if stderr.is_empty() {
        None
    } else {
        Some(stderr.as_str())
    };

    // Логируем результат выполнения команды
    let audit_log = AuditLog::new(
        action_description,
        user,
        Some(&full_command),
        status,
        details,
        None,
    );

    log_audit_event(audit_log, None).await?;

    if !output.status.success() {
        error!(
            "Команда завершилась с ошибкой (код {}): {}",
            exit_status, stderr
        );
        return Err(anyhow::anyhow!("Ошибка выполнения команды: {}", stderr));
    }

    debug!("Команда успешно выполнена: {}", full_command);

    Ok(stdout)
}

/// Настраивает брандмауэр UFW
pub async fn configure_firewall(ports: &[u16], user: &str) -> Result<()> {
    // Разрешаем SSH по умолчанию
    execute_command_with_audit(
        "ufw",
        &["allow", "ssh"],
        user,
        "Настройка UFW: Разрешение SSH",
    )
    .await?;

    // Разрешаем указанные порты
    for port in ports {
        let port_str = port.to_string();
        execute_command_with_audit(
            "ufw",
            &["allow", &port_str],
            user,
            &format!("Настройка UFW: Разрешение порта {}", port),
        )
        .await?;
    }

    // Включаем фаервол
    execute_command_with_audit(
        "ufw",
        &["--force", "enable"],
        user,
        "Включение фаервола UFW",
    )
    .await?;

    // Проверяем статус
    let status =
        execute_command_with_audit("ufw", &["status", "verbose"], user, "Проверка статуса UFW")
            .await?;

    info!("Настройка брандмауэра UFW успешно завершена");
    debug!("Статус UFW:\n{}", status);

    Ok(())
}

/// Проверяет сложность пароля
/// Пароль должен содержать минимум 8 символов, прописные и строчные буквы и цифры
pub fn check_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(anyhow::anyhow!(
            "Пароль должен содержать не менее 8 символов"
        ));
    }

    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));

    if !has_uppercase {
        return Err(anyhow::anyhow!("Пароль должен содержать прописные буквы"));
    }

    if !has_lowercase {
        return Err(anyhow::anyhow!("Пароль должен содержать строчные буквы"));
    }

    if !has_digit {
        return Err(anyhow::anyhow!("Пароль должен содержать цифры"));
    }

    Ok(())
}

/// Хеширует пароль для использования в /etc/shadow
pub fn hash_password(password: &str) -> Result<String> {
    // Для Windows версии просто возвращаем временный хеш (в продакшене будет работать на Linux)
    #[cfg(target_os = "windows")]
    {
        // Эмулируем хеш на Windows для тестирования
        Ok(format!("$6$temp_hash${}", password))
    }

    // Полная реализация для Linux
    #[cfg(not(target_os = "windows"))]
    {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };

        // Генерируем соль
        let salt = SaltString::generate(&mut OsRng);

        // Хешируем пароль с использованием Argon2
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Не удалось хешировать пароль: {}", e))?
            .to_string();

        Ok(password_hash)
    }
}

/// Установка прав доступа на файл/директорию
pub async fn set_permissions(path: &str, permissions: &str, user: &str, group: &str) -> Result<()> {
    // Изменение прав доступа
    execute_command_with_audit(
        "chmod",
        &[permissions, path],
        user,
        &format!("Установка прав доступа {} на {}", permissions, path),
    )
    .await?;

    // Изменение владельца
    execute_command_with_audit(
        "chown",
        &[&format!("{}:{}", user, group), path],
        user,
        &format!("Изменение владельца на {}:{} для {}", user, group, path),
    )
    .await?;

    info!("Установлены права доступа для {}", path);

    Ok(())
}
