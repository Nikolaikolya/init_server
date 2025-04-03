use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::{env, path::Path};
use tokio::{fs, process::Command};

/// Проверяет, установлен ли пакет в системе
pub async fn is_package_installed(package: &str) -> Result<bool> {
    let output = Command::new("dpkg")
        .args(["-s", package])
        .output()
        .await
        .with_context(|| format!("Не удалось выполнить проверку установки пакета {}", package))?;

    Ok(output.status.success())
}

/// Устанавливает пакет в системе
pub async fn install_package(package: &str) -> Result<()> {
    if is_package_installed(package).await? {
        info!("Пакет {} уже установлен", package);
        return Ok(());
    }

    info!("Установка пакета: {}", package);

    let output = Command::new("apt-get")
        .args(["install", "-y", package])
        .output()
        .await
        .with_context(|| format!("Не удалось установить пакет {}", package))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка установки пакета {}: {}", package, stderr);
        return Err(anyhow::anyhow!(
            "Ошибка установки пакета {}: {}",
            package,
            stderr
        ));
    }

    info!("Пакет {} успешно установлен", package);
    Ok(())
}

/// Выполняет обновление системы
pub async fn update_system() -> Result<()> {
    info!("Обновление списка пакетов...");

    let output = Command::new("apt-get")
        .args(["update"])
        .output()
        .await
        .with_context(|| "Не удалось выполнить apt-get update")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка обновления списка пакетов: {}", stderr);
        return Err(anyhow::anyhow!(
            "Ошибка обновления списка пакетов: {}",
            stderr
        ));
    }

    info!("Обновление системы...");

    let output = Command::new("apt-get")
        .args(["upgrade", "-y"])
        .output()
        .await
        .with_context(|| "Не удалось выполнить apt-get upgrade")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка обновления системы: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка обновления системы: {}", stderr));
    }

    info!("Система успешно обновлена");
    Ok(())
}

/// Проверяет, запущен ли процесс от имени root
pub fn is_root() -> bool {
    match env::var("USER") {
        Ok(user) => user == "root",
        Err(_) => false,
    }
}

/// Создает тестовый HTML файл для проверки настройки веб-сервера
pub async fn create_test_html(path: &str, domain: &str) -> Result<()> {
    let html_content = format!(
        r#"<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Тестовая страница</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
        h1 {{ color: #2c3e50; }}
        .container {{ max-width: 800px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
        .success {{ background-color: #d4edda; color: #155724; padding: 15px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Тестовая страница успешно загружена!</h1>
        <div class="success">
            <p>Ваш сервер успешно настроен для домена <strong>{}</strong></p>
            <p>Это тестовая страница, созданная автоматически.</p>
        </div>
    </div>
</body>
</html>"#,
        domain
    );

    // Создаем директорию, если она не существует
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Не удалось создать директорию: {:?}", parent))?;
    }

    fs::write(path, html_content)
        .await
        .with_context(|| format!("Не удалось создать тестовый HTML файл: {}", path))?;

    info!("Создан тестовый HTML файл: {}", path);
    Ok(())
}

/// Получает IP-адрес сервера
pub async fn get_server_ip() -> Result<String> {
    let output = Command::new("hostname")
        .args(["-I"])
        .output()
        .await
        .with_context(|| "Не удалось получить IP-адрес сервера")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка получения IP-адреса: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка получения IP-адреса: {}", stderr));
    }

    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Используем первый IP-адрес, если их несколько
    let first_ip = ip
        .split_whitespace()
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();

    debug!("IP-адрес сервера: {}", first_ip);
    Ok(first_ip)
}
