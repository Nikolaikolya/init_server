use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::{fs, path::Path};
use tokio::process::Command;

use crate::{
    config::{self, ServerConfig},
    security, utils,
};

/// Структура для хранения информации о домене
///
/// # Fields
/// * `domain` - Доменное имя
/// * `target` - Целевой адрес для проксирования или "static" для статического сайта
/// * `is_static` - Флаг статического сайта
#[derive(Debug)]
pub struct DomainConfig {
    pub domain: String,
    pub target: String,
    pub is_static: bool,
}

impl DomainConfig {
    pub fn new(domain: &str, target: &str, is_static: bool) -> Self {
        Self {
            domain: domain.to_string(),
            target: target.to_string(),
            is_static: is_static,
        }
    }

    /// Парсит конфигурацию домена из строки вида "domain:target" или "domain:static"
    pub fn from_string(config_str: &str) -> Result<Self> {
        let parts: Vec<&str> = config_str.split(':').collect();

        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Неверный формат конфигурации домена: {}",
                config_str
            ));
        }

        let domain = parts[0].trim();
        let target = parts[1].trim();

        if domain.is_empty() || target.is_empty() {
            return Err(anyhow::anyhow!(
                "Домен или цель не могут быть пустыми: {}",
                config_str
            ));
        }

        let is_static = target == "static";

        Ok(Self::new(domain, target, is_static))
    }
}

/// Настраивает Nginx для работы только с IP
///
/// Создает базовую конфигурацию Nginx без поддержки доменов и SSL,
/// настраивает логи и статические файлы
///
/// # Arguments
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка настройки
///
/// # Examples
/// ```rust
/// setup_nginx_ip_only("admin").await?;
/// ```
pub async fn setup_nginx_ip_only(user: &str) -> Result<()> {
    info!("Настройка Nginx для работы только с IP...");

    // Создаем базовую конфигурацию Nginx
    let nginx_conf = r#"
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    error_log   /var/log/nginx/error.log;

    sendfile        on;
    keepalive_timeout  65;

    server {
        listen 80;
        server_name _;

        location / {
            root   /usr/share/nginx/html;
            index  index.html index.htm;
        }

        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   /usr/share/nginx/html;
        }
    }
}
"#;

    // Создаем директории для Nginx
    let nginx_conf_dir = config::get_full_path(user, config::NGINX_CONF_DIR);
    let nginx_logs_dir = config::get_full_path(user, config::NGINX_LOGS_DIR);
    let nginx_html_dir = config::get_full_path(user, config::NGINX_HTML_DIR);

    for dir in [&nginx_conf_dir, &nginx_logs_dir, &nginx_html_dir] {
        fs::create_dir_all(dir)
            .with_context(|| format!("Не удалось создать директорию {}", dir))?;
    }

    // Записываем конфигурацию Nginx
    let nginx_conf_file = format!("{}/nginx.conf", nginx_conf_dir);
    fs::write(&nginx_conf_file, nginx_conf)
        .with_context(|| format!("Не удалось записать файл {}", nginx_conf_file))?;

    // Создаем тестовую страницу
    let test_html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Nginx!</title>
    <style>
        body {
            width: 35em;
            margin: 0 auto;
            font-family: Tahoma, Verdana, Arial, sans-serif;
        }
    </style>
</head>
<body>
    <h1>Welcome to Nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>
"#;

    let test_html_file = format!("{}/index.html", nginx_html_dir);
    fs::write(&test_html_file, test_html)
        .with_context(|| format!("Не удалось записать файл {}", test_html_file))?;

    // Создаем docker-compose.yml
    let docker_compose = format!(
        r#"version: '3'
services:
  nginx:
    image: nginx:latest
    container_name: nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - {}:/etc/nginx/nginx.conf:ro
      - {}:/usr/share/nginx/html
      - {}:/var/log/nginx
    networks:
      - server-network

networks:
  server-network:
    external: true
"#,
        nginx_conf_file, nginx_html_dir, nginx_logs_dir
    );

    let settings_dir = config::get_settings_dir(user);
    let docker_compose_path = format!("{}/docker-compose.yml", settings_dir);
    fs::write(&docker_compose_path, docker_compose)
        .with_context(|| format!("Не удалось записать файл {}", docker_compose_path))?;

    // Запускаем контейнер
    security::execute_command_with_audit(
        "docker-compose",
        &["-f", &docker_compose_path, "up", "-d"],
        user,
        "Запуск Nginx контейнера",
    )
    .await?;

    info!("Nginx успешно настроен для работы с IP");
    Ok(())
}

/// Настраивает Nginx с поддержкой доменов и SSL
///
/// # Arguments
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка настройки
///
/// # Examples
/// ```rust
/// setup_nginx("admin").await?;
/// ```
pub async fn setup_nginx(user: &str) -> Result<()> {
    info!("Настройка Nginx...");

    // Создаем необходимые директории
    let settings_dir = config::get_settings_dir(user);
    let nginx_dir = format!("{}/nginx", settings_dir);

    for dir in [
        format!("{}/conf", nginx_dir),
        format!("{}/logs", nginx_dir),
        format!("{}/html", nginx_dir),
    ] {
        fs::create_dir_all(&dir)
            .with_context(|| format!("Не удалось создать директорию {}", dir))?;
    }

    // Проверяем, запущен ли скрипт в режиме IP-only
    let config = ServerConfig::load_or_create(user)?;
    if config.domains.is_empty() {
        setup_nginx_ip_only(user).await?;
    } else {
        // ... existing nginx setup code ...
    }

    Ok(())
}

/// Настраивает конфигурацию для домена с прокси
///
/// # Arguments
/// * `domain_config` - Конфигурация домена
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка настройки
///
/// # Examples
/// ```rust
/// let config = DomainConfig::new("example.com", "localhost:8080", false);
/// configure_domain_proxy(&config, "admin").await?;
/// ```
pub async fn configure_domain_proxy(domain_config: &DomainConfig, user: &str) -> Result<()> {
    info!(
        "Настройка домена с прокси: {} -> {}",
        domain_config.domain, domain_config.target
    );

    let conf_file = format!("{}/{}.conf", config::NGINX_CONF_DIR, domain_config.domain);

    let conf_content = format!(
        r#"server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {domain};
    
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {{
        proxy_pass http://{target};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"#,
        domain = domain_config.domain,
        target = domain_config.target
    );

    fs::write(&conf_file, conf_content)
        .with_context(|| format!("Не удалось создать файл конфигурации домена: {}", conf_file))?;

    info!("Создан файл конфигурации для домена: {}", conf_file);

    Ok(())
}

/// Настраивает конфигурацию для статического домена
///
/// # Arguments
/// * `domain_config` - Конфигурация домена
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка настройки
///
/// # Examples
/// ```rust
/// let config = DomainConfig::new("example.com", "static", true);
/// configure_domain_static(&config, "admin").await?;
/// ```
pub async fn configure_domain_static(domain_config: &DomainConfig, user: &str) -> Result<()> {
    info!("Настройка статического домена: {}", domain_config.domain);

    let conf_file = format!("{}/{}.conf", config::NGINX_CONF_DIR, domain_config.domain);
    let static_dir = format!("{}/{}", config::NGINX_HTML_DIR, domain_config.domain);

    // Создаем директорию для статических файлов
    fs::create_dir_all(&static_dir)
        .with_context(|| format!("Не удалось создать директорию для статики: {}", static_dir))?;

    // Создаем тестовую страницу
    let test_html_path = format!("{}/index.html", static_dir);
    utils::create_test_html(&test_html_path, &domain_config.domain).await?;

    let conf_content = format!(
        r#"server {{
    listen 80;
    listen [::]:80;
    server_name {domain};

    location /.well-known/acme-challenge/ {{
        root /var/www/certbot;
    }}

    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {domain};
    
    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    root /usr/share/nginx/html/{domain};
    index index.html;
    
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"#,
        domain = domain_config.domain
    );

    fs::write(&conf_file, conf_content)
        .with_context(|| format!("Не удалось создать файл конфигурации домена: {}", conf_file))?;

    info!(
        "Создан файл конфигурации для статического домена: {}",
        conf_file
    );

    Ok(())
}

/// Генерирует SSL сертификат для домена
///
/// # Arguments
/// * `domain` - Доменное имя
/// * `email` - Email администратора для Let's Encrypt
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка генерации
///
/// # Examples
/// ```rust
/// generate_ssl_cert("example.com", "admin@example.com", "admin").await?;
/// ```
pub async fn generate_ssl_cert(domain: &str, email: &str, user: &str) -> Result<()> {
    info!("Генерация SSL сертификата для домена: {}", domain);

    // Перезагружаем Nginx для применения новой конфигурации
    let output = Command::new("docker")
        .args(["exec", "nginx", "nginx", "-s", "reload"])
        .output()
        .await
        .context("Не удалось перезагрузить Nginx")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка перезагрузки Nginx: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка перезагрузки Nginx: {}", stderr));
    }

    // Проверяем, существует ли уже сертификат
    let cert_path = format!("{}/live/{}/fullchain.pem", config::CERTBOT_CONF_DIR, domain);
    if Path::new(&cert_path).exists() {
        info!("Сертификат для домена {} уже существует", domain);
        return Ok(());
    }

    // Запускаем certbot для получения сертификата
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &format!("{}:/etc/letsencrypt", config::CERTBOT_CONF_DIR),
            "-v",
            &format!("{}:/var/www/certbot", config::CERTBOT_WWW_DIR),
            "certbot/certbot:latest",
            "certonly",
            "--webroot",
            "--webroot-path=/var/www/certbot",
            "--email",
            email,
            "--agree-tos",
            "--no-eff-email",
            "-d",
            domain,
        ])
        .output()
        .await
        .with_context(|| format!("Не удалось выполнить certbot для домена {}", domain))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "Ошибка получения сертификата для домена {}: {}",
            domain, stderr
        );
        return Err(anyhow::anyhow!(
            "Ошибка получения сертификата для домена {}: {}",
            domain,
            stderr
        ));
    }

    // Перезагружаем Nginx после получения сертификата
    let output = Command::new("docker")
        .args(["exec", "nginx", "nginx", "-s", "reload"])
        .output()
        .await
        .context("Не удалось перезагрузить Nginx после получения сертификата")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка перезагрузки Nginx: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка перезагрузки Nginx: {}", stderr));
    }

    // Логируем событие получения сертификата
    let audit_log = security::AuditLog::new(
        "ssl_certificate_generation",
        user,
        Some(&format!("Generate SSL certificate for domain {}", domain)),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("SSL сертификат для домена {} успешно получен", domain);

    Ok(())
}

/// Настраивает автообновление SSL сертификатов
///
/// # Arguments
/// * `user` - Имя пользователя для настройки прав доступа
///
/// # Returns
/// * `Result<()>` - Успех или ошибка настройки
///
/// # Examples
/// ```rust
/// setup_certbot_renewal("admin").await?;
/// ```
pub async fn setup_certbot_renewal(user: &str) -> Result<()> {
    info!("Настройка автообновления SSL сертификатов...");

    // Создаем cron-задачу для обновления сертификатов
    let cron_file = "/etc/cron.d/certbot-renewal";
    let cron_content = "0 */12 * * * root cd /root/server-settings && docker-compose restart certbot >/dev/null 2>&1\n";

    fs::write(cron_file, cron_content)
        .with_context(|| format!("Не удалось создать cron-задачу: {}", cron_file))?;

    // Устанавливаем правильные права на файл
    let output = Command::new("chmod")
        .args(["644", cron_file])
        .output()
        .await
        .with_context(|| format!("Не удалось установить права на файл: {}", cron_file))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Ошибка установки прав на cron-файл: {}", stderr);
    }

    // Логируем событие настройки автообновления
    let audit_log = security::AuditLog::new(
        "certbot_renewal_setup",
        user,
        Some("Setup automatic SSL certificate renewal"),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Автообновление SSL сертификатов успешно настроено");

    Ok(())
}
