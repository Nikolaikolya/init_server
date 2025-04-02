use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::{fs, path::Path};
use tokio::process::Command;

use crate::{config, security, utils};

/// Структура для хранения информации о домене
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

/// Устанавливает Nginx через Docker
pub async fn setup_nginx(user: &str) -> Result<()> {
    info!("Настройка Nginx...");

    // Создаем необходимые директории
    for dir in &[
        config::NGINX_CONF_DIR,
        config::NGINX_LOGS_DIR,
        config::NGINX_HTML_DIR,
    ] {
        fs::create_dir_all(dir)
            .with_context(|| format!("Не удалось создать директорию: {}", dir))?;

        debug!("Создана директория: {}", dir);
    }

    // Создаем docker-compose.yml для Nginx
    let docker_compose_path = format!("{}/docker-compose.yml", config::SERVER_SETTINGS_DIR);

    let docker_compose_content = r#"version: '3'

services:
  nginx:
    image: nginx:latest
    container_name: nginx
    restart: always
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf:/etc/nginx/conf.d
      - ./nginx/logs:/var/log/nginx
      - ./nginx/html:/usr/share/nginx/html
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    networks:
      - server-network

  certbot:
    image: certbot/certbot:latest
    container_name: certbot
    restart: unless-stopped
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    depends_on:
      - nginx
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew; sleep 12h & wait $${!}; done;'"
    networks:
      - server-network

networks:
  server-network:
    external: true
"#;

    fs::write(&docker_compose_path, docker_compose_content).with_context(|| {
        format!(
            "Не удалось создать файл docker-compose.yml: {}",
            docker_compose_path
        )
    })?;

    info!("Создан файл docker-compose.yml: {}", docker_compose_path);

    // Создаем базовую конфигурацию Nginx
    let nginx_default_conf = format!("{}/default.conf", config::NGINX_CONF_DIR);

    let default_conf_content = r#"# Default Nginx configuration
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 444;
    }
}
"#;

    fs::write(&nginx_default_conf, default_conf_content).with_context(|| {
        format!(
            "Не удалось создать файл default.conf: {}",
            nginx_default_conf
        )
    })?;

    info!(
        "Создан файл базовой конфигурации Nginx: {}",
        nginx_default_conf
    );

    // Создаем тестовую страницу
    let test_html_path = format!("{}/index.html", config::NGINX_HTML_DIR);
    utils::create_test_html(&test_html_path, "localhost").await?;

    // Запускаем Docker Compose
    let output = Command::new("docker-compose")
        .args(["-f", &docker_compose_path, "up", "-d"])
        .current_dir(config::SERVER_SETTINGS_DIR)
        .output()
        .await
        .context("Не удалось запустить Docker Compose")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!("Ошибка запуска Docker Compose: {}", stderr);
        return Err(anyhow::anyhow!("Ошибка запуска Docker Compose: {}", stderr));
    }

    // Логируем событие установки Nginx
    let audit_log = security::AuditLog::new(
        "nginx_setup",
        user,
        Some("Setup Nginx with Docker Compose"),
        "success",
        None,
        None,
    );

    security::log_audit_event(audit_log, None).await?;

    info!("Nginx успешно настроен и запущен");

    Ok(())
}

/// Настраивает конфигурацию для домена с прокси
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
