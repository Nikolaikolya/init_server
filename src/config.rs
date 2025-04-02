use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use base64::{decode, encode};
use log::{debug, info, warn};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const SERVER_SETTINGS_DIR: &str = "server-settings";
pub const NGINX_CONF_DIR: &str = "server-settings/nginx/conf";
pub const NGINX_LOGS_DIR: &str = "server-settings/nginx/logs";
pub const NGINX_HTML_DIR: &str = "server-settings/nginx/html";
pub const CERTBOT_WWW_DIR: &str = "server-settings/certbot/www";
pub const CERTBOT_CONF_DIR: &str = "server-settings/certbot/conf";
pub const GITLAB_RUNNER_DIR: &str = "server-settings/gitlab-runners/conf";

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub log_level: String,
    pub domains: Vec<String>,
    pub admin_email: String,
    pub packages: Vec<String>,
    pub package_versions: HashMap<String, String>,
    pub encryption_key: Option<String>,
    pub encrypt_sensitive_data: bool,
    pub enable_firewall: bool,
    pub allowed_ports: Vec<u16>,
    pub docker_version: String,
    pub nginx_version: String,
    pub certbot_version: String,
    pub gitlab_runners: Vec<String>,
    pub is_audit_enabled: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            domains: Vec::new(),
            admin_email: "admin@example.com".to_string(),
            packages: vec![
                "build-essential".to_string(),
                "curl".to_string(),
                "apt-transport-https".to_string(),
                "ca-certificates".to_string(),
                "software-properties-common".to_string(),
            ],
            package_versions: HashMap::new(),
            encryption_key: None,
            encrypt_sensitive_data: true,
            enable_firewall: true,
            allowed_ports: vec![22, 80, 443],
            docker_version: "24.0.5".to_string(),
            nginx_version: "1.25".to_string(),
            certbot_version: "2.6.0".to_string(),
            gitlab_runners: Vec::new(),
            is_audit_enabled: true,
        }
    }
}

impl ServerConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config_content = fs::read_to_string(&path).with_context(|| {
            format!(
                "Не удалось прочитать файл конфигурации: {:?}",
                path.as_ref()
            )
        })?;

        let config: ServerConfig = toml::from_str(&config_content)
            .with_context(|| "Не удалось распарсить файл конфигурации")?;

        debug!("Конфигурация успешно загружена");
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let config_content = toml::to_string_pretty(self)
            .with_context(|| "Не удалось сериализовать конфигурацию")?;

        let parent_dir = path.as_ref().parent().with_context(|| {
            format!(
                "Невозможно определить родительскую директорию для {:?}",
                path.as_ref()
            )
        })?;

        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Не удалось создать директорию: {:?}", parent_dir))?;

        fs::write(&path, config_content).with_context(|| {
            format!(
                "Не удалось записать конфигурацию в файл: {:?}",
                path.as_ref()
            )
        })?;

        info!("Конфигурация успешно сохранена в {:?}", path.as_ref());
        Ok(())
    }

    /// Шифрует строку с использованием AES-GCM
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        if !self.encrypt_sensitive_data {
            return Ok(plaintext.to_string());
        }

        // Получаем или генерируем ключ шифрования
        let encryption_key = match &self.encryption_key {
            Some(key) => {
                let mut hasher = Sha256::new();
                hasher.update(key.as_bytes());
                hasher.finalize().to_vec()
            }
            None => {
                warn!("Ключ шифрования отсутствует, используем временный ключ");
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                key.to_vec()
            }
        };

        // Создаем шифр и генерируем nonce
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| anyhow::anyhow!("Ошибка инициализации шифра: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Шифрование данных
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Ошибка шифрования: {}", e))?;

        // Комбинируем nonce и шифротекст для хранения
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(encode(result))
    }

    /// Дешифрует строку, зашифрованную с помощью AES-GCM
    pub fn decrypt_string(&self, encrypted: &str) -> Result<String> {
        if !self.encrypt_sensitive_data {
            return Ok(encrypted.to_string());
        }

        // Получаем ключ шифрования
        let encryption_key = match &self.encryption_key {
            Some(key) => {
                let mut hasher = Sha256::new();
                hasher.update(key.as_bytes());
                hasher.finalize().to_vec()
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Ключ шифрования не установлен, невозможно расшифровать данные"
                ));
            }
        };

        // Создаем шифр
        let cipher = Aes256Gcm::new_from_slice(&encryption_key)
            .map_err(|e| anyhow::anyhow!("Ошибка инициализации шифра: {}", e))?;

        // Декодирование из base64
        let encrypted_data =
            decode(encrypted).with_context(|| "Не удалось декодировать Base64 данные")?;

        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Неверный формат шифрованных данных"));
        }

        // Извлекаем nonce и шифротекст
        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        // Дешифрование данных
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Ошибка дешифрования: {}", e))?;

        String::from_utf8(plaintext)
            .with_context(|| "Не удалось преобразовать расшифрованные данные в UTF-8 строку")
    }

    /// Создает директории, необходимые для работы
    pub fn create_directories() -> Result<()> {
        let dirs = [
            SERVER_SETTINGS_DIR,
            NGINX_CONF_DIR,
            NGINX_LOGS_DIR,
            NGINX_HTML_DIR,
            CERTBOT_WWW_DIR,
            CERTBOT_CONF_DIR,
            GITLAB_RUNNER_DIR,
        ];

        for dir in &dirs {
            fs::create_dir_all(dir)
                .with_context(|| format!("Не удалось создать директорию: {}", dir))?;
            debug!("Создана директория: {}", dir);
        }

        Ok(())
    }

    /// Генерирует надежный пароль
    pub fn generate_strong_password(length: usize) -> String {
        if length < 8 {
            panic!("Длина пароля должна быть не менее 8 символов");
        }

        let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let charset_bytes = charset.as_bytes();
        let mut rng = OsRng;

        let mut password = String::with_capacity(length);

        let mut has_uppercase = false;
        let mut has_lowercase = false;
        let mut has_digit = false;

        for _ in 0..length {
            let idx = (rng.next_u32() as usize) % charset_bytes.len();
            let ch = charset_bytes[idx] as char;

            if ch.is_uppercase() {
                has_uppercase = true;
            }
            if ch.is_lowercase() {
                has_lowercase = true;
            }
            if ch.is_digit(10) {
                has_digit = true;
            }

            password.push(ch);
        }

        // Если не соответствует требованиям, генерируем заново
        if !has_uppercase || !has_lowercase || !has_digit {
            return Self::generate_strong_password(length);
        }

        password
    }
}
