use std::{
    collections::HashMap,
    fs::{self, create_dir_all, File},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result};
use base64::{decode, encode};
use log::{debug, info};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Используем импорты aes-gcm более структурированно
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
// Используем OsRng из rand
use rand::rngs::OsRng;

// Константы путей настроек сервера
pub const SERVER_SETTINGS_DIR: &str = "server-settings";
pub const NGINX_CONF_DIR: &str = "nginx/conf";
pub const NGINX_LOGS_DIR: &str = "nginx/logs";
pub const NGINX_HTML_DIR: &str = "nginx/html";
pub const CERTBOT_WWW_DIR: &str = "certbot/www";
pub const CERTBOT_CONF_DIR: &str = "certbot/conf";
pub const GITLAB_RUNNER_DIR: &str = "gitlab-runners/conf";
pub const BACKUP_DIR: &str = "backups";
pub const AUDIT_DIR: &str = "audit";
pub const CONFIG_FILE: &str = "config.json";

/// Получает полный путь к директории настроек сервера
pub fn get_settings_dir(user: &str) -> String {
    format!("/home/{}/{}", user, SERVER_SETTINGS_DIR)
}

/// Получает полный путь к поддиректории в директории настроек
pub fn get_full_path(user: &str, subdir: &str) -> String {
    format!("/home/{}/{}/{}", user, SERVER_SETTINGS_DIR, subdir)
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Ошибка шифрования: {0}")]
    EncryptionError(String),
    #[error("Ошибка чтения конфигурации: {0}")]
    ReadError(String),
    #[error("Ошибка записи конфигурации: {0}")]
    WriteError(String),
    #[error("Ошибка валидации пароля: {0}")]
    PasswordValidation(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
            domains: vec![],
            admin_email: "admin@example.com".to_string(),
            packages: vec![
                "apt-transport-https".to_string(),
                "ca-certificates".to_string(),
                "curl".to_string(),
                "gnupg".to_string(),
                "lsb-release".to_string(),
                "software-properties-common".to_string(),
                "ufw".to_string(),
            ],
            package_versions: HashMap::new(),
            encryption_key: None,
            encrypt_sensitive_data: true,
            enable_firewall: true,
            allowed_ports: vec![22, 80, 443],
            docker_version: "latest".to_string(),
            nginx_version: "latest".to_string(),
            certbot_version: "latest".to_string(),
            gitlab_runners: vec!["runner-1".to_string(), "runner-2".to_string()],
            is_audit_enabled: true,
        }
    }
}

impl ServerConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            info!("Конфигурационный файл не найден, создаем по умолчанию");
            let config = Self::default();
            config.save(path)?;
            return Ok(config);
        }

        let mut file = File::open(path)
            .with_context(|| format!("Не удалось открыть файл конфигурации: {:?}", path))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .with_context(|| format!("Не удалось прочитать файл конфигурации: {:?}", path))?;

        serde_json::from_str(&contents).with_context(|| {
            format!(
                "Не удалось десериализовать конфигурацию из файла: {:?}",
                path
            )
        })
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .with_context(|| "Не удалось сериализовать конфигурацию в JSON")?;

        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Не удалось создать директорию: {:?}", parent))?;
        }

        let mut file = File::create(path)
            .with_context(|| format!("Не удалось создать файл конфигурации: {:?}", path))?;
        file.write_all(json.as_bytes())
            .with_context(|| format!("Не удалось записать в файл конфигурации: {:?}", path))?;

        info!("Конфигурация сохранена в {:?}", path);
        Ok(())
    }

    /// Шифрует строку с использованием AES-GCM
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        if !self.encrypt_sensitive_data {
            return Ok(plaintext.to_string());
        }

        let key_string = self
            .encryption_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Encryption key is not set"))?;

        // Расшифровываем ключ из base64
        let key_bytes = decode(&key_string)
            .with_context(|| "Не удалось декодировать ключ шифрования из Base64")?;

        // Преобразуем байты в ключ AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        // Создаем шифр
        let cipher = Aes256Gcm::new(key);

        // Генерируем случайный nonce
        let nonce_bytes = OsRng.gen::<[u8; 12]>(); // 96 бит
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Шифруем
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Ошибка шифрования: {}", e))?;

        // Комбинируем nonce и шифротекст для хранения
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(encode(result))
    }

    /// Дешифрует строку, зашифрованную с помощью AES-GCM
    pub fn decrypt_string(&self, encrypted: &str) -> Result<String> {
        if !self.encrypt_sensitive_data {
            return Ok(encrypted.to_string());
        }

        let key_string = self
            .encryption_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Encryption key is not set"))?;

        // Расшифровываем ключ и шифротекст из base64
        let key_bytes = decode(&key_string)
            .with_context(|| "Не удалось декодировать ключ шифрования из Base64")?;
        let all_bytes =
            decode(encrypted).with_context(|| "Не удалось декодировать Base64 данные")?;

        if all_bytes.len() < 12 {
            return Err(anyhow::anyhow!("Некорректный формат зашифрованных данных"));
        }

        // Извлекаем nonce и шифротекст
        let nonce_bytes = &all_bytes[..12];
        let ciphertext = &all_bytes[12..];

        // Преобразуем байты в ключ и nonce для AES-256-GCM
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Создаем шифр
        let cipher = Aes256Gcm::new(key);

        // Расшифровываем
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Ошибка расшифровки: {}", e))?;

        String::from_utf8(plaintext)
            .with_context(|| "Не удалось преобразовать расшифрованные данные в строку")
    }

    /// Создает директории, необходимые для работы
    pub fn create_directories(user: &str) -> Result<()> {
        let settings_dir = get_settings_dir(user);

        // Создаем основную директорию
        create_dir_all(&settings_dir)
            .with_context(|| format!("Не удалось создать директорию {}", settings_dir))?;

        // Создаем поддиректории
        let dirs = [
            get_full_path(user, NGINX_CONF_DIR),
            get_full_path(user, NGINX_LOGS_DIR),
            get_full_path(user, NGINX_HTML_DIR),
            get_full_path(user, CERTBOT_WWW_DIR),
            get_full_path(user, CERTBOT_CONF_DIR),
            get_full_path(user, GITLAB_RUNNER_DIR),
            get_full_path(user, BACKUP_DIR),
            get_full_path(user, AUDIT_DIR),
        ];

        for dir in &dirs {
            create_dir_all(dir)
                .with_context(|| format!("Не удалось создать директорию {}", dir))?;
            debug!("Создана директория: {}", dir);
        }

        Ok(())
    }

    /// Генерирует надежный пароль
    pub fn generate_strong_password(length: usize) -> Result<String> {
        if length < 8 {
            return Err(anyhow::anyhow!(
                "Длина пароля должна быть не менее 8 символов"
            ));
        }

        let mut rng = thread_rng();
        let password: String = (0..length)
            .map(|_| {
                let char_type = rng.gen_range(0..3);
                match char_type {
                    0 => rng.gen_range(b'A'..=b'Z') as char, // Прописные
                    1 => rng.gen_range(b'a'..=b'z') as char, // Строчные
                    _ => rng.gen_range(b'0'..=b'9') as char, // Цифры
                }
            })
            .collect();

        // Проверяем, что пароль содержит все необходимые типы символов
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_digit(10));

        if has_uppercase && has_lowercase && has_digit {
            Ok(password)
        } else {
            // Повторяем генерацию, если не удовлетворяет требованиям
            Self::generate_strong_password(length)
        }
    }
}
