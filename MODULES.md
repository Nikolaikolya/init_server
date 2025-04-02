# Структура проекта и описание модулей

В этом документе описывается структура проекта утилиты настройки сервера Ubuntu 24, включая модули, их функции и взаимодействия.

## Общая структура проекта

```
src/
├── main.rs         # Точка входа, обработка аргументов командной строки
├── server.rs       # Основные функции инициализации сервера
├── config.rs       # Работа с конфигурацией, шифрование данных
├── security.rs     # Аудит, права доступа, брандмауэр
├── backup.rs       # Создание и восстановление бэкапов
├── logger.rs       # Форматирование логов, цветовой вывод
├── utils.rs        # Вспомогательные функции
├── docker.rs       # Работа с Docker и GitLab Runners
└── nginx.rs        # Настройка веб-сервера и SSL-сертификатов
```

## Подробное описание модулей

### main.rs

Модуль `main.rs` является точкой входа в приложение. Он отвечает за:
- Парсинг аргументов командной строки с использованием библиотеки `clap`
- Инициализацию логгера
- Запуск соответствующих функций в зависимости от переданных команд и параметров

Основные структуры:
- `Cli` - структура для хранения параметров командной строки
- `Commands` - перечисление доступных команд (Init, Uninstall)

```rust
// Пример использования:
init_server -auto -user admin -ssh-key "ssh-key" -ip-only -setup-runners
init_server uninstall
```

### config.rs

Модуль `config.rs` отвечает за управление конфигурацией, а также шифрование и дешифрование чувствительных данных:

Основные компоненты:
- Константы директорий для разных компонентов системы
- Структура `ServerConfig` для хранения конфигурации
- Функции для работы с шифрованием (AES-GCM)
- Функции для генерации надежных паролей

Основные функции:
- `ServerConfig::load` - загрузка конфигурации из файла
- `ServerConfig::save` - сохранение конфигурации в файл
- `ServerConfig::encrypt_string` - шифрование строки
- `ServerConfig::decrypt_string` - дешифрование строки
- `ServerConfig::create_directories` - создание необходимых директорий
- `ServerConfig::generate_strong_password` - генерация надежного пароля

### logger.rs

Модуль `logger.rs` отвечает за инициализацию и настройку логирования:

Основные функции:
- `init` - инициализация логгера с цветными уровнями
- `command_info` - форматированный вывод информации о командах
- `success` - форматированный вывод сообщения об успехе
- `password_info` - форматированный вывод информации о пароле

### security.rs

Модуль `security.rs` отвечает за аудит, безопасность и управление доступом:

Основные компоненты:
- Структура `AuditLog` для хранения информации аудита
- Функции для работы с аудитом
- Функции для настройки брандмауэра
- Функции для проверки сложности паролей
- Функции для управления правами доступа

Основные функции:
- `log_audit_event` - запись события в журнал аудита
- `execute_command_with_audit` - выполнение команды с аудитом
- `configure_firewall` - настройка брандмауэра (UFW)
- `check_password_strength` - проверка сложности пароля
- `set_permissions` - установка прав доступа

### backup.rs

Модуль `backup.rs` отвечает за создание и управление резервными копиями:

Основные функции:
- `backup_file` - создание бэкапа файла перед изменением
- `restore_from_backup` - восстановление файла из бэкапа
- `clean_old_backups` - удаление старых бэкапов (хранение N последних)

### utils.rs

Модуль `utils.rs` содержит вспомогательные функции, используемые в разных частях приложения:

Основные функции:
- `is_package_installed` - проверка установки пакета
- `install_package` - установка пакета через apt
- `update_system` - обновление системы
- `is_root` - проверка запуска от имени root
- `create_test_html` - создание тестового HTML-файла
- `get_server_ip` - получение IP-адреса сервера

### docker.rs

Модуль `docker.rs` отвечает за установку и настройку Docker и GitLab Runners:

Основные функции:
- `install_docker` - установка Docker и Docker Compose
- `create_docker_network` - создание Docker-сети
- `cleanup_containers` - очистка неиспользуемых контейнеров
- `setup_gitlab_runners` - настройка GitLab Runners

### nginx.rs

Модуль `nginx.rs` отвечает за настройку веб-сервера Nginx и управление SSL-сертификатами:

Основные компоненты:
- Структура `DomainConfig` для хранения информации о домене
- Функции для настройки Nginx в Docker
- Функции для настройки доменов
- Функции для генерации SSL-сертификатов

Основные функции:
- `setup_nginx` - настройка Nginx через Docker
- `configure_domain_proxy` - настройка прокси для домена
- `configure_domain_static` - настройка статического домена
- `generate_ssl_cert` - генерация SSL-сертификата
- `setup_certbot_renewal` - настройка автообновления сертификатов

### server.rs

Модуль `server.rs` содержит основные функции для инициализации и управления сервером:

Основные функции:
- `change_root_password` - изменение пароля root
- `create_user` - создание пользователя с правами sudo
- `setup_ssh_access` - настройка SSH-доступа
- `setup_domains` - настройка доменов
- `setup_runners` - настройка GitLab Runners
- `init_server` - инициализация сервера (основная функция)
- `uninstall_server` - удаление настроек сервера

## Взаимодействие между модулями

1. `main.rs` парсит аргументы командной строки и вызывает `server.rs` для инициализации или удаления сервера
2. `server.rs` координирует весь процесс настройки, вызывая функции из других модулей
3. `config.rs` предоставляет конфигурацию и управление данными
4. `logger.rs` обеспечивает логирование происходящих процессов
5. `security.rs` обеспечивает аудит и безопасность операций
6. `backup.rs` управляет резервными копиями файлов
7. `utils.rs` предоставляет вспомогательные функции для работы
8. `docker.rs` отвечает за установку и настройку Docker-компонентов
9. `nginx.rs` отвечает за настройку веб-сервера и SSL-сертификатов

## Диаграмма зависимостей

```
              +------------+
              |   main.rs  |
              +-----+------+
                    |
                    v
              +------------+
              | server.rs  |
              +-----+------+
                    |
          +---------+---------+
          |         |         |
          v         v         v
  +------------+  +---------+  +------------+
  | docker.rs  |  | nginx.rs|  | security.rs|
  +-----+------+  +----+----+  +------+-----+
        |              |              |
        |              |              |
        v              v              v
  +------------+  +---------+  +------------+
  |  utils.rs  |  | config.rs|  |  backup.rs |
  +------------+  +---------+  +------------+
        ^              ^              ^
        |              |              |
        +--------------+--------------+
                       |
                       v
                  +---------+
                  |logger.rs|
                  +---------+
```

## Структуры данных

### ServerConfig

```rust
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
```

### DomainConfig

```rust
pub struct DomainConfig {
    pub domain: String,
    pub target: String,
    pub is_static: bool,
}
```

### AuditLog

```rust
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
``` 