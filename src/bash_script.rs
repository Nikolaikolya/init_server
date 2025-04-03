// ! Модуль для генерации bash скриптов
// !
// ! Этот модуль содержит функции для создания bash скриптов, которые можно использовать
// ! для автоматизации различных задач по управлению сервером, включая начальную настройку,
// ! обновление компонентов и создание резервных копий.

use anyhow::{Context, Result};
use log::info;
use std::path::Path;
use tokio::fs;

/// Генерирует bash скрипт для автоматической настройки сервера
///
/// Создает скрипт, который устанавливает необходимые зависимости и запускает
/// утилиту bash_script с указанными параметрами для настройки сервера.
///
/// # Аргументы
///
/// * `output_path` - Путь для сохранения скрипта
/// * `auto` - Автоматический режим настройки
/// * `user` - Имя пользователя для создания
/// * `ssh_key` - SSH-ключ для добавления пользователю
/// * `ip_only` - Настройка только для IP (без доменов)
/// * `setup_runners` - Настройка GitLab Runners
///
/// # Возвращаемое значение
///
/// Возвращает `Result<()>`, который содержит `()` в случае успеха или `Error` в случае ошибки.
pub async fn generate_setup_script(
    output_path: &str,
    auto: bool,
    user: Option<&str>,
    ssh_key: Option<&str>,
    ip_only: bool,
    setup_runners: bool,
) -> Result<()> {
    info!("Генерация bash скрипта для автоматической настройки сервера...");

    // Создаем директорию для скрипта, если она не существует
    if let Some(parent) = Path::new(output_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Не удалось создать директорию {}", parent.display()))?;
        }
    }

    // Формируем аргументы командной строки
    let mut args = vec!["bash_script"];

    if auto {
        args.push("--auto");
    }

    if let Some(username) = user {
        args.push("--user");
        args.push(username);
    }

    if let Some(key) = ssh_key {
        args.push("--ssh-key");
        args.push(key);
    }

    if ip_only {
        args.push("--ip-only");
    }

    if setup_runners {
        args.push("--setup-runners");
    }

    // Добавляем команду init
    args.push("init");

    // Собираем команду запуска
    let cmd_line = args.join(" ");

    // Формируем содержимое скрипта
    let script_content = format!(
        r#"#!/bin/bash

# Автоматически сгенерированный скрипт установки сервера

# Проверка наличия прав суперпользователя
if [ "$EUID" -ne 0 ]; then
  echo "Для запуска скрипта необходимы права суперпользователя"
  exit 1
fi

# Установка необходимых зависимостей
apt-get update
apt-get install -y curl wget git

# Скачивание и установка утилиты bash_script
if [ ! -f /usr/local/bin/bash_script ]; then
    curl -sSL https://example.com/download/bash_script -o /usr/local/bin/bash_script
    chmod +x /usr/local/bin/bash_script
fi

# Запуск основного процесса настройки сервера
{command}

echo "Настройка сервера завершена"
exit 0
"#,
        command = cmd_line
    );

    // Записываем скрипт в файл
    fs::write(output_path, script_content)
        .await
        .with_context(|| format!("Не удалось записать скрипт в файл {}", output_path))?;

    // Делаем скрипт исполняемым
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(output_path)
            .await
            .with_context(|| format!("Не удалось получить метаданные файла {}", output_path))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms)
            .await
            .with_context(|| format!("Не удалось установить права на файл {}", output_path))?;
    }

    info!(
        "Bash скрипт успешно сгенерирован и сохранен в {}",
        output_path
    );
    Ok(())
}

/// Генерирует bash скрипт для автоматического обновления сервера
///
/// Создает скрипт, который обновляет пакеты системы, Docker-контейнеры и SSL-сертификаты.
///
/// # Аргументы
///
/// * `output_path` - Путь для сохранения скрипта
///
/// # Возвращаемое значение
///
/// Возвращает `Result<()>`, который содержит `()` в случае успеха или `Error` в случае ошибки.
pub async fn generate_update_script(output_path: &str) -> Result<()> {
    info!("Генерация bash скрипта для обновления сервера...");

    // Создаем директорию для скрипта, если она не существует
    if let Some(parent) = Path::new(output_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Не удалось создать директорию {}", parent.display()))?;
        }
    }

    // Формируем содержимое скрипта обновления
    let script_content = r#"#!/bin/bash

# Автоматически сгенерированный скрипт обновления сервера

# Проверка наличия прав суперпользователя
if [ "$EUID" -ne 0 ]; then
  echo "Для запуска скрипта необходимы права суперпользователя"
  exit 1
fi

# Обновление системы
echo "Обновление списка пакетов..."
apt-get update

echo "Обновление установленных пакетов..."
apt-get upgrade -y

# Обновление Docker контейнеров
if command -v docker &> /dev/null; then
    echo "Обновление Docker контейнеров..."
    
    # Остановить все контейнеры
    docker-compose -f /var/server/docker-compose.yml down 2>/dev/null || true
    
    # Обновить образы
    docker-compose -f /var/server/docker-compose.yml pull
    
    # Запустить контейнеры с обновленными образами
    docker-compose -f /var/server/docker-compose.yml up -d
    
    # Удаление неиспользуемых образов
    docker image prune -af
fi

# Обновление SSL сертификатов
if [ -d "/var/server/certbot" ]; then
    echo "Обновление SSL сертификатов..."
    docker run --rm -v /var/server/certbot:/etc/letsencrypt -v /var/server/certbot-www:/var/www/certbot certbot/certbot renew
    
    # Перезапуск Nginx для применения обновленных сертификатов
    docker-compose -f /var/server/docker-compose.yml restart nginx
fi

echo "Обновление сервера успешно завершено"
exit 0
"#;

    // Записываем скрипт в файл
    fs::write(output_path, script_content)
        .await
        .with_context(|| format!("Не удалось записать скрипт в файл {}", output_path))?;

    // Делаем скрипт исполняемым
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(output_path)
            .await
            .with_context(|| format!("Не удалось получить метаданные файла {}", output_path))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms)
            .await
            .with_context(|| format!("Не удалось установить права на файл {}", output_path))?;
    }

    info!(
        "Скрипт обновления успешно сгенерирован и сохранен в {}",
        output_path
    );
    Ok(())
}

/// Генерирует bash скрипт для бэкапа сервера
///
/// Создает скрипт, который делает резервную копию конфигурации сервера,
/// включая данные Docker, настройки SSH и логи аутентификации.
///
/// # Аргументы
///
/// * `output_path` - Путь для сохранения скрипта
/// * `backup_dir` - Директория для хранения резервных копий
///
/// # Возвращаемое значение
///
/// Возвращает `Result<()>`, который содержит `()` в случае успеха или `Error` в случае ошибки.
pub async fn generate_backup_script(output_path: &str, backup_dir: &str) -> Result<()> {
    info!("Генерация bash скрипта для бэкапа сервера...");

    // Создаем директорию для скрипта, если она не существует
    if let Some(parent) = Path::new(output_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Не удалось создать директорию {}", parent.display()))?;
        }
    }

    // Формируем содержимое скрипта бэкапа
    let script_content = format!(
        r#"#!/bin/bash

# Автоматически сгенерированный скрипт бэкапа сервера

# Проверка наличия прав суперпользователя
if [ "$EUID" -ne 0 ]; then
  echo "Для запуска скрипта необходимы права суперпользователя"
  exit 1
fi

# Настройка переменных
BACKUP_DIR="{backup_dir}"
DATE=$(date +%%Y-%%m-%%d-%%H%%M)
BACKUP_FILE="$BACKUP_DIR/server-backup-$DATE.tar.gz"

# Создаем директорию для бэкапов, если она не существует
mkdir -p "$BACKUP_DIR"

# Останавливаем контейнеры перед бэкапом
if command -v docker &> /dev/null && [ -f "/var/server/docker-compose.yml" ]; then
    echo "Останавливаем Docker контейнеры..."
    docker-compose -f /var/server/docker-compose.yml stop
fi

# Создаем архив с данными сервера
echo "Создание бэкапа сервера..."
tar -czf "$BACKUP_FILE" \
    /var/server \
    /etc/ssh/sshd_config \
    /var/log/auth.log 2>/dev/null || true

# Запускаем контейнеры после бэкапа
if command -v docker &> /dev/null && [ -f "/var/server/docker-compose.yml" ]; then
    echo "Запускаем Docker контейнеры..."
    docker-compose -f /var/server/docker-compose.yml start
fi

# Удаляем старые бэкапы (оставляем только 5 последних)
echo "Удаляем старые бэкапы..."
ls -t "$BACKUP_DIR"/server-backup-*.tar.gz | tail -n +6 | xargs rm -f 2>/dev/null || true

echo "Бэкап сервера успешно создан: $BACKUP_FILE"
exit 0
"#,
        backup_dir = backup_dir
    );

    // Записываем скрипт в файл
    fs::write(output_path, script_content)
        .await
        .with_context(|| format!("Не удалось записать скрипт в файл {}", output_path))?;

    // Делаем скрипт исполняемым
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(output_path)
            .await
            .with_context(|| format!("Не удалось получить метаданные файла {}", output_path))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms)
            .await
            .with_context(|| format!("Не удалось установить права на файл {}", output_path))?;
    }

    info!(
        "Скрипт бэкапа успешно сгенерирован и сохранен в {}",
        output_path
    );
    Ok(())
}
