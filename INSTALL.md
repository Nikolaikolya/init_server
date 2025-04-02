# Установка утилиты настройки сервера на Ubuntu 24

В этом руководстве описываются шаги для установки утилиты настройки сервера на Ubuntu 24.04 LTS.

## Предварительные требования

- Операционная система Ubuntu 24.04 LTS
- Права суперпользователя (root)
- Подключение к интернету

## Установка Rust (если не установлен)

```bash
# Обновление пакетов
sudo apt update
sudo apt upgrade -y

# Установка необходимых пакетов
sudo apt install -y build-essential curl git

# Установка Rust через rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Выбираем "1) Proceed with installation (default)"

# Загружаем переменные окружения Rust
source "$HOME/.cargo/env"

# Проверяем версию Rust
rustc --version
cargo --version
```

## Установка утилиты из исходного кода

### Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/username/bash_script.git
cd bash_script
```

### Шаг 2: Сборка проекта

```bash
# Сборка в режиме релиза
cargo build --release
```

### Шаг 3: Установка исполняемого файла

```bash
# Копирование исполняемого файла в каталог bin
sudo cp target/release/bash_script /usr/local/bin/init_server
sudo chmod +x /usr/local/bin/init_server
```

### Шаг 4: Проверка установки

```bash
# Проверка справки
init_server --help
```

## Альтернативная установка через Cargo

```bash
# Установка напрямую через Cargo
cargo install --path .
```

После выполнения этой команды, исполняемый файл будет доступен в `~/.cargo/bin/bash_script`.

## Получение прав суперпользователя

Утилита требует прав суперпользователя для выполнения большинства операций:

```bash
# Запуск в интерактивном режиме
sudo init_server

# Или в автоматическом режиме
sudo init_server -auto
```

## Устранение проблем

### Ошибки разрешений

Если вы столкнулись с ошибками разрешений, убедитесь, что запускаете утилиту с правами суперпользователя:

```bash
sudo init_server
```

### Ошибки зависимостей

Если возникают ошибки, связанные с отсутствующими зависимостями, установите их:

```bash
sudo apt install -y build-essential curl git apt-transport-https \
    ca-certificates gnupg lsb-release software-properties-common
```

### Логи

Лог-файлы могут быть полезны для диагностики:

```bash
# Просмотр журнала аудита
cat server-settings/audit/audit_log.json

# Просмотр логов Nginx (если установлен)
cat server-settings/nginx/logs/error.log
cat server-settings/nginx/logs/access.log
``` 