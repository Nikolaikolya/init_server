#!/bin/bash

# Установка необходимых пакетов
echo "Обновление системы и установка необходимых пакетов..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential curl git pkg-config libssl-dev

# Проверка установки libssl-dev
pkg-config --libs openssl

# Установка Rust через rustup
if ! command -v rustc &> /dev/null; then
    echo "Установка Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"
fi

# Проверка версии Rust
echo "Проверка версии Rust..."
rustc --version
cargo --version

# Клонирование репозитория
REPO_URL="https://github.com/Nikolaikolya/init_server.git"
echo "Клонирование репозитория..."
git clone $REPO_URL
cd init_server || exit 1

# Сборка проекта
echo "Сборка проекта..."
cargo build --release

# Копирование исполняемого файла в каталог bin
echo "Копирование исполняемого файла в каталог /usr/local/bin..."
sudo cp target/release/bash_script /usr/local/bin/init_server
sudo chmod +x /usr/local/bin/init_server

# Проверка установки
echo "Проверка установки..."
init_server --help

echo "Очистка установленных пакетов..."
cargo clean

echo "Установка завершена!"