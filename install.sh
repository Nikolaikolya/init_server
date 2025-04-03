#!/bin/bash

# Установка необходимых пакетов
echo "Обновление системы и установка необходимых пакетов..."
sudo apt update && sudo apt upgrade -y

# Клонирование репозитория
REPO_URL="https://github.com/Nikolaikolya/init_server.git"
echo "Клонирование репозитория..."
git clone $REPO_URL
cd init_server || exit 1

# Копирование исполняемого файла в каталог bin
echo "Копирование исполняемого файла в каталог /usr/local/bin..."
sudo cp release/init_server /usr/local/bin/init_server
sudo chmod +x /usr/local/bin/init_server

# Проверка установки
echo "Проверка установки..."
init_server --help

echo "Очистка установленных пакетов..."
cargo clean

echo "Установка завершена!"