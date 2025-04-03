#!/bin/bash

# Сборка проекта
echo "Сборка проекта..."
cargo build --release

# Перемещение исполняемого файла в каталог release
mv target/release/init_server release/