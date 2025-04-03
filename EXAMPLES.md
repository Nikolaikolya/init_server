# Примеры использования утилиты настройки сервера

Ниже приведены примеры команд для разных сценариев использования утилиты настройки сервера Ubuntu 24.

## Базовая настройка сервера

```bash
# Интерактивный режим (задаются вопросы пользователю)
sudo init_server

# Автоматический режим с параметрами по умолчанию
sudo init_server -auto
```

## Создание пользователя и настройка SSH

```bash
# Создание пользователя admin и использование SSH-ключа
sudo init_server -auto -user admin -ssh-key "ssh-rsa AAAA..."

# Создание пользователя developer
sudo init_server -auto -user developer
```

## Настройка веб-сервера

```bash
# Настройка только для IP (без доменов)
sudo init_server -auto -ip-only

# Настройка с доменами (ввод доменов будет запрошен интерактивно)
sudo init_server
```

## Настройка GitLab Runners

```bash
# Настройка с GitLab Runners
sudo init_server -auto -setup-runners

# Полная автоматическая настройка
sudo init_server -auto -user admin -ssh-key "ssh-rsa AAAA..." -setup-runners
```

## Удаление настроек

```bash
# Удаление всех настроек сервера
sudo init_server uninstall
```

## Пример интерактивного ввода для доменов

При запросе доменов в интерактивном режиме, используйте следующие форматы:

```
# Прокси на порт 8080
example.com:8080

# Статические файлы
static.example.com:static

# Несколько доменов, разделенных запятыми
example.com:8080, blog.example.com:static, api.example.com:3000
```

## Настройка брандмауэра

Брандмауэр (UFW) настраивается автоматически, разрешая порты 22 (SSH), 80 (HTTP) и 443 (HTTPS).
Если вам нужны дополнительные порты, настройте их вручную после установки:

```bash
# Разрешить дополнительный порт
sudo ufw allow 8080
```

## Проверка установленных компонентов

```bash
# Проверка статуса Docker
sudo systemctl status docker

# Проверка запущенных контейнеров
sudo docker ps

# Проверка статуса брандмауэра
sudo ufw status verbose

# Проверка настроек Nginx
sudo docker exec -it nginx nginx -t
``` 