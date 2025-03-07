# Fail2Ban Exporter for Prometheus

Экспортер метрик для мониторинга Fail2Ban с помощью Prometheus. Собирает информацию о заблокированных IP-адресах, статусе сервиса и версии Fail2Ban.

## Содержание
- [Описание](#описание)
- [Установка](#установка)
- [Настройка](#настройка)
- [Метрики](#метрики)
- [Примеры](#примеры)
- [Лицензия](#лицензия)

---

## Описание
Экспортер предоставляет следующие возможности:
- Отслеживание заблокированных IP-адресов для каждого jail
- Общее количество заблокированных IP
- Статус работы сервиса Fail2Ban
- Версия установленного Fail2Ban
- Самодиагностика экспортера

---

## Установка

### Требования
1. Установленный Fail2Ban
2. Права на выполнение команд:
    - `fail2ban-client`
    - `systemctl` или `pgrep`
3. Go 1.20+ (для сборки из исходников)

### Сборка из исходников
```bash
git clone https://github.com/your-repo/fail2ban_exporter.git
cd fail2ban_exporter
go build -o fail2ban_exporter
```
## Установка через пакетный менеджер (пример для Debian/Ubuntu)
```bash
wget https://github.com/your-repo/fail2ban_exporter/releases/download/v1.0.0/fail2ban_exporter_1.0.0_amd64.deb
sudo dpkg -i fail2ban_exporter_1.0.0_amd64.deb
```
## Настройка
### Параметры запуска
```bash 
./fail2ban_exporter --port 9111
```
## Права доступа
### Добавьте пользователя экспортера в группу fail2ban:
```bash 
sudo usermod -aG fail2ban fail2ban_exporter_user
```
### Для systemd создайте файл /etc/systemd/system/fail2ban_exporter.service:
```ini 
[Unit]
Description=Fail2Ban Exporter
After=network.target

[Service]
User=fail2ban_exporter
ExecStart=/usr/local/bin/fail2ban_exporter --port 9111
Restart=always

[Install]
WantedBy=multi-user.target
```
## Метрики
| МЕТРИКА                   | ТИП | ОПИСАНИЕ                               |
|---------------------------|-----|----------------------------------------|
| fail2ban_ip_banned        |Gauge| Статус блокировки IP (1 - заблокирован) |
| fail2ban_total_banned_ips |Gauge| Общее количество заблокированных IP    |
| fail2ban_service_status   |Gauge| Статус сервиса Fail2Ban (1 - работает) |
| fail2ban_version_info     |Gauge| Версия Fail2Ban (метка version)        |
| fail2ban_exporter_status  |Gauge| Статус экспортера (1 - работает)       |

## Примеры
### Prometheus конфигурация
```yaml 
scrape_configs:
  - job_name: 'fail2ban'
    static_configs:
      - targets: ['localhost:9111']
```
### Запросы в Prometheus
```promql
# Все заблокированные IP
count(fail2ban_ip_banned{state="1"})

# Топ-10 jail по блокировкам
topk(10, count by (jail) (fail2ban_ip_banned{state="1"}))
```
### Пример Grafana dashboard
```json
{
  "panels": [
    {
      "title": "Общее количество блокировок",
      "type": "stat",
      "targets": [
        {
          "expr": "fail2ban_total_banned_ips",
          "format": "time_series"
        }
      ]
    },
    {
      "title": "Заблокированные IP по jail",
      "type": "table",
      "targets": [
        {
          "expr": "fail2ban_ip_banned{state='1'}",
          "format": "table"
        }
      ]
    }
  ]
}
```
## Лицензия
MIT License

Copyright (c) 2025 @baseencode64

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.