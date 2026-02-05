# Эмуляция тестовых угроз (RU)

Важно: выполняйте тесты **только на своем ПК и в своей сети**. Не сканируйте внешние адреса без разрешения.

Перед тестом:
- `python app.py` запущен.
- Интерфейс выбран (`PREVISOR_NET_IFACE`).
- Для фиксации алертов запустите разовый анализ в UI или вызовите `/analyze` вручную.

Важно: в real-режиме эвристики по умолчанию учитывают только private/loopback источники и цели.
Если нужно ловить внешние адреса, установите `PREVISOR_HEURISTICS_REQUIRE_PRIVATE_SOURCE=false`.
Эмуляцию на 127.0.0.1 ловим через loopback (Npcap Loopback Adapter); если его нет, используйте IP роутера/другого устройства в LAN.

## 1) Suspicious Port (подозрительные порты)
Сделайте несколько обращений к «рискованному» порту (например, 22) на localhost.
```powershell
1..5 | ForEach-Object { Test-NetConnection -ComputerName 127.0.0.1 -Port 22 | Out-Null }
```
Ожидаемый алерт: `Suspicious Port`.

## 2) Port Scanning (сканирование портов)
Обращение ко множеству разных портов от одного источника:
```powershell
1..30 | ForEach-Object { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ | Out-Null }
```
Ожидаемый алерт: `Port Scanning`.

## 3) HTTP Anomaly (подозрительный HTTP-запрос)
Сделайте запрос с «подозрительным» шаблоном в URL:
```powershell
Invoke-WebRequest "http://127.0.0.1:5000/?q=../etc/passwd" | Out-Null
Invoke-WebRequest "http://127.0.0.1:5000/?q=union%20select" | Out-Null
```
Ожидаемый алерт: `HTTP Anomaly`.

## 4) Anomaly (IsolationForest)
Требует обученной модели аномалий и накопленного baseline.
- Накопите baseline (кнопка **Накопить baseline**) до целевого объема.
- Включите `ANOMALY_ENABLED=true`.
- Запускайте анализ в UI или через `/analyze` и смотрите алерты типа `Anomaly`.

## 5) DDoS (сложно эмулировать на одном ПК)
Для DDoS-эвристики нужны **многие источники**, что на одном ПК не воспроизводится корректно.
Если нужно, имитируйте это в лабораторной сети с несколькими машинами и разрешением.
