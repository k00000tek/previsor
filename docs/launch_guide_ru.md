# PreVisor: запуск и работа в real-режиме (RU)

Цель: от клонирования репозитория дойти до первого алерта и стабильной фоновой работы.

## 0) Требования
- Windows 10/11, PowerShell.
- Python 3.12+ и Git.
- Для захвата трафика на Windows нужен Npcap (рекомендуется режим совместимости с WinPcap).
- Реальный захват трафика требует запуск PowerShell **от имени администратора**.

## 1) Установка
```powershell
git clone https://github.com/k00000tek/previsor
cd previsor
python -m venv .venv
.\.venv\Scripts\Activate
pip install -r requirements.txt
```

## 2) Telegram-уведомления
1. Бот уже создан: найдите его по имени **PreVisor notifications bot**.
2. Отправьте `/start` в личный чат или в нужную группу.
3. Укажите токен и chat_id в `.env`:
   ```ini
   TELEGRAM_BOT_TOKEN=...
   TELEGRAM_CHAT_ID=...
   PREVISOR_TELEGRAM_ENABLED=true
   ```

Подсказка, как узнать `chat_id`:
```powershell
python scripts/telegram_pairing.py --write
```

## 3) Выбор сетевого интерфейса
По умолчанию используется `PREVISOR_NET_IFACE=auto`, но в Windows лучше задать явно.

Список интерфейсов:
```powershell
Get-NetAdapter | Select-Object -ExpandProperty Name
```
Пример:
```powershell
$env:PREVISOR_NET_IFACE="Беспроводная сеть"
```

Также список можно получить через API:
```powershell
Invoke-RestMethod http://127.0.0.1:5000/interfaces
```

Если за 30 секунд нет пакетов, попробуйте сгенерировать трафик (открыть сайт или `ping 8.8.8.8 -n 5`).

## 4) Запуск приложения
Откройте PowerShell **от имени администратора** и запустите:
```powershell
python app.py
```
Проверка:
```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```

## 5) Основной пользовательский путь
1. Откройте UI: http://127.0.0.1:5000/dashboard
2. Нажмите **Запустить анализ** (или просто ждите — фоновый монитор включен по умолчанию).
3. Если нужно ускорить обучение аномалий — нажмите **Собрать базовую выборку** несколько раз.
4. Когда появятся алерты, бот пришлет уведомление в Telegram.

Параметры по умолчанию:
- `PREVISOR_AUTO_MONITOR=true`
- `PREVISOR_AUTO_MONITOR_INTERVAL=300`
- `PREVISOR_BASELINE_TARGET_ROWS=5000`
- `PREVISOR_ANOMALY_AUTO_TRAIN=true`


## 6) Контрольный прогон (от установки до алерта)
1. Запустите приложение (`python app.py`).
2. Зайдите в UI и нажмите **Запустить анализ**.
3. Сгенерируйте небольшой тестовый трафик (см. `docs/threat_emulation_ru.md`).
4. Снова нажмите **Запустить анализ** или дождитесь следующего цикла авто-монитора.
5. Проверьте Telegram — должно прийти уведомление.

## 7) Ручной запуск (если нужно)
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/analyze?mode=real&model=rf"
```

## 8) Частые вопросы
- **Почему нет записей?** Убедитесь, что интерфейс задан правильно и PowerShell запущен от администратора.
- **Почему нет `ip_cache`?** Кэш заполняется только при успешных запросах в AbuseIPDB и наличии ключа.
- **Можно ли без Celery?** Да, авто-монитор в `app.py` работает сам.

Разработческие сценарии: `docs/test_scenarios_powershell.md`.
