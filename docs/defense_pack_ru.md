# PreVisor: пакет для защиты (RU)

Цель: быстрый чек-лист готовности и список артефактов для защиты ВКР.

## 1) Чек-лист готовности
- Репозиторий актуален, `README.md` соответствует текущему состоянию.
- `.env` заполнен (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PREVISOR_NET_IFACE).
- Приложение запускается: `python app.py`.
- Работает auto-monitor (по умолчанию): `/monitor/status`.
- В real-режиме есть записи в `data/runtime/collected_traffic.csv`.
- Baseline накоплен (5000+ строк) и обучен IsolationForest.
- Отчеты по обучению в `models/runtime/last_report*.txt`.
- Telegram-уведомления приходят.
- UI отображает алерты и позволяет менять статус.

## 2) Файлы для защиты (предоставить/приложить)
- Основное описание проекта: `README.md`.
- Пользовательский путь: `docs/launch_guide_ru.md`.
- Эмуляция угроз: `docs/threat_emulation_ru.md`.
- Сценарии разработчика (PowerShell): `docs/test_scenarios_powershell.md`.
- Отчеты обучения: `models/runtime/last_report.txt`, `models/runtime/last_report_xgb.txt`.
- Артефакты моделей (при необходимости): `models/runtime/*.pkl`.
- Диаграммы PlantUML (обновленные):
  - `static/previsor_component_diagram.puml`
  - `static/previsor_deployment_diagram.puml`
  - `static/previsor_activity_diagram.puml`
  - `static/previsor_sequence_diagram.puml`
  - `static/erd.puml`
- EDA ноутбук: `notebooks/eda_additional.ipynb`.
- Логи/результаты прогонов: `results/*.txt`.

## 3) Скриншоты (рекомендуемые)
- Старт сервиса в PowerShell (лог запуска).
- `/health` и `/monitor/status` в браузере или PowerShell.
- UI /dashboard с алертами (таблица + графики).
- Telegram-уведомление об угрозе.
- Файл `models/runtime/last_report*.txt` (открылся в редакторе).
- Диаграммы PlantUML (с рендером в PNG/SVG).
- Пара визуализаций из `notebooks/eda_additional.ipynb`.

## 4) Мини-команды для фиксации результатов
```powershell
# Проверка сервиса
Invoke-RestMethod http://127.0.0.1:5000/health
Invoke-RestMethod http://127.0.0.1:5000/monitor/status

# Прогон анализа (real)
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/analyze?mode=real&model=rf"

# Проверка алертов
Invoke-RestMethod "http://127.0.0.1:5000/alerts?limit=5"
```

## 5) Рендер диаграмм PlantUML
Если нужно получить PNG/SVG, используйте любой PlantUML-рендерер и файлы из `static/`.

Готовность считаем достигнутой, когда:
- есть хотя бы 1 алерт в БД,
- Telegram прислал уведомление,
- отчеты обучения сохранены.
