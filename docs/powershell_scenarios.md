# Сценарии тестирования PreVisor (PowerShell)

## Предварительно
- Приложение запущено: `python app.py`
- Для `mode=real`: PowerShell от имени администратора и задан `PREVISOR_NET_IFACE`
- Внутренние режимы demo/test/dataset скрыты в UI, но доступны через API

## Как найти PREVISOR_NET_IFACE (Windows)
```powershell
Get-NetAdapter | Select-Object -ExpandProperty Name
```
Пример:
```powershell
$env:PREVISOR_NET_IFACE="Ethernet"
```

## API список интерфейсов
```powershell
Invoke-RestMethod http://127.0.0.1:5000/interfaces
```


## 1) Health check
```powershell
Invoke-RestMethod http://127.0.0.1:5000/health
```


## 1.1) Старт/стоп мониторинга
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/monitor/start"
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/monitor/stop"
Invoke-RestMethod "http://127.0.0.1:5000/monitor/status"
```
## 2) Demo запуск (без файла)
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/analyze?mode=demo&model=rf"
```

## 3) Dataset запуск (processed датасет)
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/analyze?mode=dataset&model=rf"
```

## 4) Загрузка CSV для анализа
```powershell
$file = Get-Item ".\data\runtime\datasets\cicids2017_processed.csv"
Invoke-WebRequest -Method Post "http://127.0.0.1:5000/analyze?mode=dataset&model=rf" -Form @{ file = $file }
```

## 5) Real режим (нужны права администратора)
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/analyze?mode=real&model=rf"
```

## 6) Ручное накопление baseline (в БД, real)
```powershell
Invoke-RestMethod "http://127.0.0.1:5000/collect?mode=real&baseline=1&rows=200"
```

## 7) Список алертов
```powershell
Invoke-RestMethod "http://127.0.0.1:5000/alerts?limit=10"
```

## 8) Обновление статуса алерта
```powershell
$id = 1
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/alerts/$id/status" `
  -ContentType "application/json" `
  -Body '{"status":"acknowledged"}'

Invoke-RestMethod -Method Post "http://127.0.0.1:5000/alerts/$id/status" `
  -ContentType "application/json" `
  -Body '{"status":"false_positive"}'
```

## 9) Очистка алертов (dev endpoint)
```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:5000/alerts/purge" `
  -ContentType "application/json" `
  -Body '{"keep_last": 20}'
```

## 10) Проверка модели аномалий (auto retrain)
```powershell
Test-Path ".\models\runtime\isolation_forest.pkl"
```
