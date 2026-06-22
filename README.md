# Alpha Test

Архитектура разделена на два приложения:
- `FastAPI` backend (только API и бизнес-логика);
- `Flask` frontend (HTML-страницы, которые работают через обращения к API).

## 1. Установка

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Запуск backend (FastAPI)

```bash
uvicorn app.main:app --reload --port 8000
```

- API docs: `http://127.0.0.1:8000/docs`

## 3. Запуск storage agent (polling daemon, без uvicorn и без входящего HTTP)

Агент запускается как служба: `python -m agent.main`.
Агент не поднимает веб-сервер. Он работает только исходящими запросами (`requests`) к central API:
- регистрация;
- heartbeat;
- polling очереди задач;
- передача файловых данных.

Поддержаны 3 варианта конфигурации:
- JSON config file (`--config /path/to/agent_config.json`)
- параметры unit в `systemd` (через `ExecStart` + env)
- аргументы командной строки для запуска службы на Windows

Приоритет настроек: `CLI args > ENV > config file > defaults`.

### Вариант A: config file

```bash
python -m agent.main --config ./agent/agent_config.example.json
```

### Вариант B: systemd unit (Linux)

Пример `/etc/systemd/system/alpha-agent.service`:

```ini
[Unit]
Description=Alpha Storage Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/alpha_test
ExecStart=/usr/bin/python3 -m agent.main --config /etc/alpha-agent/config.json
Restart=always
RestartSec=3
User=alpha-agent
Group=alpha-agent

[Install]
WantedBy=multi-user.target
```

### Вариант C: Windows service args

Пример запуска процесса как службы/daemon с аргументами:

```powershell
python -m agent.main `
  --poll-interval-sec 3 `
  --agent-root C:\alpha-agent\storage `
  --agent-keys-dir C:\alpha-agent\keys `
  --agent-state-dir C:\alpha-agent\state `
  --agent-name node-agent-01 `
  --agent-host 10.10.0.21 `
  --central-server-url https://central.example.com `
  --agent-register-token alpha_agent_bootstrap_token
```

## 4. Запуск frontend (Flask)

```bash
set BACKEND_URL=http://127.0.0.1:8000
python frontend\app.py
```

- Frontend URL: `http://127.0.0.1:5000`

## 5. Страницы frontend

- `/login` — вход
- `/drive` — интерфейс файлов/ресурсов (в стиле cloud drive)
- `/admin` — dashboard админ-панели
- `/admin/nodes/<id>` — детальная страница ноды

Ссылка на админ-панель отображается только для админов с правом `admin_panel`.

## 6. Демо-пользователи

- `admin / admin123` (`super_admin`)
- `orgadmin / orgadmin123` (`org_admin`)
- `employee1 / employee123`
- `client1 / client123`

## 7. Что важно

- Все данные на frontend запрашиваются через API backend.
- Frontend не работает напрямую с БД.
- Добавление нод, томов, файлов, ACL-операции идут через FastAPI эндпоинты.

## 8. Загрузка файлов

Во фронте поддержаны оба варианта:
- через выбор файла в проводнике;
- через drag-and-drop на зону загрузки.

Оба сценария используют API `POST /files/upload` (multipart).

### Стратегия для маленьких и больших файлов

1. Frontend всегда отправляет файл в central API (`/files/upload`).
2. Backend пишет upload потоково во временный blob на центральном сервере (без чтения всего в память).
3. Создается job для ноды-агента:
- `store_file` для записи файла на ноду;
- `collect_file` для выгрузки файла с ноды обратно на central.
4. Агент по polling забирает job, скачивает/загружает blob потоками.

Это дает стабильную работу и для маленьких, и для больших файлов без открытых входящих портов на нодах.

## 9. Agent/SSH и безопасность

1. `agent`:
- при старте агент генерирует OpenPGP ключи;
- отправляет публичный ключ на central server через `/agent/control/register` по bootstrap токену;
- получает публичный ключ сервера;
- управляющие команды и метаданные шифруются OpenPGP поверх HTTPS.

Примечание по предупреждениям PGP:
- предупреждения `TripleDES` и `compression preferences` исправлены в коде;
- если ключи были сгенерированы старой версией настроек, пересоздайте их:
  - удалите файлы ключей в `agent_keys` у агента;
  - удалите `server_private.asc/server_public.asc` в `alpha_test/keys`;
  - перезапустите backend и agent.

2. `ssh`:
- рекомендуется ключевая авторизация (без пароля), отдельный сервисный пользователь;
- ограничить доступ пользователя SSH только необходимыми командами/путями;
- использовать allowlist IP и fail2ban/аналогичные меры.
