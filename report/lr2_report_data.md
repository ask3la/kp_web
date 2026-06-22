# Данные для отчета по ЛР2 (alpha_test)

Этот файл — конспект всех исходных данных, на которых можно написать/обновить отчет по ЛР2.

## 1) Формулировка задания (по PDF ЛР2)

Тема: **«Разработка прототипа и интеграции»**.

Ключевые требования:
- Сделать прототип из 2–3 основных модулей/сервисов.
- Определить формат межмодульного взаимодействия (REST/gRPC/очереди и т.д.).
- Организовать хранение данных в SQL/NoSQL по ER-логике из ЛР1.
- Реализовать CRUD-доступ к данным.
- Добавить безопасность (аутентификация/авторизация), проверить недоступность закрытых операций без прав.
- Показать применение принципов SOLID, DRY, KISS.
- В отчете обязательно описать:
  - подход реализации;
  - структуру прототипа;
  - хранение данных;
  - CRUD (какие endpoint’ы/методы);
  - безопасность;
  - SOLID/DRY/KISS;
  - выводы.

## 2) Кратко о реализованной системе

Проект: `alpha_test`

Архитектура:
- Backend: FastAPI (`alpha_test/app`)
- Frontend: Flask (`alpha_test/frontend`)
- Storage-agent: polling daemon (`alpha_test/agent`)
- БД: SQLite (`alpha_test/app.db`)

Идея: корпоративное облачное хранилище с пользователями, ACL, ресурсами, нодами/томами, файлами, аудитом, админ-панелью.

## 3) Модули и взаимодействие

### 3.1 Основные модули
- Auth/Users
- ACL/Groups/Permissions/Resources
- Nodes/Volumes
- Files/Placement
- Agent control (регистрация, heartbeat, job queue, transfer)
- Audit

### 3.2 Формат интеграции
- Frontend ↔ Backend: REST API (JSON + multipart upload)
- Agent ↔ Backend: REST + polling jobs
- Передача данных файлов: через `transfer_blobs` + proxy streaming

## 4) Хранение данных (SQLite)

Источник: `alpha_test/app/db.py`

Таблицы:
- `users`
- `groups_acl`
- `user_groups`
- `resources`
- `resource_folders`
- `resource_nodes`
- `group_permissions`
- `nodes`
- `volumes`
- `files`
- `agent_jobs`
- `transfer_blobs`
- `audit_logs`
- `service_settings`

Ключевые детали:
- `files` содержит служебные поля хранения (`storage_rel_path`) и шаринга (`share_enabled`, `share_uuid`).
- `volumes` ведет квоты и фактическое использование в байтах (`quota_bytes`, `used_bytes`).
- Включены внешние ключи и каскадные связи там, где нужно.

## 5) CRUD и API (фактические endpoint’ы)

Источник: `alpha_test/app/routers/*.py`

### 5.1 Auth (`/auth`)
- `POST /auth/login`
- `POST /auth/users`
- `GET /auth/users`
- `PUT /auth/users/{user_id}`
- `POST /auth/users/{user_id}/password`
- `POST /auth/users/{user_id}/block`
- `POST /auth/users/{user_id}/unblock`
- `DELETE /auth/users/{user_id}`
- `GET /auth/me`

### 5.2 ACL (`/acl`)
- Группы:
  - `POST /acl/groups`
  - `GET /acl/groups`
  - `DELETE /acl/groups/{group_id}`
  - `POST /acl/groups/bind-user`
  - `DELETE /acl/groups/{group_id}/users/{user_id}`
- Ресурсы:
  - `POST /acl/resources`
  - `PUT /acl/resources/{resource_id}`
  - `DELETE /acl/resources/{resource_id}`
  - `GET /acl/resources`
  - `POST /acl/folders`
  - `GET /acl/resources/{resource_id}/folders`
  - `GET /acl/resources/{resource_id}/nodes`
  - `PUT /acl/resources/{resource_id}/nodes`
- Права:
  - `POST /acl/permissions/grant`
  - `GET /acl/permissions`
  - `DELETE /acl/permissions/{permission_id}`
- Служебные:
  - `GET /acl/me/permissions`
  - `GET /acl/admin/management`

### 5.3 Nodes (`/nodes`)
- `POST /nodes`
- `POST /nodes/agent/register`
- `GET /nodes`
- `PUT /nodes/{node_id}`
- `POST /nodes/{node_id}/check`
- `DELETE /nodes/{node_id}`

### 5.4 Volumes (`/volumes`)
- `POST /volumes`
- `GET /volumes`
- `PUT /volumes/{volume_id}`
- `DELETE /volumes/{volume_id}`

### 5.5 Files (`/files`)
- `POST /files`
- `POST /files/upload`
- `GET /files`
- `GET /files/{file_id}`
- `POST /files/{file_id}/prepare-download`
- `GET /files/{file_id}/download`
- `GET /files/{file_id}/share`
- `PUT /files/{file_id}/share`
- `PUT /files/{file_id}`
- `DELETE /files/{file_id}`
- Публичная ссылка:
  - `GET /private/{share_uuid}/download` (через `public_router`)

### 5.6 Admin (`/admin`)
- `GET /admin/dashboard`
- `GET /admin/nodes/{node_id}/detail`
- `GET /admin/capabilities`
- `GET /admin/settings`
- `PUT /admin/settings`
- `GET /admin/audit`

### 5.7 Agent control (`/agent/control`)
- `POST /agent/control/register`
- `POST /agent/control/heartbeat`
- `POST /agent/control/jobs/fetch`
- `GET /agent/control/jobs/{job_id}/download`
- `POST /agent/control/jobs/{job_id}/upload-result`
- `POST /agent/control/jobs/{job_id}/complete`

## 6) Реализация безопасности

### 6.1 Аутентификация
- JWT-токен (Bearer) в backend (`security.py`, `dependencies.py`).

### 6.2 Авторизация
- Роли + уровни админства (`none`, `group_admin`, `org_admin`, `super_admin`).
- ACL-пермишены:
  - `view`, `read`, `write`, `delete`, `share`,
  - `manage_users`, `manage_groups`, `manage_nodes`, `manage_volumes`, `manage_permissions`,
  - `admin_panel`.

### 6.3 Ограничения доступа
- Закрытые операции недоступны без токена/прав (`401/403`).
- Для файловых действий используются проверки `can_read_file / can_write_file / can_delete_file`.
- Приватная ссылка для скачивания реализована длинным `share_uuid`.

## 7) Аудит и трассируемость

Источник: middleware в `app/main.py`, роутер `app/routers/audit.py`.

Что логируется:
- **Любой HTTP-запрос** в middleware (`event_code=http_request`).
- Доменные события: login/upload/download/delete/share и т.д.
- Записываются `ip_address`, `user_agent`, `actor_type`, `meta`.

Отдельно по скачиванию:
- Логируется обычное скачивание файла.
- Логируется скачивание по приватной ссылке.
- Во frontend пробрасываются `X-Forwarded-For`, `X-Real-IP`, `User-Agent` в backend для корректного IP/UA в аудите.

## 8) Логика хранения и размещения файлов

Источник: `app/services.py`, `app/repositories.py`

Ключевые моменты:
- Выбор тома делает `PlacementService.choose_volume`.
- Учитывается доступный объем (квота/занятость), при нехватке — поиск следующего кандидата.
- Если подходящий том не найден, возвращается ошибка.
- Для ресурсов с явно назначенными нодами используются **только** эти ноды.
- Если ноды ресурса не заданы, применяется fallback:
  - сначала ноды с `store_all_data=1`,
  - затем общий пул активных нод с сортировкой по `storage_priority` и свободному месту.

## 9) SOLID / DRY / KISS (факты для раздела отчета)

### SOLID
- SRP: роутеры, сервисы и репозитории разделены по ответственности.
- Бизнес-логика вынесена в `services.py`, а не в HTTP-слой.

### DRY
- Повторяющиеся операции доступа к БД централизованы в репозиториях.
- Общие проверки доступа централизованы (`AccessService`).
- Единый аудит HTTP-запросов через middleware.

### KISS
- Простой и прозрачный стек: FastAPI + Flask + SQLite.
- REST как единый понятный способ интеграции.
- Polling-agent вместо избыточно сложной инфраструктуры.

## 10) Что можно вставить в выводы отчета

- Прототип работоспособен и покрывает требования ЛР2:
  - многомодульная архитектура,
  - CRUD через API,
  - SQL-хранение данных,
  - аутентификация/авторизация,
  - интеграция между модулями,
  - аудит обращений.
- Система пригодна для дальнейшего развития (масштабирование, отказоустойчивость, расширение бизнес-правил).

## 11) Полезные ссылки на код (для доказательной базы в отчете)

- Точка входа backend: `alpha_test/app/main.py`
- Инициализация БД: `alpha_test/app/db.py`
- Бизнес-логика: `alpha_test/app/services.py`
- Репозитории: `alpha_test/app/repositories.py`
- Роутеры API: `alpha_test/app/routers/*.py`
- Frontend: `alpha_test/frontend/app.py`, `alpha_test/frontend/templates/*`
- Agent: `alpha_test/agent/main.py`

