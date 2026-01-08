# CalendarServer API (спецификация по коду)

Документ основан на исходном коде репозитория (в основном `src/net/HttpServer.cpp`, `src/auth/Jwt.*`, `src/db/DbPool.*`, `src/main.cpp`). Если в коде что-то неочевидно, в тексте отмечено место в коде, где это выясняется.

## 1) Общие правила

- Base URL
  - В коде сервер слушает на TCP-порту, задаваемом конфигом (`Config::from_env` в `src/main.cpp`). В примерах ниже используем переменную `$BASE_URL`.

- Auth
  - Аутентификация: HTTP header `Authorization: Bearer $TOKEN` с JWT.
  - Формирование/проверка токенов:
    - `auth::Claims` (в `src/auth/Jwt.h`) содержит поля: `sub` (string, user id), `email` (string), `iat` (int64), `exp` (int64).
    - Токен создаётся `auth::create_jwt(claims, jwt_secret)` в `/auth/login` (см. `HttpServer.cpp`). Подпись HMAC-SHA256.
    - Проверка: `auth::verify_jwt(token, secret)` возвращает `std::optional<Claims>` или пусто при ошибке/просрочке.
  - Публичные / без требования токена:
    - GET /health (router в `main.cpp`) — публичный
    - GET /metrics (если включено) — публичный
    - GET /auth/ping (router в `main.cpp`) — публичный
    - POST /auth/register — реализован в `HttpServer::handle_request` (обрабатывается без предварительной проверки Authorization)
    - POST /auth/login — без предварительной проверки Authorization
  - Эндпоинты, требующие токен (везде в `HttpServer.cpp` вызывается `Session::authenticate_bearer(req, jwt_secret)`):
    - Создание/получение/патч/удаление календарей, шаринг, events/tasks/recurrence endpoints и `/me`.

- Формат времени
  - Во входных/выходных полях timestamps используются ISO-8601 с суффиксом `Z`, например `2026-01-15T10:00:00Z` — код ожидает строки и валидирует их в нескольких местах, при ошибках возвращает `400` или `{"error":"invalid timestamp format"}` (см. случаи где `boost::asio::error::invalid_argument` проверяется в callback'ах от DB).
  - Для механики кеширования и `months_touched`/`month_range_utc_from_ts` функции ожидают либо полноценный timestamp (`YYYY-MM-DDTHH:MM:SSZ`) либо `YYYY-MM` (например для month range parsing есть `parse_yyyy_mm` и `month_range_utc_from_ts` в `HttpServer.cpp`).
  - Поля `from`/`to`, `start_ts`, `end_ts`, `original_start_ts`, `new_start_ts`, `until_ts`, `due_ts` — все как строки ISO-8601 в UTC (код не переводит временные зоны).

- Content-Type
  - JSON bodies: `Content-Type: application/json` обязательно проверяется во многих хендлерах. При несоответствии возвращается `400`.

- Ошибки (JSON error schema)
  - Общая схема ошибок в коде — простые JSON-объекты вида `{"error":"code"}` (строка). Примеры: `"invalid input"`, `"unauthorized"`, `"forbidden"`, `"not found"`, `"internal"`, `"invalid timestamp format"`, `"missing range"`, `"conflict"`, `"rate limited"`.
  - Статусы используются как обычно: 200 OK, 201 Created, 204 No Content, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 409 Conflict, 413 Payload Too Large, 431 Request Header Fields Too Large, 429 Too Many Requests, 500 Internal Server Error.

- Роли / доступы
  - В коде присутствуют три уровня роли, используемые как числа:
    - 0 — reader / только чтение
    - 1 — moderator / может создавать/редактировать
    - 2 — owner / может удалять календарь/удалять элементы
  - Проверки определяются через `db->async_get_membership(calid, user_id, ...)`, результат содержит `m.role` (в DB результате третья колонка). Парсинг роли: `json_parse_int32_strict` -> если парсинг невалидный — возвращается `403`.
  - Где проверяются минимальные роли (по коду `HttpServer.cpp`):
    - Создание событий/тасков/обновление календаря, recurrence patch, exdates/occurrence override, members list, share -> требуется role >= 1 (moderator).
    - Удаление события/таска/календаря -> role >= 2 (owner) для удаления событий и тасков; удаление календаря требует совпадения `owner_user_id == cl.sub` (owner check по owner поля календаря).
    - Получение списка событий/тасков/календарей/деталей календаря -> нужно быть участником (получение membership) — если membership отсутствует -> 403.
  - Точное место проверок: многочисленные вызовы `async_get_membership` в `src/net/HttpServer.cpp`.

- Кеширование (Redis)
  - Redis используется через `RedisClient` (см. `src/cache/RedisClient.*` и `src/cache/CacheKeys.h`). Настройка включается флагом `cache_enabled` в `HttpServer` (передаётся из конфига в `main.cpp`).
  - Политика кеша для endpoint'а `GET /calendars/{id}/events?from=...&to=...`:
    - Кеширование только для *полных месячных диапазонов* (проверка: `month_range_utc_from_ts(from)` и `from == mr.first && to == mr.second`). Кроме того, `cache_enabled` и `redis` должны быть доступны.
    - Ключ формируется как `ev:<calendar_id>:<YYYYMM>`, где `YYYYMM` извлекается из `from` (функция формирует `yyyymm = from.substr(0,4) + from.substr(5,2)`).
    - Заголовки ответа при работе кеша:
      - `X-Cache-Key` — ключ
      - `X-Cache` — `hit` при хите; `miss` при записи; `error` при ошибке записи
    - TTL: значение `self->cache_ttl_sec` (передаётся в конструктор `HttpServer` из конфигурации `cfg.cache_ttl_sec`).
    - Singleflight: при miss лидер читает DB и делает `SETEX`, другие запросы ждут результата (в памяти реализован `inflight_map`).
  - Инвалидация кеша на запись: при изменениях, которые затрагивают месечные данные (create/update/delete event, recurrence changes, upsert occurrence override, add/remove exdate и т.д.) код вызывает `redis->async_del(key)` для соответствующих `ev:<calid>:<YYYYMM>` ключей. В большинстве мест удаление выполняется и упреждающе ограничено таймаутом (50ms) — логируется `cache_invalidate_ok` или `cache_invalidate_error`.


## 2) Краткая таблица эндпоинтов

(метод, путь, auth?, min role, краткое описание)

- GET /health — no — public health check
- GET /metrics — no — metrics (если включено)
- GET /auth/ping — no — auth ping
- POST /auth/register — no — регистрация пользователя (email+password)
- POST /auth/login — no — логин, возвращает token
- GET /me — yes — получение информации о текущем пользователе

Календари и шаринг:
- POST /calendars — yes — создать календарь (role owner после создания)
- GET /calendars — yes — список календарей текущего пользователя
- GET /calendars/{calid} — yes — получить данные календаря (требует membership)
- PATCH /calendars/{calid} — yes, role>=1 — обновить (title)
- DELETE /calendars/{calid} — yes, owner only (owner_user_id == token.sub) — удалить календарь
- POST /calendars/{calid}/share — yes, role>=1 — пригласить/обновить роль участника
- GET /calendars/{calid}/members — yes, role>=1 — получить список участников

Events:
- POST /calendars/{calid}/events — yes, role>=1 — создать событие (поддержка recurrence + materialize)
- GET /calendars/{calid}/events?from=...&to=... — yes, role>=0 (член) — список occurrences в диапазоне (кеширование для full-month ranges)
- PATCH /calendars/{calid}/events/{eventId} — yes, role>=1 — обновить event
- DELETE /calendars/{calid}/events/{eventId} — yes, role>=2 — удалить event

Recurrence admin:
- POST /recurrence/{rule_id}/exdates — yes, role>=1 — добавить exdate
- DELETE /recurrence/{rule_id}/exdates — yes, role>=1 — удалить exdate
- PATCH /recurrence/{rule_id}/occurrence — yes, role>=1 — upsert override for single occurrence
- PATCH /recurrence/{rule_id} — yes, role>=1 — update recurrence rule (partial patch)

Tasks:
- POST /calendars/{calid}/tasks — yes, role>=1 — создать таск
- GET /calendars/{calid}/tasks — yes, role>=0 — список тасков (фильтры from/to/status)
- PATCH /calendars/{calid}/tasks/{taskId} — yes, role>=1 — обновить таск
- DELETE /calendars/{calid}/tasks/{taskId} — yes, role>=2 — удалить таск

Примечание: реализация отдельных endpoint'ов и поведения — в `src/net/HttpServer.cpp` (блок `handle_request`).


## 3) Детальная спецификация эндпоинтов

Далее перечислены эндпоинты в том же порядке, что и в краткой таблице. Для каждого приведены: назначение, доступ, параметры, тела, ответы, побочные эффекты и edge-cases, а также ссылки на места в коде.

---

### GET /health
- Назначение: проверка доступности сервера
- Auth: public
- Path params: none
- Query params: none
- Body: none
- Responses:
  - 200 OK: {"status":"ok"} (см. `main.cpp` router.add_route)
- Edge cases: нет
- Side effects: none
- Код: `src/main.cpp` router.add_route

---

### GET /metrics
- Назначение: Prometheus-совместимый scrape (включается через конфиг)
- Auth: public
- Content-Type: text/plain; version=0.0.4
- Responses:
  - 200 OK: текст метрик (см. `observability::Metrics::instance().scrape()`)
- Код: `src/main.cpp` (включение когда `cfg.metrics_enabled` true)

---

### GET /auth/ping
- Назначение: health/ping для auth подсистемы
- Auth: public
- Responses: 200 OK {"status":"ok"}
- Код: `src/main.cpp`

---

### POST /auth/register
- Назначение: зарегистрировать нового пользователя
- Auth: public
- Path params: none
- Query params: none
- Body (Content-Type: application/json):
  - email (string) — обязательное, нормализуется (trim+lower), проверяется наличие '@' и длина <=254
  - password (string) — обязательное, длина >=8 и <=1024
  - Примечание: body size ограничен 32KiB (см. `HttpServer.cpp`)
- Responses:
  - 201 Created: {"id":"<user_id>","email":"<email>"} — возвращается id из `async_insert_user` (RETURNING id)
  - 400 Bad Request: {"error":"invalid input"} — при проблемах парсинга или валидации
  - 409 Conflict: {"error":"conflict"} — если пользователь уже существует (DB unique constraint или проверка exists)
  - 500 Internal Server Error: {"error":"internal"} — при ошибках DB или хеширования
- Edge cases:
  - длинные тела -> 400/413 (см. header/body limits)
  - нестандартные email -> 400
  - хеширование пароля выполняется в пуле CPU (`cpu_pool`), при отсутствии пула возвращается 500
- Side effects:
  - запись в таблицу users через `db->async_insert_user` (см. `src/db/DbPool.cpp`)
- Код: `src/net/HttpServer.cpp` (обработчик прямо в `handle_request`)

---

### POST /auth/login
- Назначение: авторизовать пользователя и выдать JWT
- Auth: public
- Body (application/json): {"email":"...","password":"..."}
  - email нормализуется (trim+lower)
  - password проверяется через `auth::verify_password` на фоне в `cpu_pool`
- Responses:
  - 200 OK: {"token":"<jwt>"}
  - 401 Unauthorized: {"error":"invalid credentials"} — если пользователь не найден или пароль неверный
  - 500 Internal Server Error: {"error":"internal"} — при проблемах (например, jwt_secret не настроен)
- Edge cases:
  - длинный запрос >32KiB -> 400/unauthorized
  - timing: проверка пароля в пуле `cpu_pool`
- Side effects: нет прямых DB-мутирующих эффектов кроме чтения пользователя (`async_get_user_by_email`)
- Код: `src/net/HttpServer.cpp`

---

### GET /me
- Назначение: возвратить canonical user record
- Auth: yes (Bearer JWT)
- Access: любой аутентифицированный пользователь
- Responses:
  - 200 OK: {"id":"<id>","email":"<email>"}
  - 401 Unauthorized: {"error":"unauthorized"} — если токен отсутствует/невалиден
  - 500 Internal Server Error: {"error":"internal"} — если DB недоступна
- Side effects: чтение `db->async_get_user_by_id(cl.sub)`
- Код: `src/net/HttpServer.cpp`

---

### POST /calendars
- Назначение: создать календарь
- Auth: yes
- Access: любой аутентифицированный пользователь становится owner автора (в DB создаётся membership role=2)
- Body (application/json): {"title":"..."}
  - title: обязательное, непустое, max 1024
- Responses:
  - 201 Created: {"id":"<calendar_id>"}
  - 400 Bad Request: {"error":"invalid input"}
  - 401 Unauthorized: {"error":"unauthorized"}
  - 500 Internal Server Error: {"error":"internal"}
- Side effects:
  - `db->async_create_calendar(cl.sub, title)` — в `DbPool::async_create_calendar` создаётся запись и вставляется membership owner role=2 (см. `src/db/DbPool.cpp`)
- Код: `src/net/HttpServer.cpp` (строки около создания календаря)

---

### GET /calendars
- Назначение: список календарей, где пользователь участник
- Auth: yes
- Body: none
- Responses:
  - 200 OK: JSON array — каждый элемент {"id":"","title":"","owner":"","role":<int>} (role как число из membership)
  - 401 Unauthorized: когда нет токена
  - 500 Internal Server Error при проблемах DB
- Side effects: чтение `db->async_list_calendars_for_user(cl.sub)`
- Код: `HttpServer.cpp`

---

### GET /calendars/{calid}
- Назначение: получить метаданные календаря
- Auth: yes
- Access: пользователь должен быть членом календаря (membership exists) — иначе 403
- Path params:
  - calid (string) — id календаря
- Responses:
  - 200 OK: {"id":"","title":"","owner":""}
  - 401 Unauthorized: missing/invalid token
  - 403 Forbidden: not a member
  - 404 Not Found: calendar not found
  - 500 Internal Server Error
- Side effects: `db->async_get_membership` -> `db->async_get_calendar`
- Код: `HttpServer.cpp` (helper /calendars/{id})

---

### PATCH /calendars/{calid}
- Назначение: обновить календарь (сейчас поддерживается только поле `title`)
- Auth: yes, role >= 1 (moderator)
- Body: {"title":"..."} (application/json)
- Responses:
  - 200 OK: возвращает обновлённый объект {"id":"","title":"","owner":""}
  - 400 Bad Request: invalid input
  - 401 Unauthorized
  - 403 Forbidden: роль ниже moderator или membership отсутствует
  - 500 Internal Server Error
- Side effects: `UPDATE calendars SET title=...` через `async_exec_params`
- Код: `HttpServer.cpp`

---

### DELETE /calendars/{calid}
- Назначение: удалить календарь
- Auth: yes, owner only — проверяется через `db->async_get_calendar` и сравнение `owner_user_id == cl.sub`
- Responses:
  - 204 No Content — успешно
  - 401 Unauthorized
  - 403 Forbidden — если не владелец
  - 404 Not Found — calendar not found
  - 500 Internal Server Error
- Side effects: `DELETE FROM calendars WHERE id=$1` (cascade удалит членства и связанные данные в БД)
- Код: `HttpServer.cpp`

---

### POST /calendars/{calid}/share
- Назначение: пригласить/обновить участника
- Auth: yes, role >= 1 (moderator)
- Body: {"email": "user@example.com", "role": <int>} (application/json)
  - role: int, допустимые значения: 0 или 1 (в коде проверяется строго role != 0 && role != 1 -> bad role)
- Responses:
  - 201 Created: {"status":"ok"} когда создана новая запись
  - 200 OK: {"status":"ok"} когда обновлена роль
  - 400 Bad Request: invalid input или invalid role
  - 401,403,404,500 как обычно (см. `HttpServer.cpp`)
- Side effects:
  - `async_get_user_by_email` -> `async_get_membership` -> либо `async_update_membership_role`, либо `async_add_membership`
- Код: `HttpServer.cpp`

---

### GET /calendars/{calid}/members
- Назначение: получить список участников (user_id, email, role)
- Auth: yes, role >= 1 (moderator)
- Responses:
  - 200 OK: array [{"user_id":"","email":"","role":<int>}]
  - 401/403/500 и т.д.
- Side effects: `db->async_list_memberships(calid)`
- Код: `HttpServer.cpp`

---

### POST /calendars/{calid}/events
- Назначение: создать событие; поддерживает простые события и recurring (опция `recurrence` в теле)
- Auth: yes, role >= 1 (moderator)
- Body (application/json):
  - title (string) — required
  - description (string|null) — optional; код различает ключ присутствует/отсутствует через `json_extract_string_opt_present`
  - start_ts (string) — required, ISO-8601 UTC
  - end_ts (string|null) — optional
  - recurrence (object) — optional: вложенный объект с полями `freq`, `interval`, `count`, `until_ts`, `byweekday` и т.п. Код парсит `recurrence` как подстроку JSON (см. `find_recurrence_object`) и затем извлекает поля вручную.

- Responses:
  - 201 Created: возвращает созданный event объект (id, calendar_id, title, description|null, start_ts, end_ts|null, created_by, created_at, updated_at)
  - 400 Bad Request: invalid input, unsupported recurrence, invalid timestamp format
  - 401/403/500 как обычно
- Side effects:
  - Для нефрекуррентных: `db->async_create_event_with_occurrence` — атомарно создаёт event + single occurrence.
  - Для рекуррентных: парсит правило, materialize первых ~31 дней (для DAILY/WEEKLY), затем вызывает `db->async_create_event_with_recurrence` для создания event + rule + bulk occurrences.
  - Invalidates Redis keys для месяцев, затронутых событием (`months_touched`, формирование `ev:<calid>:<YYYYMM>`).
- Edge cases:
  - `recurrence` может быть отсутствующим -> создаётся простое событие
  - Unsupported recurrence freq (не DAILY/WEEKLY) -> 400 `{"error":"unsupported recurrence"}`
  - When DB returns `boost::asio::error::invalid_argument` the server maps it to 400 `invalid timestamp format`.
- Код: `HttpServer.cpp` (блок POST /calendars/{id}/events)

---

### GET /calendars/{calid}/events?from=...&to=...
- Назначение: получить список occurrences событий в диапазоне (включая materialized occurrences и overrides)
- Auth: yes (user must be a member)
- Query params (required):
  - from (string) — required
  - to (string) — required
  - оба парсятся как строки; если отсутствуют -> 400 {"error":"missing range"}
- Caching logic:
  - Если `cache_enabled` и `redis` подключён и `from`/`to` образуют полный месячный диапазон (сравнение с `month_range_utc_from_ts(from)`), то сервер пытается `GET` ключ `ev:<calid>:<YYYYMM>`.
  - При хите возвращает тело из кэша с заголовками `X-Cache: hit` и `X-Cache-Key`.
  - При miss лидер читает `db->async_list_occurrences(calid, from, to)`, сериализует ответы в {"items":[...]} и делает `SETEX key TTL out`. Singleflight и soft-deadline 50ms применяются для setex.
- Responses:
  - 200 OK: {"items": [ {"id":"","title":"","description":...,"start_ts":"","end_ts":...,"created_by":"","created_at":""}, ... ] }
  - 400 Bad Request: missing range or invalid timestamp format
  - 401/403/500
- Side effects: чтение `db->async_list_occurrences`; при miss запись в Redis (setex) и логирование метрик
- Edge cases:
  - Cache get/set ошибки логируются и трактуются как miss
  - Если redis не доступен — поведение падает back to DB
- Код: `HttpServer.cpp` (блок GET /calendars/{id}/events)

---

### PATCH /calendars/{calid}/events/{eventId}
- Назначение: полное обновление event (title, description, start_ts, end_ts)
- Auth: yes, role >= 1 (moderator)
- Body: частичные поля поддерживаются через `json_extract_*_opt_present`.
  - Если ключ присутствует и значение null -> explicit null (например description очищается)
  - Если ключ отсутствует -> сохраняется текущее значение (в коде читается текущая запись и затем формируется `new_*`)
- Responses:
  - 200 OK: возвращает обновлённый event JSON
  - 400 Bad Request: invalid input
  - 401/403/404/500
- Side effects:
  - `db->async_update_event_full(calid,eventId,...)` — возвращает обновлённую строку
  - invalidation Redis для месяцев, затронутых старым и новым start_ts (функция `months_touched` используется)
- Edge cases:
  - Если передан пустой title или пустой start_ts -> 400
  - invalid timestamp -> 400 `invalid timestamp format` (если DB возвращает соответствующую ошибку)
- Код: `HttpServer.cpp`

---

### DELETE /calendars/{calid}/events/{eventId}
- Назначение: удалить event
- Auth: yes, role >= 2 (owner)
- Responses:
  - 204 No Content: success
  - 401/403/404/500
- Side effects:
  - `db->async_get_event` -> `db->async_delete_event`
  - после удаления инвалидация кеша для месяцев, в которых лежало событие (используется `months_touched(start_ts,end_ts)`)
- Код: `HttpServer.cpp`

---

### Recurrence endpoints
Общие замечания: в коде есть набор endpoint'ов для управления правилами рекурсии, exdates и overrides. Для операций сначала делается resolve calendar_id по rule_id:
```sql
SELECT e.calendar_id FROM recurrence_rules rr JOIN events e ON e.id=rr.event_id WHERE rr.id=$1 LIMIT 1
```
Если правило не найдено -> 404.

#### POST /recurrence/{rule_id}/exdates
- Назначение: добавить exdate (string date)
- Auth: yes, role >= 1
- Body: {"date":"YYYY-MM-DD"} (в коде используется `json_extract_string` и затем `month_range_utc_from_ts(date)` — ожидается формат `YYYY-MM` или timestamp, при неверном формате -> 400)
- Responses:
  - 200 OK: {"status":"ok"}
  - 400 Bad Request: invalid input / invalid date
  - 401/403/404/500
- Side effects:
  - `db->async_add_recurrence_exdate(rule_id, date)`
  - Invalidate corresponding month cache (compute month from date) и `async_enqueue_outbox_job("recompute_rule", payload)` — чтобы воркер пересчитал rule
- Код: `HttpServer.cpp`

#### DELETE /recurrence/{rule_id}/exdates
- Назначение: удалить exdate
- Auth: yes, role >= 1
- Body: {"date":"..."}
- Responses: 200 OK {"status":"ok"} / 400 / 401 / 403 / 404 / 500
- Side effects: `async_remove_recurrence_exdate`, invalidate month cache, enqueue outbox job
- Код: `HttpServer.cpp`

#### PATCH /recurrence/{rule_id}/occurrence
- Назначение: upsert override for one occurrence
- Auth: yes, role >= 1
- Body (application/json):
  - original_start_ts (string) — required (the original occurrence start)
  - new_start_ts (string|null) — optional (use json_extract_string_opt_present)
  - new_end_ts (string|null) — optional
  - title (string|null) — optional
  - notes (string|null) — optional
  - cancelled (int) — optional (0/1); parsed via json_extract_int_opt
- Responses:
  - 200 OK: {"status":"ok"}
  - 400 Bad Request: invalid input / invalid timestamp
  - 401/403/404/500
- Side effects:
  - `async_upsert_occurrence_override` — затем compute affected months (original month and possibly new_start month) -> invalidate cache keys -> enqueue outbox recompute jobs per affected range
- Код: `HttpServer.cpp`

#### PATCH /recurrence/{rule_id}
- Назначение: patch recurrence rule (freq, interval, count, until_ts)
- Auth: yes, role >= 1
- Body: partial fields; if no fields provided -> 400 `{"error":"no fields to update"}`
- Responses:
  - 200 OK: {"status":"ok"}
  - 400 Bad Request: no fields / invalid timestamp format
  - 403 Forbidden: membership missing or role < moderator
  - 404 Not Found
  - 500 Internal Server Error
- Side effects:
  - Atomic DB update (`WITH upd AS (UPDATE ... RETURNING id) INSERT INTO outbox_jobs(job_type,payload) SELECT 'recompute_rule', $N::jsonb FROM upd ...`)
  - Invalidate two months window (start month and next month)
- Код: `HttpServer.cpp`

---

### POST /calendars/{calid}/tasks
- Назначение: создать таск
- Auth: yes, role >= 1
- Body: {"title":"...","description":...,"due_ts":...}
- Responses:
  - 201 Created: returns created task object with fields id, calendar_id, title, description|null, due_ts|null, status (int), created_by, created_at, updated_at
  - 400/401/403/500 as usual
- Side effects: `db->async_create_task` (DB insert)
- Код: `HttpServer.cpp`

---

### GET /calendars/{calid}/tasks?from=...&to=...&status=...
- Назначение: список тасков с фильтрами
- Auth: yes (be a member)
- Query params optional: from, to (timestamps) and status (int)
- Responses:
  - 200 OK: {"items":[...]} each item: id, title, description, due_ts|null, status(int), created_by, created_at, updated_at
  - 400 invalid timestamp format
- Side effects: `db->async_list_tasks`
- Код: `HttpServer.cpp`

---

### PATCH /calendars/{calid}/tasks/{taskId}
- Назначение: обновить таск
- Auth: yes, role >= 1
- Body: partial fields supported (title, description, due_ts, status)
  - status must be 0 or 1 (код проверяет)
- Responses: 200 OK returns updated task JSON, or 400/401/403/404/500
- Side effects: `db->async_update_task_full`
- Код: `HttpServer.cpp`

---

### DELETE /calendars/{calid}/tasks/{taskId}
- Назначение: удалить таск
- Auth: yes, role >= 2
- Responses: 204 No Content or 403/404/500
- Side effects: `db->async_delete_task`
- Код: `HttpServer.cpp`


## 4) Примеры curl (используйте переменные $BASE_URL, $TOKEN, $CALID)

- register
  curl -X POST -H "Content-Type: application/json" -d '{"email":"u@example.com","password":"password123"}' "$BASE_URL/auth/register"

- login
  curl -X POST -H "Content-Type: application/json" -d '{"email":"u@example.com","password":"password123"}' "$BASE_URL/auth/login"

- create calendar
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title":"My Cal"}' "$BASE_URL/calendars"

- list calendars
  curl -H "Authorization: Bearer $TOKEN" "$BASE_URL/calendars"

- share calendar / add member
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"email":"other@example.com","role":0}' "$BASE_URL/calendars/$CALID/share"

- create event (simple)
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title":"Meeting","start_ts":"2026-01-15T10:00:00Z","end_ts":"2026-01-15T11:00:00Z"}' "$BASE_URL/calendars/$CALID/events"

- list events by month (full-month range required for caching)
  curl -H "Authorization: Bearer $TOKEN" "$BASE_URL/calendars/$CALID/events?from=2026-01-01T00:00:00Z&to=2026-02-01T00:00:00Z"

- create recurrence (example minimal recurrence object in body)
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"title":"Daily","start_ts":"2026-01-01T09:00:00Z","recurrence":{"freq":"DAILY","interval":1}}' "$BASE_URL/calendars/$CALID/events"

- add exdate
  curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"date":"2026-01-15"}' "$BASE_URL/recurrence/$RULE_ID/exdates"

- delete event
  curl -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/calendars/$CALID/events/$EVENT_ID"


## 5) Проверка полноты (все места, где маршруты добавляются/обрабатываются)

Документированные места маршрутов:
- `Router::add_route("GET","/health",...)` — `src/main.cpp`
- `Router::add_route("GET","/metrics",...)` — `src/main.cpp` (если включено)
- `Router::add_route("GET","/auth/ping",...)` — `src/main.cpp`

Все внутренние маршруты, обрабатываемые в `HttpServer::Session::handle_request` (файл `src/net/HttpServer.cpp`):
- POST /auth/register
- POST /auth/login
- GET /me
- POST /calendars
- GET /calendars
- GET /calendars/{calid}
- PATCH /calendars/{calid}
- DELETE /calendars/{calid}
- POST /calendars/{calid}/share
- GET /calendars/{calid}/members
- POST /calendars/{calid}/events
- GET /calendars/{calid}/events
- PATCH /calendars/{calid}/events/{eventId}
- DELETE /calendars/{calid}/events/{eventId}
- POST /calendars/{calid}/tasks
- GET /calendars/{calid}/tasks
- PATCH /calendars/{calid}/tasks/{taskId}
- DELETE /calendars/{calid}/tasks/{taskId}
- PATCH /recurrence/{rule_id}/occurrence
- POST /recurrence/{rule_id}/exdates
- DELETE /recurrence/{rule_id}/exdates
- PATCH /recurrence/{rule_id}

Сверка: все `router.add_route(...)` вызовы из кода перечислены (см. `src/main.cpp`) — они лишь для /health, /metrics, /auth/ping; остальные пути реализованы в `HttpServer.cpp` внутри `handle_request`.

---

Требования покрытия:
- Источник истины: `src/net/HttpServer.cpp`, `src/auth/Jwt.*`, `src/db/DbPool.*`, `src/main.cpp` — использованы.
- Не домысливал поля/типы: где неочевидно — отмечено место в коде (например точный формат `date` в exdates — код поддерживает `YYYY-MM` и timestamps через `month_range_utc_from_ts`).

