# CalendarServer

Минимальный проект C++20 с CMake и docker-compose для Checkpoint 0.

Требования
- CMake >= 3.20
- C++20 совместимый компилятор (gcc/clang)
- Boost (system). На Ubuntu: sudo apt install libboost-system-dev libboost-all-dev

Структура
CalendarServer/
  CMakeLists.txt
  README.md
  src/
    main.cpp
  scripts/
    build.sh
    run.sh
  docker/
    docker-compose.yml
    postgres-init/
      .gitkeep
    redis/
      .gitkeep

Сборка
1) Сделать исполняемым скрипт и запустить:
```
./scripts/build.sh
```

Запуск
```
./scripts/run.sh 8080
```
или
```
PORT=9090 ./scripts/run.sh
```

Docker
Перейдите в каталог `docker/` или используйте путь к файлу compose из корня проекта.
Поднять Postgres и Redis:
```
docker compose -f docker/docker-compose.yml up -d
```

Примечания
- На этом этапе сервер запускает буферный acceptor и выполняет io_context.run() без обработки соединений.
- Если Boost не найден при конфигурации CMake, установите Boost dev пакеты: sudo apt update && sudo apt install -y libboost-system-dev libboost-all-dev

## Checkpoint 2

Config через env:
- PORT (по умолчанию 8080)
- LOG_LEVEL: DEBUG/INFO/WARN/ERROR (по умолчанию INFO)
- METRICS_ENABLED: 0/1 (по умолчанию 1)
- ACCESS_LOG: 0/1 (по умолчанию 1)

Примеры:
```
METRICS_ENABLED=0 ACCESS_LOG=0 ./scripts/run.sh 8080
LOG_LEVEL=DEBUG ./scripts/run.sh 8080
```

Endpoint `/metrics` возвращает Prometheus-style метрики (http_requests_total и гистограмма latency). Если METRICS_ENABLED=0, `/metrics` вернёт 404.

Migrations
----------
After starting Postgres and PgBouncer, run migrations using DATABASE_URL pointing at PgBouncer (e.g. postgres://postgres:postgres@localhost:6432/postgres):

```
DATABASE_URL=postgres://postgres:postgres@localhost:6432/postgres ./scripts/migrate.sh
```
