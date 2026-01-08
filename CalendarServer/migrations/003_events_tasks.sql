-- 003_events_tasks.sql: events and tasks (v1)

-- ensure pgcrypto is available (already done in previous migrations, safe to repeat)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  title text NOT NULL,
  description text NULL,
  start_ts timestamptz NOT NULL,
  end_ts timestamptz NULL,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_calendar_start_idx ON events(calendar_id, start_ts);
CREATE INDEX IF NOT EXISTS events_calendar_created_idx ON events(calendar_id, created_at);

CREATE TABLE IF NOT EXISTS tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  title text NOT NULL,
  description text NULL,
  due_ts timestamptz NULL,
  status int NOT NULL DEFAULT 0,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tasks_calendar_due_idx ON tasks(calendar_id, due_ts);
CREATE INDEX IF NOT EXISTS tasks_calendar_status_idx ON tasks(calendar_id, status);
