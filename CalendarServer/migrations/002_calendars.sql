-- 002_calendars.sql: calendars and memberships

-- ensure pgcrypto is available for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS calendars (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  owner_user_id uuid NOT NULL REFERENCES users(id),
  created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS calendar_memberships (
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role smallint NOT NULL,
  created_at timestamptz DEFAULT now(),
  PRIMARY KEY(calendar_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_calendar_memberships_user_id ON calendar_memberships(user_id);
