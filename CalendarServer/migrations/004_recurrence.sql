-- 004_recurrence.sql: recurrence rules and occurrences

BEGIN;

-- recurrence rules: one per event (optional)
CREATE TABLE IF NOT EXISTS recurrence_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE UNIQUE,
  freq text NOT NULL,
  interval int NOT NULL DEFAULT 1,
  count int NULL,
  until_ts timestamptz NULL,
  byweekday int[] NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- occurrences: materialized event instances used for range queries
CREATE TABLE IF NOT EXISTS occurrences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  start_ts timestamptz NOT NULL,
  end_ts timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- unique per event+start to make materialization idempotent
CREATE UNIQUE INDEX IF NOT EXISTS occurrences_event_start_uniq ON occurrences(event_id, start_ts);
CREATE INDEX IF NOT EXISTS occurrences_event_start_idx ON occurrences(event_id, start_ts);
CREATE INDEX IF NOT EXISTS occurrences_start_idx ON occurrences(start_ts);

COMMIT;
