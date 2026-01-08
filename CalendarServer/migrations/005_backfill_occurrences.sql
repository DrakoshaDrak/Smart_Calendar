-- Backfill occurrences for pre-existing events that have no occurrences
INSERT INTO occurrences(event_id, start_ts, end_ts, created_at)
SELECT e.id, e.start_ts, e.end_ts, now()
FROM events e
ON CONFLICT (event_id, start_ts) DO NOTHING;
