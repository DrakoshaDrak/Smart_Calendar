-- 006_overrides_exdates.sql
BEGIN;

CREATE TABLE IF NOT EXISTS recurrence_exdates (
    rule_id UUID NOT NULL REFERENCES recurrence_rules(id) ON DELETE CASCADE,
    exdate DATE NOT NULL,
    PRIMARY KEY (rule_id, exdate)
);

CREATE TABLE IF NOT EXISTS occurrence_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES recurrence_rules(id) ON DELETE CASCADE,
    original_start_ts TIMESTAMPTZ NOT NULL,
    new_start_ts TIMESTAMPTZ NULL,
    new_end_ts TIMESTAMPTZ NULL,
    title TEXT NULL,
    notes TEXT NULL,
    is_cancelled BOOL NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, original_start_ts)
);

CREATE INDEX IF NOT EXISTS idx_recurrence_exdates_rule ON recurrence_exdates(rule_id, exdate);
CREATE INDEX IF NOT EXISTS idx_occurrence_overrides_rule_orig ON occurrence_overrides(rule_id, original_start_ts);

COMMIT;
