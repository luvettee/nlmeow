ALTER TABLE log_entries
    DROP CONSTRAINT IF EXISTS log_entries_entry_type_check;

ALTER TABLE log_entries
    ADD CONSTRAINT log_entries_entry_type_check
    CHECK (entry_type IN ('Config', 'Script', 'Style'));
