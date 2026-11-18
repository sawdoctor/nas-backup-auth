# Tracearr generated settings identity, 18 November 2026

Native device-aware restore 4d49ce4b5b4354845b76a86efa05b5fb0995edd0
passed runtime and original device-choice verification, then stopped at
"The setting schema needs review". This is in plan validation BEFORE native
temporary-table tests, state creation, any production app stop or live SQL.
Both earlier workers and live history/control state remain retained.

Implementation error: the helper/tests modeled settings as name/value only.
Official v3.1.7 schema has id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY
KEY, name VARCHAR(255) UNIQUE NOT NULL, and value JSONB. Do not just remove
the schema guard: id must be accounted for in normal writes and rollback.

Corrected helper requires exactly id/name/value, positive integer IDs and
unchanged IDs for existing rows. It updates existing setting values by
id+name (no upsert/identity sequence allocation), deletes only the four
original-absent overrides, and explicitly restores retained IDs with
OVERRIDING SYSTEM VALUE during rollback. Temporary PostgreSQL fixtures use
the same override when inserting their retained generated IDs. No setval,
sequence reset, table/schema alteration or source database import.

Primary references:
- https://github.com/connorgallopo/Tracearr/blob/v3.1.7/apps/server/src/db/schema.ts
- https://www.postgresql.org/docs/16/sql-insert.html

All 19 local focused tests passed, including the actual id/name/value model,
normal value-only writes, original-ID restoration, generated-always temp
fixture inserts, rejected identity/unknown-column changes, scoped original
device restoration, Node runtime evidence, idempotence and control-only
rollback. Real PostgreSQL temp-table forward/reverse/readback/rollback tests
still run on the NAS before any live mutation. Native completion pending.

New helper: scripts/restore-nas-tracearr-setting-identities.py
SHA256: 6878f35d8740788b8bc4d5948de2848e6e335e4786f7c69cc11cbbc7c02d4abe
New private worker: tracearr-control-handover/worker-with-setting-identities.py
Unit: nas-production-tracearr-controls-schema.service
Both retained earlier worker hashes are required. Existing state.json and
all previous image/history/server/request/preference safeguards retained.
Only Tracearr app stops/starts; DB/Redis/Plex/others continue. After success,
read pending host owner/NPM certificate-module metadata in the same run.

