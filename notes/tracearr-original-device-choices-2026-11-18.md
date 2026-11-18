# Restore exact original Tracearr device choices, 18 November 2026

The first restore 9da666a78c1517119264f6ce942d0f5dc72e8579 stopped BEFORE
PostgreSQL tests, state-plan creation, application stop or live SQL writes.
Native runtime v3.1.7 / commit35840ba6caa3fce9298c8882021d973dfac9f90f
confirmed all four default controls true, default fallback active and the
all-true device migration guard present.

Native original/current evidence now resolves the three preference values:
on_stream_started, on_stream_stopped, on_trust_score_changed are TRUE in
the frozen original and FALSE on both current paired devices. The two
original/current preference row IDs and mobile identities still match.
Keeping all six false values while enabling push would let startup mute
shared senders. Do not just waive the guard.

The focused correction restores exactly those three original TRUE choices
on each reviewed device, together with the previously reviewed push enable.
It requires the exact original-true/current-false evidence for all three,
preserves every other current preference, and still requires every shared
push event to be true AFTER the planned changes so boot reconciliation is
a no-op. Unknown other mutes, separate edits and changed source choices
remain blockers. Existing settings, rules, destinations, Plex/request
connections and current history/image safeguards remain.

All 15 focused local tests pass: exact original/current evidence, refusal
of unknown mutes and unrelated notification edits, scoped SQL, current
connection/history retention, idempotent repeat, pre-write failure and
control-only rollback. The existing native PostgreSQL temporary-table
forward/reverse/readback/rollback tests run before the live transaction.
No live restoration is claimed until native success.

Original installed worker.py remains checksum-pinned and unchanged.
Corrected helper installs worker-with-original-device-choices.py in the same
private handover folder, uses the existing state.json, and runs as
nas-production-tracearr-controls-resume.service. Only the existing Tracearr
app container is briefly stopped/started. No image pull or database import.

After accepted Tracearr restoration the same command reports pending host
owner states and NPM certificate-module bindings READ ONLY, outside the
backup lock. Failure of that optional readout does not undo or invalidate
an accepted Tracearr restoration. This avoids a separate audit round trip.

Remaining migration work: reviewed host cron/jobs and HBA bridge retirement,
NAS-only certificate renewal, book functional checks and final acceptance.
Kuma/HBA, current imports, backup/sample restore and reboot remain accepted.
User asks for efficient completion to conserve remaining Work chat credits.

