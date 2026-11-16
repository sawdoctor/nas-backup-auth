# Kuma and HBA accepted; original Tracearr review next, 16 November 2026

Native nas-production-kuma-controls.service completed successfully using
84c427aede88bf6c00f3576f9ce3e95e861631a0, script SHA256
d9c844f035e69043c093a5c036c86c23b7c4f45ebf245aa53aee384ede40e7c1.

All ten isolated regression cases passed natively. The HBA handover was
accepted from three recent scheduled collector successes, with current
temperature 61 C. The corrected worker, original collector/OMV job and
one-minute bridge remain; retire the bridge at the final OMV cron handover,
after verifying the original dispatcher schedule.

Kuma restored exactly 15 reviewed active monitors and 10 paused, original
notification destination active/default false and 16 original associations.
All 15 current heartbeat results are UP:
2,3,6,7,8,9,10,14,16,17,18,21,23,27,28.
Current image/users/history/auth/TLS and unrelated runtimes retained. No
test notification. Native unit exited successfully, CPU 2.425 s, memory
peak 153.6 MiB. Do not rerun accepted Kuma/HBA restoration.

The original/current Tracearr comparison is deliberately separate.
It will compare only the seven selected settings, five control tables and
server metadata from the actual frozen source and current NAS PostgreSQL.
Current NAS history, fixed Plex connection and enabled request service
are authoritative. No blanket enable or database rollback is authorized.

The new reviewer validates the accepted Kuma/current source proof, exact
original cached PostgreSQL image and checksum-listed stopped-source
cluster files. It makes one bounded disposable cluster copy (max 4 GiB,
2 GiB disk reserve), starts the original PostgreSQL image without network
or published ports and only with the copy mounted, and queries control
tables read-only. Temporary database/container are removed, even on
ordinary read/query failure. The source OptiPlex stays frozen.

No live application restart, image pull, control update, full live DB
restore, new backup, repeated reboot/playback test or global cron release.
Raw selected control snapshots and any original-PostgreSQL diagnostics
remain private for the next scoped restoration. Console shows only safe
original/current flags, counts, field differences and credential-free
origins.

No Python executor is available in this session. The read-only reviewer
has been source-reviewed; its NAS execution is still pending. Previously
accepted native tests above are actual user-provided evidence.

Remaining after original Tracearr control restoration: host jobs/cron
(including HBA ownership handoff), NAS-only NPM certificate renewal,
functional book login/playback acceptance and final migration acceptance
and documentation. Keep current NAS versions/settings, Dockmon
notify-only policy, Plex auto-empty-trash off, source freeze and all
rollback roots. Dockhand comparison remains deferred.

The existing named handover checklist could be read but cannot be
written from this executor-free turn; no checklist update is claimed.
This repository note preserves the new native evidence.
