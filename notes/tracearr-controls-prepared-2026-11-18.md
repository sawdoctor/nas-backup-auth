# Tracearr control restoration prepared, 18 November 2026

Accepted native comparison: 3b4c64827f9e41e7a93a57a308ea3ff8fab8fb92,
SHA256 8dc851ab294ef9f976d61b7c4f509a6c2c22d5bea6c52ceb754a168d79f33670.
All seven source-image tests passed. Verified original PostgreSQL copy:
254119802 bytes, 3355 regular files. Temporary PostgreSQL/container/copy
removed. No live restart or control/data change during comparison.

Original/current evidence: five automations and two destinations match in
all compared fields except disabled enable switches; no newsletters.
Two paired-device push switches disabled. Three other device event choices
differ from frozen source and must be preserved. The NAS Plex endpoint is
http://192.168.0.220:32400. The one enabled request service was newly created
on the NAS and remains authoritative.

Source mobileEnabled=true and backupScheduleType=daily; NAS false/disabled.
Source externalUrl=https://tracearr.sawdoctor.uk, NAS private origin.
Source has no rows for pollerEnabled, imagePrecacheEnabled,
pluginUpdateCheckEnabled or serverUpdateCheckEnabled; NAS has false rows.
Official v3.1.3/v3.1.7 settings defaults are true for those four keys.
Remove only their staged overrides rather than assuming absent means false.

Reviewed upstream v3.1.7 pushDelivery.reconcileDeviceMutes can rewrite shared
senders at boot if current per-device event switches are muted. The restore
checks installed build-info, actual compiled defaults/fallback and the
all-true migration guard, then requires the current event switches to make
that guard a no-op. If not, it prints safe current/original boolean choices
and stops BEFORE any live mutation. It does not rewrite the three choices
or infer user intent from their differences.

New helper: scripts/restore-nas-reviewed-tracearr-controls.py.
SHA256 82a86b14a6cbac1ec76e725645105ee6ce5e8844327e5a32f9d376afa9909812.
All 13 local tests passed, including real Node execution of the installed
runtime reader, preservation/idempotence, unrelated edit refusal, failure
before production stop and control-only rollback on application failure.
Native PostgreSQL forward/reverse/readback/subtransaction tests run in
session-only temporary tables before any live mutation. They have not yet
run on the NAS; native restoration is still pending.

The live write is one guarded PostgreSQL transaction over selected control
tables only. Current users/history/media/server/request data is never
imported or replaced. Only the existing Tracearr app container is briefly
stopped/started; DB/Redis/other apps stay running. Full current image,
config, normalized mounts/networks, protected Plex/request configuration
and all control/device fields are read back. Observe poller and daily
backup scheduler startup. A recovery failure rolls back controls only.
Source freeze, cron/host jobs, NAS-only certificate renewal remain held.

Already accepted: Kuma 15 UP / 10 paused, original destination/default and
16 joins; HBA bridge three fresh readings/latest61C; current application
imports/updates, boot/reboot, media recovery, Houndarr/Wizarr/Speedtest,
SSD/GDrive backup and sample restore. Do not repeat these accepted actions.
Remaining after native Tracearr acceptance: host cron/job ownership with
HBA bridge retirement, NAS-only NPM renewal, book functional checks and
final migration acceptance/documentation. Dockhand comparison deferred.

