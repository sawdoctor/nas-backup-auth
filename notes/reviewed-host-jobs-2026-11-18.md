# Reviewed NAS host schedule handover

Native remaining-owner review: 74 files, no missing inputs; SHA256
73ff1f6fead44c90af0bdd6c594379b2eb1382921277c9dfeaeed151b89a4110.
Private bytes fetched from the existing backup review and hash-verified.

Cron contains normal Debian/OMV maintenance and the original one-minute HBA
collector dispatcher. OMV Compose update/prune/backup cron files have no active
jobs. The root crontab has no active command. Anacron already runs independently.
The ABS and Flora helpers match reviewed generated implementations exactly.
The TorBox helper matches the accepted boot repair. The archive package and
54-entry retained ledger match the staged implementation. Existing current
NAS audiobook/podcast/Shelfmark targets are retained, with live API/plan checks
required before releasing any conditions.

restore-nas-reviewed-host-jobs.py restores only cron and the four reviewed NAS
job service/timer conditions. Original drop-ins are retained. The general
import marker and source freeze stay in place. The existing HBA bridge stops
before cron starts, and the handover observes an original cron-scheduled fresh
reading. Failure of that proof restores the cron hold and HBA bridge.

The archive's existing service gains one scoped flock override, coordinating
with normal NAS backup/recovery. Conflict status75 counts as a skipped successful
attempt; original program/environment/ledger/maximum-two-backups policy remain.
Other workers already use the shared backup lock and are started only after the
controller releases it. ABS, Flora and CAM watchdog first runs are verified;
the archive timer is enabled without claiming its first cloud transfer finished.
Original Flora push-monitor pause remains; no new restart behavior is added.

Completion is journaled component by component and can resume without reverting
application data or completed ownership. No image pull, application recreation,
database import, source start or certificate action is performed. An optional
read-only NPM summary distinguishes certificates referenced by enabled live
hosts from unused/disabled old records, and reads actual public-certificate
expiry where available. No key material is read or printed.

Ten local regression tests cover refusal before schedule changes, archive plan
semantics, backup lock scope, HBA owner ordering/recovery and certificate-use
filtering. Native preflight and execution remain pending; NPM renewal and book
functional acceptance remain separate.
