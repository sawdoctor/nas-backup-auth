# Failed nightly backup and guarded lock correction

Native current review on 19 November found nas-backup.service failed at
02:00:04 with exit status1, despite its timer firing correctly. The most recent
complete/uploaded set is nas-20261118T020005Z (34.64GiB applications archive).
Its SSD/Google Drive file sizes and exact checksum manifest match. All33
containers are running. Cron/HBA are healthy (60C, cache16seconds old); ABS,
Flora and TorBox watchdog last executions succeeded; the archive was in progress.
The read-only media check timed out while it could be waiting on the same lock;
this alone does not establish a stale mount. No cleanup or new app was installed.

The actual backup program SHA c73df0bd8860f4366806546e4ddd076b7cdd6434ff700e6c76d6adc21c073d3b
matches the retained reviewed code exactly. Its entry point uses a nonblocking
flock and exits1 with "Another NAS backup/recovery is running." on contention.
That is a plausible cause, not yet proved by the supplied native journal.

The guarded repair MUST confirm that exact message in the latest failed
invocation before changing anything. Other failures are privately captured for
review and do not permit a patch. It verifies the exact code identity, existing
service command and adequate unit timeout, then changes only the lock statement
to wait up to30minutes on the same lock. No schedule, paths, archive scope,
credentials, retention or recovery commands change. It retains the original
script privately and tests shell syntax before atomic replacement.

It starts the same normal NAS backup outside all shared locks, observes it
without tying it to SSH, and requires a newly completed/uploaded SSD set and
fresh cloud metadata/manifest proof. Normal backup application pauses remain
the existing backup's behavior. It neither kills a competing archive/recovery
job nor starts a second backup process directly. A pending recovery or stopped
container is reported as follow-up, not silently accepted.

Eight local regressions pass, including real flock wait/release and timeout
tests. The exact retained full backup program also passes the replacement SHA
and bash syntax checks locally. Actual failure confirmation, patch and new
backup are pending native execution. Cleanup and both comparison/test projects
remain queued behind current backup health.
