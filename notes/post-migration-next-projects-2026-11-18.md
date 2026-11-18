# Current health, cleanup and comparison work

The operational NAS migration is accepted, including the user's existing book
functionality tests. The user has now requested cleanup, current confirmation
of backups/cron/jobs, a Dockhand comparison, and an InfiniDysk 2 beta test.

The current review is observational. It checks actual service execution status
separately from enabled timers and reports backup-lock skips honestly. It reads
the newest completed/uploaded SSD set, compares remote file sizes and the exact
Google Drive checksum manifest, and summarizes successful backup journal events.
It does not repeat a full archive checksum/restore or claim one was done.

Cleanup starts with sizes, current container references and exact retired
Listenarr proxy/certificate references. The initial review deletes nothing.
Production control records, import-active identity, frozen OptiPlex and rollback
roots must be retained; current boot/preflight helpers still depend on them.
Never use blanket Docker pruning or old --commit-core as cleanup.

Dockhand will be evaluated alongside Dockmon on a separate private port/data
directory, with notification-only update checks and no competing deployment,
prune or backup schedule. Compare its container/volume file browser, editing
existing Compose definitions, image update detection, phone layout and resource
use. Existing Compose owners and mount-aware NAS boot services remain authoritative
until a separately reviewed adoption. A Docker socket read-only bind alone is
not a read-only Docker API.

Official sources checked on 18 November: Dockhand manual at
https://dockhand.pro/manual/ and repository Finsys/dockhand; InfiniDysk v2 docs at
https://www.infinidysk.com/v2/ and actual GitHub releases API. The newest beta
returned is v2.0.0-beta.10, published 18 November 2026 04:13:49Z (changelog dated
17 November). Pin a release rather than the moving edge tag for repeatable tests.
The v2 image is ghcr.io/infinidysk/infinidysk-next and the UI/API/WebDAV use port
3000. It has its own config/database and optional native FUSE mount; changing the
production image name alone is not a migration.

Recommended initial beta test: a separate NAS instance/config, private port,
small connection allocation and a few test NZBs. Do not import live Arr
credentials or point it at production media paths. Start with WebDAV/isolated
playback, then evaluate a dedicated FUSE path if needed; do not replace the
production /mnt/nzbdav mount or point the current production Silo library at a
fresh beta database. Do not restart the frozen OptiPlex production daemon to
create a test environment. Actual installation and cleanup depend on the native
health/space/port/reference report and have not yet run.

Eight focused local tests verify job result interpretation and remote backup
inventory mismatch detection. Native current health results remain pending.
