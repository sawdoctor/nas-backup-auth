# HBA cache freshness repair, 16 November 2026

Native evidence: the existing one-minute timer is enabled/active. Its
collector service alternates between successful 60 C readings and
"The existing HBA collector did not refresh its cache". The original
handover journal remains prepared. The failed setup command was
systemctl start nas-hba-temperature-bridge.service.

A bug exists in the bridge's comparison of inode mtime against
time.time_ns() immediately before a fast collection. Linux can assign
coarser inode timestamps. This is consistent with the intermittent
native result; the actual native timestamp delta was not printed.

The correction changes only that exact three-line collection block:
retain the prior cache identity, run the same original collector,
validate the numeric nonsymbolic result, and require a different inode
for an existing cache. The original collector uses atomic rename, so
this proves replacement without comparing timestamps from two clocks.

Old worker SHA256:
fbd591947d67f1e92897008d9ecc892685473007d9b501cc6751ea08afadf60f

Corrected worker SHA256:
55908c698d9368e53b348fc15dfb4164ae2c6e370a587ea7aa9a866b41b97124

The repair helper includes eight isolated regression cases and compiles
the corrected worker before any mutation. It pauses only the existing
timer, lets any collection finish, retains the exact old worker, installs
only the exact known corrected bytes, restores the unchanged timer and
resumes the original two-reading handover. Collector, OMV job, unit
definitions, global cron holds and all application versions/data remain
unchanged.

There is no Python executor in this session. The Python regression suite
has NOT been executed here. The repair worker must run all eight cases
on the NAS before patching. Native success is still pending.

Remaining migration scope: restore the already reviewed 15 Kuma monitors,
original notification associations and reviewed endpoints, then original
Tracearr controls, remaining host jobs/cron, NAS-only certificate renewal,
functional book acceptance and final documentation. At final cron handover,
verify the original OMV HBA dispatcher schedule and retire this temporary
bridge before starting cron. Do not repeat accepted application imports,
playback, reboot, backup/sample restore or mount recovery.
