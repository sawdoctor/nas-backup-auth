# Current NAS NPM certificate renewal handover

Native host-job handover succeeded: current ABS plan3members/3shared libraries,
three permission updates applied by the reviewed provisioner, existing private
libraries retained. Flora empty queue, no restart behavior, original paused push
monitor retained. Archive plan8protected/0errors/0pending/0unmatched/0vault review.
Original OMV cron collected60C after the temporary bridge stopped. All four NAS
timers active and ABS/Flora/CAM watchdog first runs passed. Archive was activating
at the captured instant; this is not a completed-transfer claim. Unit succeeded.

Native NPM usage readout found28 certificates referenced by enabled proxy hosts.
One remains actually expired: certificate71 / proxy30,9November2026. Old other
expired database records are not referenced by these enabled hosts. Domain names
are read natively before changing the owner; no certificate is deleted.

resume-nas-npm-certificate-renewal.py uses the same already-running local image,
removes only the reviewed certificate-held.js bind from the current Dockmon
Compose file, and leaves all application storage, settings, routes and controls.
An unstarted comparison container references the existing network externally,
with no application execution, image pull or new network. It compares current
runtime configuration/mounts/ports, reads the current image's stock module and
checks its syntax with the already-running Node runtime. The probe is removed.

The actual NPM recreate uses the same image and existing Compose owner. Current
environment, persistent mounts, network, HTTPS route, users/access/routing and
certificate settings are checked, permitting only generated hostname/Compose
metadata, equivalent empty DNS representations, removed guard mount and normal
certificate expiry/update timestamps. The normal stock timer startup is observed.
Its built-in sequential renewal batch performs certificate work; no competing
Certbot or additional force-renew/deletion/ForceSSL/HSTS action is requested.

On recovery failure only the saved Compose/held-proxy owner is restored. No
database, key, certificate or application-state snapshot is restored. Source
production remains frozen. The shared NAS backup lock is released before waiting
for renewal outcomes. A still-expired enabled certificate is reported explicitly
without claiming it is fixed. This handover is not final migration acceptance.

Ten local regressions cover scoped mount removal, unstarted/existing-network
handling, exact runtime ports/environment/storage/policy protection, current-image
module checks, safe bounded tar reads and secret-free mismatch messages. Native
execution remains pending. Official v2.16.0 certificate.js was reviewed to confirm
immediate and hourly sequential expiry processing; the installed image's own
module remains authoritative instead of copying that public version into NPM.
