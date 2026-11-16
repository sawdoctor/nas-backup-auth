# Reviewed Kuma restoration, 16 November 2026

Prepared from the sealed native Kuma/HBA review and current application
acceptance. Current Kuma remains on its reviewed running image ID
sha256:7e56461bcf86c4399a782952d73e1108354024421693806b4314927c40c418f5.

Restore the 15 reviewed NAS monitors; retain 10 paused, including absent
Jellyfin and deferred Dockhand. Restore the original notification
destination (active, not default) and its exact 16 original associations.
Only seven monitor URL fields differ from the staged NAS values.
Private path/query/auth settings, TLS choices, users and history remain
unchanged. The TCP nzbdav monitor already targets the NAS; its unused
legacy URL is not altered.

The worker runs ten isolated regression cases before any live change.
They cover original active/paused choices, private input retention,
identity/configuration drift refusal, atomic SQL controls and unrelated
history retention, idempotence, concurrent edit refusal, transactional
rollback, and recent versus stale HBA journal evidence. Then it validates
the sealed current native plan, saves private before/after controls, stops
only the existing Kuma container, writes control-only SQL, starts the
same container, and checks its exact runtime and control read-back.
A failed application recovery rolls back those controls. No frozen live
database import, image pull, container recreation, or test notification.

HBA completion is accepted separately from the repaired timer's actual
recent successes and exact local identities. If this evidence is
unavailable, HBA remains pending while the Kuma work can continue. No
collector or timer setup is repeated.

The shared backup lock covers the consistent live update. It is released
before the first-heartbeat wait so normal media recovery is not blocked.
Genuine down/pending endpoints are reported, not treated as a reason to
undo correctly restored monitoring or to overwrite application data.

Execution here has no Python runtime. The ten self-tests and live
restoration are pending execution on the NAS; no success is claimed.
The repository unittest wrapper invokes those same isolated cases.
The older HBA unit mock now performs the real atomic cache replacement
required by the already-native-tested freshness correction.

Already accepted: current application imports/updates and boot ownership,
reboot, local/cloud backup with sample restore, media recovery, and
Houndarr/Wizarr/Speedtest controls. Latest user recovery check: no stale
or unavailable media bindings; pending backup recovery records zero.

Remaining after native Kuma/HBA acceptance: original Tracearr controls,
remaining host jobs and cron with bridge retirement at OMV HBA schedule
handover, NAS-only NPM renewal, functional book checks, final acceptance
and handover documentation. Keep the source OptiPlex production freeze,
current NAS image versions/data, Dockmon notify-only policy and Plex
auto-empty-trash off. Deferred Dockhand comparison stays deferred.
