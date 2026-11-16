# Original Tracearr PostgreSQL cache prerequisite, 16 November 2026

Native comparison fd6b6d86b7c0aacfac1e11062113895c89c0719b,
SHA256 b83e7a898fa635b86a6a351fd39efaa9afd63b70b458bff503aad0783c5e46ee,
stopped at its exact original PostgreSQL image-ID lookup. Plex identity
verification had passed. No original database copy, temporary PostgreSQL
start, production data/control write or production restart occurred.

This does not show a broken running PostgreSQL service. It establishes
that the original frozen image ID is not currently cached. Do not assume
the image was pruned or that there is no source-equivalent local image.

The separate image-aware reviewer preserves the exact installed old worker.
It first runs seven isolated image checks, then uses the already pinned
cache/core helpers to search all local images for the frozen platform,
layers and runtime configuration. A verified equivalent image is allowed
only for the disposable original-database review, never for production.

If none is cached, obtain only the unique saved immutable registry digest
from the verified frozen manifest. Restrict the repository to the recorded
Timescale PostgreSQL image, platform linux/amd64. Do not pull latest, change
tags, Compose, the current running database image, or source-host services.
Check download space and verify all current tag bindings and production
container runtimes before and after. Retain a small cache record and private
download log.

Then continue the same read-only original/current control comparison using
that verified image for its isolated, networkless, disposable PostgreSQL
copy. Keep the live NAS history, Plex connection and request service.
All original copy/checksum, isolation, cleanup and data-selection behavior
is retained. The old worker remains worker.py; the new worker is
tracearr-control-review/worker-with-source-image.py, using
nas-original-tracearr-controls-resume.service.

Seven native tests cover digest normalization, absent/foreign/ambiguous
source digests, changed image configuration, changed layers and changed
platform; the unchanged source image must also match. These are run on the
NAS before any cache request. This executor-free session did not execute
the Python tests or native download/comparison. Native completion remains
pending; publication is not runtime acceptance.

Kuma/HBA are already accepted: all ten Kuma regressions passed natively,
all 15 restored monitors UP, ten paused, original destination/default/16
associations restored; three fresh HBA readings, latest 61 C. Do not rerun.
Source hold, remaining Tracearr controls, host cron/jobs and NAS-only NPM
renewal remain. Functional book checks/final documentation are pending.
