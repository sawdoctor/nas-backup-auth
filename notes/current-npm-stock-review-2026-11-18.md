# Current-image NPM source review after preflight stop

Native OOM comparison passed with actual currentnull/probefalse, effectivefalse
on both. The next stock-module pattern check failed, before live Compose/state
changes or proxy recreation. The probe was removed by finally. No assumption
about the exact NPM version/module format is justified by this stop alone.

inspect-nas-current-npm-certificate-module.py reuses the exact retained original
and OOM-corrected helpers. It intercepts the stock-file check and privately copies
the current local image's certificate.js plus selected package metadata, prints
hash/version metadata and unconditionally unwinds the probe cleanup before any
live action. An existing live handover state prevents replay. No image is pulled,
probe started, certificate action requested or live proxy data changed. The
existing private backup connection uploads this bounded review without sharing.

Three local regressions verify exact CJS/ESM preservation, bounded package/source
validation and unconditional interruption before apply with cleanup. Native
review remains pending. Review actual code before altering behavior checks.
