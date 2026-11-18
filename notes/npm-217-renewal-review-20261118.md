# Current NAS NPM 2.17 renewal handover

The NAS current-image review completed without changing the live proxy. It
identified NPM 2.17.0 in the existing cached image
`sha256:c41c0570868e42a76cf0d406e47c0156704a7ca45feba0971aeb87dead4ec58f`.
Its `/app/internal/certificate.js` SHA256 is
`4a5f1a06aa28af7a0a7eebad7dba7f35d4c1b395cdee5a88bf8ce4a392e15855`,
which also matches the official v2.17.0 source exactly.

The earlier guard expected `renew(access, data)`. Version 2.17.0 accepts
`renew(access, data, options = {})` and reloads nginx once after the normal
sequential renewal batch. This explains the earlier preflight rejection.

`scripts/finish-nas-npm-217-renewal.py` requires the exact native review and
stock source hashes, then reuses the pinned handover and reviewed OOM-default
comparison. It removes only the certificate-module hold and recreates NPM on
the same cached image, network, ports and persistent storage. Existing
configuration checks and guarded-proxy recovery remain in the original
worker. It does not start a competing renewal command.

After the normal batch, it checks enabled-route certificate database expiry,
actual public fullchain files and trusted SNI TLS on previously expired routes.
It records the final outcome separately from renewal-owner startup. If
certificate follow-up remains, a bounded private diagnostic is retained and
uploaded through the existing backup remote; keys and credentials are never
printed or committed.

Validation: 20 local regression tests passed, including the existing runtime,
network, storage and OOM policy checks. The actual captured native source also
passed the exact review/module checks locally. Native restoration and actual
certificate renewal remain pending until the user runs the pinned installer.
