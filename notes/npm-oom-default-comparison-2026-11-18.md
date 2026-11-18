# NPM nullable OOM policy comparison

Native original renewal attempt stopped during unstarted-probe comparison with
only HostConfig.OomKillDisable differing. Probe cleanup runs in finally. No live
Compose write/recreation, control-plan state or certificate action occurred.
The native archive result meanwhile confirmed inactive/Resultsuccess/exit0.

Moby v28.5.2 hostconfig.go defines OomKillDisable as *bool. daemon_unix.go passes
the value to OCI only when nonnil. OCI runtime-spec v1.2.1 config-linux.md says
the OOM killer is enabled by default; disableOOMKiller=false keeps it enabled,
and true disables it. Therefore unset and explicit false are equivalent for
this one field. Native actual nullable/boolean values are printed before the
comparison; an explicit true change or malformed/nonboolean remains refused.

The small resume loader requires the exact retained original worker SHA256
1348d0c2e23b6967d385bc50217ba7fa1ece56b2e686d7a314be363ee9ac7ce5,
leaves it intact and wraps only its comparison signature. The original current
image, guarded candidate/probe, scoped source-owner/backup checks, stock-module
validation, runtime/route/data protection and renewal transaction remain intact.
New worker-with-oom-defaults.py / nas-production-npm-renewal-resume.service reuse
the existing private work/state. No runtime OOM option is written or changed.

All11 existing regressions and5 targeted regressions pass locally,16 total.
Native corrected preflight and renewal outcome remain pending.
