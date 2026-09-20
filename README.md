# fwos-src

Rust sources for first-party appliance programs. Not OCI recipes.

Bootstrap creates the first administrator in durable FWOS-local Identity configuration, separate from network Desired state. The Appliance console and HTTPS UI share credential verification and a source-qualified authorization boundary; v1 implements local accounts only. HTTPS sessions are held in memory: logout revokes them, and a UI restart or appliance reboot invalidates them.

`fwos-fwd-setup` is the Network startup program: it creates `fwd` and `mgmt`, prepares their fixed links and the Host netns connection, and moves Traffic NICs into `fwd` before netd starts. It then exits; netd owns ongoing network policy and does not enter the Host or Management netns.

`fwos` is the Appliance CLI Host program on VGA and serial (first-boot Bootstrap console, then admin apply of full Desired state and a Host update socket client). `fwos-update` is the Host update program: it wraps `bootc` in the Host netns and listens on a unix socket on `/var`; staging does not reboot, and `reboot` is an explicit Appliance CLI step. After that reboot it checks appliance health (default target, fwd/mgmt, netd) and rolls back the bootc deployment if the new Release is not a working appliance. Desired state that fails to apply does not roll back. Manual `rollback` remains. `netd` is the built-in addon binary (OCI recipe in `fwos-builtin-addons`). `fwos-ui` is the UI built-in addon binary: HTTPS JSON plus a static JS SPA, unix-socket client of `netd` (not of the Host update program). The host image copies binaries at image-build; this tree is not vendored into `fwos-image`.
