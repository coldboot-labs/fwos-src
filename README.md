# fwos-src

Rust sources for first-party appliance programs. Not OCI recipes.

`fwos-fwd-setup` is the Host program oneshot that creates empty named netns `fwd` and `mgmt`. `fwos` is the Appliance CLI Host program on VGA and serial (first-boot Bootstrap console, then `apply`). `netd` is the built-in addon binary (OCI recipe in `fwos-builtin-addons`). The host image copies binaries at image-build; this tree is not vendored into `fwos-image`.
