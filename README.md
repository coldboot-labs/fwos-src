# fwos-src

Rust sources for first-party appliance programs. Not OCI recipes.

`fwos-fwd-setup` is the Host program oneshot that creates empty named netns `fwd` and `mgmt`. The host image copies the binary at image-build; this tree is not vendored into `fwos-image`.
