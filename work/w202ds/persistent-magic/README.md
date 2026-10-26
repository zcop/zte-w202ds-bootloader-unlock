# Persistent-magic build folder

This is where the stock LK is turned into the magic64 carrier.

| File | Purpose |
|---|---|
| `magic64-linux.cpp` | Source for `magic64` (Linux port). |
| `difftool-linux.c` | Source for `difftool` (Linux port). |
| `magic64` | Prebuilt x86-64 Linux binary. Adds the post-verification loader. |
| `difftool` | Prebuilt x86-64 Linux binary. Injects the B2 runtime patch. |
| `uboot_b-stock-trimmed.bin` | Stock LK trimmed to `0x113F18` (no 5 MB partition padding). |
| `setup-build-tools.sh` | Creates the `aarch64-linux-android-*` links `magic64` needs. |

## First-time setup

```sh
./setup-build-tools.sh
```

This links:

```text
aarch64-linux-android-as      -> host aarch64-linux-gnu-as
aarch64-linux-android-ld      -> host aarch64-linux-gnu-ld
aarch64-linux-android-objcopy -> host aarch64-linux-gnu-objcopy
```

`magic64` looks for these names **in its own folder**, not in `PATH`.

## Rebuild the binaries

```sh
g++ -O2 -std=c++17 -o magic64 magic64-linux.cpp
gcc -O2 -o difftool difftool-linux.c
```

## Build checkpoints

```text
uboot_b-stock-trimmed.bin  015b660448597817ca241036ef09a51467b60a40ede711c9d1bbe09a4f5baa51
patched.bin                f14d6e28828676efa5b4e5213bcbe05d8cfb0a62932a18ead2fe30b8e6c7fbd0
```

`magic64` writes `patched.bin` in the current folder. `difftool` reads
`patched.bin` and the B2 LK, then writes the final carrier into
`../persistent-magic-b500/`.
