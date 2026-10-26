# Stock images for this build

Only the two images needed for the persistent unlock are included. The full
partition dump is much larger and is **not** in this repository.

| File | Size | SHA-256 |
|---|---:|---|
| `uboot_b.bin` | 5,242,880 | `0ae123503d1fedb4d9cdf7b6bdab1ad9f5f9cf1aa5077605c4bf79a26050ad70` |
| `splloader.bin` | 262,144 | `77a4fa3d739dfd6b333ed3c81301d59397445c246cd6def8ec9d4151c217a47d` |

These are the stock slot-B images from the test device. They are not generic.
Keep the original full backup elsewhere; these files alone cannot restore
`super`, `vbmeta`, or the other partitions.

The build scripts also expect these paths. If you replace them with a dump
from another device, the hashes in `magic-b500-run.sh` will fail — which is
intentional.
