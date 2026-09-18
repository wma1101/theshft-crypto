# Tag note for v9.4.1

This repository does not tag or push itself; the owner does, after
reviewing this branch. Once `republish-9.4.1` is merged to `main`, create
an annotated tag with this message:

```
git tag -a v9.4.1 -m "$(cat <<'EOF'
theSHFT encryption module v9.4.1

Mirrors config/encryption.js from app commit
3d4616a6dc31f6a0060b515087dbdcab0fa970e7 (app version 9.4.1).
SHA-256: f73e977b33999d0b32398a1c2d3f0e5c4e6cfc880b33aa6b4b3a641257b1f822

First republish after the repository sat stale at v7.1.0. See README.md
for scope and the Known limits section, and SECURITY.md to report a
vulnerability.
EOF
)"
git push origin v9.4.1
```
