# Tag note for v9.4.0

This repository does not tag or push itself; the owner does, after
reviewing this branch. Once `republish-9.4.1` is merged to `main`, create
an annotated tag with this message:

```
git tag -a v9.4.0 -m "$(cat <<'EOF'
theSHFT encryption module v9.4.0

Mirrors config/encryption.js from app commit
76b0e45770ca640f74074cb3b3a5cb264b300688 (app version 9.4.0, the App Store
build 69 users run).
SHA-256: 3858465c478d475f99c53588349123a3898116d11464d7b602baccdd2989ee43

First republish after the repository sat stale at v7.1.0. See README.md
for scope and the Known limits section, and SECURITY.md to report a
vulnerability.
EOF
)"
git push origin v9.4.0
```
