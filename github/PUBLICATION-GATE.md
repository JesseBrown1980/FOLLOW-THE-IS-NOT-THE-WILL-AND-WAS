# GitHub Publication Gate

GitHub is the public mediator for this repository, not the metal/fabric authority.

Publication passes only when:

1. `python tests/verify_public_repo.py` passes.
2. Every HBP receipt is `json=0` tuple text and every sidecar matches final LF bytes.
3. `REQUIRED_HIDDEN_DEPENDENCIES=0`.
4. Secret-pattern findings are zero.
5. Source-video objects are zero.
6. Exact photo and pinned dependency hashes match `hashes/PINNED-SOURCES.sha256`.
7. A descriptor is not labeled as the full source or a lossless reconstruction
   unless every required residual and decoder dependency is present and counted.

Future workflow access should use least-privilege GitHub permissions and ephemeral
OIDC where an external runtime supports it. No workflow or repository file may
contain a live API token, password, private key, cookie, or account export.

`MEASURED` local tests establish only their named scope. GitHub Actions owns its
workflow conclusion; fabric/canon owns system absorption and runtime claims.
