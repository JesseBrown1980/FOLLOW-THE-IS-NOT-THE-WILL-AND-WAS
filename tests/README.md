# Tests

Run:

```bash
python tests/verify_public_repo.py
```

The verifier checks the exact photo and dependency hashes, LF-only public text,
`json=0` receipt shape, absence of source-video files, absence of common live-secret
signatures, and the zero-hidden-dependency contract. It prints counts and paths only;
it never prints a suspected secret value.
