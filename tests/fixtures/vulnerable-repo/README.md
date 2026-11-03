# smoke-test fixture

A deliberately vulnerable mini-project. Every file here exists to make one
engine report something, so `scripts/smoke-test.sh` can prove the whole
pipeline still works — not just that the Python unit tests pass.

Nothing here is a real credential.

Nothing here is meant to be installed either: `package-lock.json` names
`flatmap-stream@0.1.1`, the malicious release behind the 2018 event-stream
attack (GHSA-9x64-5r7x-2q53, MAL-2025-20690). npm removed it, so it cannot be
installed; it is here only so SCA proves it reports malware as malware.
