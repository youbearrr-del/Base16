# Implementation plan

1. Completed: local API, migration-safe SQLite schema, bootstrap admin, v1 authentication, role checks, activity logging, application/device/configuration primitives, and local seeded demonstration data.
2. In progress: complete dashboard CRUD screens, pagination/filter controls, release catalogue and authorized download flow.
3. Planned: replace SQLite adapter with PostgreSQL for deployment, add schema migrations/test suite/rate limiting/CSRF protection, and deploy under HTTPS.
4. Deferred: Firebase Authentication/Firestore/Cloud Functions and native Android code require Firebase project/service-account setup plus Android SDK/Gradle dependencies. They are not claimed as implemented.

Never run an untrusted EXE during this workflow. Do not provide silent installation, root, system-security bypass, or arbitrary remote-code execution features.
