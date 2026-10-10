# Apk DulzInstaller

Android native starter using Kotlin and Jetpack Compose. It provides real login against the existing `/api/v1/auth/login` endpoint, bearer-token session verification, and a list of `PUBLISHED` releases from `/api/v1/client/releases`.

`debug` uses `http://10.0.2.2:8788/api/v1` for an Android Emulator. For a physical device, use the development PC's reachable LAN HTTPS endpoint; `localhost` on a phone is the phone itself. Do not ship the debug URL. Set the production URL in the `release` build type before producing a signed release.

No silent installation or system-security bypass is implemented. A download/install feature must verify SHA-256 and then use Android's user-confirmed `PackageInstaller` flow.
