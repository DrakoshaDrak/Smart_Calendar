# Calendar Desktop (Qt6) — prototype

This folder contains a minimal Qt6 desktop shell that displays the web frontend inside a QWebEngineView.

Features (iteration #1):
- Start a local HTTP server serving static files from ../web_frontend/dist and open it in an embedded browser (default / PROD).
- Optional --dev-url to open an external dev server (no local server started).
- Simple allowlist for navigation origins; external links open in system browser (unless disabled).
- Injects window.__APP_CONFIG__ (apiBaseUrl + desktop:true) into pages at DocumentCreation.

Build (requires Qt6 with WebEngine modules and CMake):

```bash
cd desktop_qt
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j
```

Run:

Default (PROD): serves ../web_frontend/dist and opens it
```bash
./desktop_app
```

DEV mode:
```bash
./desktop_app --dev-url=http://127.0.0.1:5173 --api-base-url=http://127.0.0.1:8080
```

Options:
- --dev-url=<url>  -> open dev server instead of starting local server
- --api-base-url=<url> -> value injected into window.__APP_CONFIG__.apiBaseUrl
- --dist-dir=<path> -> override dist directory (default ../web_frontend/dist relative to executable)
- --disable-external-open -> block external URLs instead of opening them

Notes:
- The built binary uses QStandardPaths::AppDataLocation to store persistent WebEngine data.
- The local server listens only on 127.0.0.1 and selects an ephemeral port.
