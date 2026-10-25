# Local Windows demo

This is a browser demo with **seven synthetic devices**. It runs a development
manager on `127.0.0.1` and does not collect data from the computer running it.
There is no device agent, remote enrollment, developer telemetry ingestion or
background sampling in `--demo-only` mode. The example Windows, Linux and macOS
devices are invented fixtures, including their observations and cases.

The launcher needs an ordinary Windows user, Windows PowerShell 5.1 or newer,
**Go 1.27.1 for Windows**, **Node.js 24** and a working `npm.cmd` on `PATH`.
It checks these tools and builds both the manager and dashboard from the current
checkout. It installs no system tools or services and changes no accounts,
permissions, execution policy, certificate trust, firewall or autostart settings.
Use the existing toolchain; do not bypass a script policy to run the demo.

## Start

From the repository root in a normal PowerShell terminal:

```powershell
.\deploy\demo\Start-Demo.ps1
```

If the matching Go toolchain is installed outside `PATH`, select its executable:

```powershell
.\deploy\demo\Start-Demo.ps1 -GoExecutable 'C:\tools\go1.27.1\go\bin\go.exe'
```

The optional flags can be combined. Choose a free port from 1 to 65535, or keep
8787. `-NoBrowser` leaves the browser launch to you:

```powershell
.\deploy\demo\Start-Demo.ps1 -Port 8788 -NoBrowser
```

The script uses existing frontend dependencies. If TypeScript or Vite is missing,
it runs `npm ci` against the checked-in lockfile. Go and npm may need network
access to download build dependencies into their normal caches; this is not a
device-data transfer. The dashboard is rebuilt on every start. First-time builds
can take longer than later starts. A failed build does not launch the manager.

Each start creates a fresh directory under
`.local/demo/<timestamp>-<random-id>/` with its own executable, SQLite database
and manager stdout/stderr logs. Existing sessions and the normal
`.local/state.db` are never reused or removed. Generated dashboard files remain
in `web/dist`. Runtime session files and build outputs are ignored by Git.

The launcher refuses an occupied port without stopping or adopting the existing
process. It starts its manager without a second console window, then verifies
`/api/health`, `/api/capabilities` (`demoOnly: true`) and exactly seven synthetic
devices before opening `http://127.0.0.1:<port>/#/overview`. The loopback address
is fixed; this command does not expose Tracebolt to another computer on the LAN.

## Show the demo

1. Start on **Overview / Übersicht**. Explain that all incidents and metrics are
   synthetic examples; missing or stale data does not prove a healthy device.
2. Open **Devices / Geräte** and show the seven example devices. Search for
   **BER-DC-01** to open its Windows device view.
3. Open its linked DNS service case, inspect the evidence and add a sample note.
   Notes and case changes affect only this demo session's database; no service
   or endpoint is changed.
4. Return to the inventory, clear the search and compare a Linux and macOS
   example. These fixtures do not demonstrate native collection on those systems.
5. Use the theme control to show dark mode and the language selector to switch
   between English and German. Theme/language preferences may remain in this
   browser's local storage even when starting a fresh database.

## Stop and start fresh

Keep the launching terminal open while presenting. Close the browser whenever
you like; that alone does not stop the demo. Press **Ctrl+C in the terminal** to
stop the manager started by that invocation. Normal script exit and startup
errors use the same cleanup path. Other processes and their ports are untouched.

Session files remain available for inspection. Running the command again starts
a new database and restores the original seven fixtures, without deleting notes
or data from prior sessions. The printed session path identifies the logs to
inspect if startup fails. If the port is occupied, stop your own earlier demo
from its terminal or choose another port.

This validates only the local synthetic demonstration. It establishes no native
agent, service installation, reboot behavior, real-device observation, LAN
deployment or release acceptance. For real devices, use the separate
[installation runbook](installation.md) and its approval and trust requirements.

## Verify the demo

With the launcher running, execute the real-browser smoke check from the
repository root (using the existing frontend development dependencies):

```powershell
node .\tests\demo\windows-demo-smoke.mjs
```

For another port, set the nonsecret `TRACEBOLT_DEMO_URL` to its loopback origin
in that terminal. The check refuses non-loopback origins, requires `demoOnly`
and only synthetic devices/cases, and exercises the actual compiled dashboard
and API without mocked responses. It covers EN/DE, desktop/mobile, light/dark,
search, device/case views, note persistence and source labels. It creates only
synthetic test notes in the current session. Start a new session afterward for
a clean presentation. Screenshots/results are in `artifacts/windows-demo-browser`.

The Windows path regression tests cover native SQLite filenames containing
spaces, `#`, `%`, `&` and Unicode, including close/reopen persistence. This does
not establish Unix `0600` permission semantics or protected Linux enrollment
storage on Windows. The LAN manager remains a Linux runtime; neither these
tests nor the demo authorize a Windows production manager or new host grants.
