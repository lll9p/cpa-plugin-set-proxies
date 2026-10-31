# cpa-plugin-set-proxies

A CLIProxyAPI native plugin that assigns working Webshare SOCKS5 proxies to file-backed credentials. It embeds a Chinese management page and needs no CPA backend source changes, Python runtime, or separate HTTP listener. The page reuses the management frontend's remembered login, with no separate plugin login. No CPA, management frontend, or Compose changes are required.

## Install from the CPA plugin store

Publish this repository and a stable GitHub Release first, then add its registry URL to the existing `plugins` section of your CPA configuration:

```yaml
plugins:
  enabled: true
  dir: plugins
  store-sources:
    - https://raw.githubusercontent.com/lll9p/cpa-plugin-set-proxies/master/registry.json
  configs:
    cpa-plugin-set-proxies:
      enabled: true
```

Keep any other configured sources and plugins. Reload the CPA configuration or restart CPA, open the plugin store, select this source, and install **Webshare Proxy Assignment**. Restart CPA if requested, then open **代理分配** from the plugin menu. The registry uses the latest stable GitHub Release; no version needs to be maintained in `registry.json`.

The release must include the ZIP for your CPA process's operating system and architecture plus `checksums.txt`. GitHub's automatically generated source ZIP is not an installable plugin. For private repositories, configure CPA's plugin store authentication separately.

## Build and install manually

Requires Go 1.26+, GNU Make, a C compiler, and CGO. Make targets use a Bash-compatible shell, including on Windows. Build for the same operating system and architecture as the CPA process. Cross-compiling a shared library also requires the matching C toolchain.

```bash
make build
# Linux example; use .dylib on macOS or .dll on Windows.
cp build/cpa-plugin-set-proxies.so /path/to/cpa/plugins/
```

The binary basename must be `cpa-plugin-set-proxies`. Plugin metadata points to [this repository](https://github.com/lll9p/cpa-plugin-set-proxies). Enable it in CPA's configuration (see `config.example.yaml`):

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    cpa-plugin-set-proxies:
      enabled: true
```

Restart CPA after manual installation. Open **代理分配** from your management frontend's plugin menu after logging into CPA with **remember password** enabled. Its static resource is:

```text
/v0/resource/plugins/cpa-plugin-set-proxies/ui
```

This version targets CPA's current C ABI 1 / RPC schema 6, with the existing v8 credential endpoints. It is not a compatibility shim for older v7 credential APIs.

## Usage

1. Open **代理分配** from your already authenticated CPA management frontend. There is no separate plugin login or logout. The plugin reads the panel's existing `cli-proxy-auth` login record to authenticate its own same-origin requests. It never writes browser storage.
2. On first setup, enter the **CPA 管理密码**, Webshare download URL, and excluded credential filenames, then choose **保存设置**. Settings are persisted at `data/cpa-plugin-set-proxies/settings.json`, relative to CPA's working directory. The backend validates an explicitly supplied password with a read-only CPA request before saving it. Settings and serialized snapshots are limited to 64 KiB. No old plugin configuration or `WEBSHARE_URL` is read, imported, or migrated.
3. Choose **扫描并预览**. The backend downloads the saved proxy list, checks up to 24 proxies concurrently, and generates a preview without modifying credentials.
4. Review the proposed assignments, then confirm **应用变更**. Application runs in the backend: closing the browser or logging out of the panel does not stop it. Reopen the plugin from the panel to see its current progress.

The settings section shows **管理密码：已设置 / 未设置**. With a saved password, its input stays hidden. **更换密码** opens it; **保存密码** updates only the backend password, preserving the URL, exclusions, and unsaved page drafts. An omitted or blank `management_key` preserves the saved value. Ordinary saves and incoming Authorization headers never rotate it. Failed validation keeps the old settings and preview. Saved passwords are never returned to the page; successfully submitted inputs are cleared. A backend CPA authentication failure prompts a password update without disconnecting the management page. Manager Plus users should enter the real upstream CPA management password, not Manager Plus's potentially different admin password.

The backend performs a native credential check before each item and sends only `name` and `proxy_url` to `PATCH /v8/management/credentials/fields`. It never writes entire credential files. Cancellation stops subsequent items but does not abort an in-flight PATCH or roll back completed updates. An uncertain outcome is reported as unknown and is never automatically retried; scan again to inspect the actual state.

Plans expire after ten minutes. Scanning again, cancelling, disabling, or reconfiguring the plugin invalidates the previous plan. Jobs and results exist only in memory: restarting CPA discards them, invalidates plans, and never resumes unfinished work. Saved settings remain; there is no task history or database.

## Management frontend authentication

Only the plugin needs updating. Stock native CPA and CPA Manager Plus can embed the plugin directly: the UI reads the existing `cli-proxy-auth` localStorage record, without creating, changing, migrating, or deleting it. Plain JSON and the v1/v2 obfuscation formats used by these frontends are supported. The API origin and path prefix must match the plugin's own CPA instance; credentials for another server are not used.

Enable **remember password** when logging into your management frontend so that record includes its credential. Without a readable remembered login, the plugin shows a short prompt and a refresh button, not another login form. An already-installed `window.cpaPluginHost` v1 request bridge is still supported, but is optional.

The page sends only its own state/settings/scan/apply/cancel requests to CPA's authenticated plugin routes. It never reads complete credential files or sends field-update PATCHes. All downloads, probing, and credential updates run in the backend with the separately saved CPA management password. A Manager Plus login credential is not copied into that backend setting.

Logout or a changed remembered connection clears the UI and stops watching the job; it does not cancel the backend job. Each request checks its connection before sending and after reading its response. Storage changes in other tabs are observed immediately; changes in the embedding page are checked once per second because browsers do not send a storage event back to the writing document.

The frontend and plugin must be same-origin, consistent with CPA's `frame-ancestors 'self'` policy. Other frontends can use the same login record or the optional request bridge. The plugin does not inspect private framework state or intercept the management page's requests. No management frontend rebuild or alternate panel asset is needed. The plugin installer does not select or replace a frontend.

## Assignment policy

- Keep an existing Webshare proxy when the endpoint and credentials are still live.
- Assign a proxy to empty/null settings or recognized Webshare settings that are no longer live.
- Infer Webshare ownership from an endpoint or username/password pair in the downloaded list. Unknown ownership is not permission to overwrite.
- Preserve external proxies, `direct`, `none`, and malformed URLs. Support both `socks5` and `socks5h` existing settings, including percent-encoded user information.
- Prefer unused live endpoints, then cycle through the full live pool in stable order.
- Skip excluded and non-file-backed credentials. Deduplicate physical files.
- Abort planning if the proxy list is unusable, no proxies pass, or any required credential cannot be read.

The health check performs an authenticated SOCKS5 connection and verified TLS handshake to `www.cloudflare.com:443`, with up to three 15-second attempts per proxy. It does not call a model provider. Passing it is not a guarantee that a proxy can access every model service.

Downloads expect one `host:port:username:password` proxy per line, up to 16 MiB. Failures distinguish HTTP status, DNS, TLS, timeout, an empty body, and an unrecognized list format without exposing the URL or response body. Webshare's HTTP 404 `Plan not found` means the selected plan could not be found: regenerate the download URL from the intended current plan, save it, then scan again. The plugin does not remove plan selectors or silently download a different plan.

## Security and limitations

The publicly navigable resource serves only static HTML/CSS/JavaScript. Settings, scan, status, cancellation, and application use CPA's existing authenticated plugin management routes. No credential changes are triggered by a public GET. The frontend never writes credential files or downloads complete credential JSON. It reads only preview/progress data and edits plugin settings through authenticated routes.

The preview exposes endpoints, not proxy passwords, credential JSON, or tokens. GET state returns configuration indicators (including `management_key_set`), exclusions, and progress, never the saved key or Webshare URL. No saved secret is returned to the browser. Use HTTPS for remote management and trust every plugin loaded into CPA's process.

Settings contain plaintext secrets. New settings directories use mode 0700 and files use 0600; replacement uses a synced, closed temporary file in the same directory followed by rename. Invalid, oversized, or unreadable settings produce a sanitized error and are not silently overwritten. Protect the data directory and all backup copies. On Windows, Go permission bits do not implement a full ACL: restrict inherited directory/file ACLs to the CPA service account and authorized administrators yourself.

A token refresh does not conflict with this plugin's field-level write. However, CPA's current PATCH endpoint has no atomic compare-and-set parameter for `proxy_url`: a simultaneous manual proxy edit in the short interval between the final check and PATCH could be overwritten. Do not run multiple application tabs or edit proxies during application.

The backend resolves its CPA management endpoint from CPA's own local configuration. With a nonblank `PGSTORE_DSN` / `pgstore_dsn`, it reads CPA's PostgreSQL config mirror at `<base>/pgstore/config/config.yaml`, ignoring `-config` as CPA does. The base is `PGSTORE_LOCAL_PATH` / `pgstore_local_path`, otherwise `WRITABLE_PATH` / `writable_path`, otherwise CPA's working directory (for example, `/CLIProxyAPI/pgstore/config/config.yaml`). Environment values are trimmed; the first nonblank uppercase/lowercase value wins. PostgreSQL takes precedence over git/object-store environment settings, matching CPA; Home mode still takes precedence and is unsupported. Without PostgreSQL, it reads the startup configuration selected by `-config` / `--config` (including `=path` forms), or `config.yaml` in CPA's working directory; git/object-store modes are unsupported. It reads the canonical `server.host`, required `server.port` (1–65535), and `server.tls.enable` fields. Empty/`0.0.0.0` binds resolve to `127.0.0.1`; `::` resolves to `::1`; other hosts are preserved. TLS uses normal certificate verification: the certificate must be trusted and valid for the resolved host. There is no configurable CPA URL/port, address fallback, port scanning, or insecure TLS bypass. CLI flag boundaries and validation still apply in PostgreSQL mode; unknown or invalid flags are rejected. Unsupported modes and missing, unreadable, or invalid selected configs fail explicitly without falling back to another config or guessing an address.

Credential changes use v8 endpoints; plugin-owned actions retain CPA's existing `/v0/management/plugins/...` extension path without changing CPA itself. This is not a durable job queue or scheduled service.

### Docker persistence

Mount the entire settings directory (not just `settings.json`, because writes replace it atomically) at the path relative to the container's CPA working directory. For example, if CPA runs in `/app` on Linux:

```bash
mkdir -p /opt/cpa/data/cpa-plugin-set-proxies
chmod 700 /opt/cpa/data/cpa-plugin-set-proxies
# Set ownership to the UID/GID running CPA before starting the container.
```

```yaml
services:
  cli-proxy-api:
    working_dir: /app
    volumes:
      - /opt/cpa/data/cpa-plugin-set-proxies:/app/data/cpa-plugin-set-proxies
```

Keep the CPA startup config accessible inside the container at its selected path as well. Adjust `/app` to the image's actual working directory, and back up the settings volume securely.

## Development and offline verification

```bash
make fmt    # Format Go sources
make check  # Check formatting, go vet, Go race tests, and JavaScript tests
make build  # Build the native shared library
make clean  # Remove build/ and dist/ only
```

Use Node.js 24+ for JavaScript tests; it is not a plugin runtime dependency. Tests use no production credentials or external proxy services. Race tests require CGO and a working C compiler (MinGW-w64 GCC on Windows).

Tool commands can be overridden, for example `make check GO=/path/to/go`. Without Make, run the equivalent commands directly:

```bash
gofmt -l cmd internal  # Must produce no output
go vet ./...
CGO_ENABLED=1 go test -race ./...
node --test test_ui.mjs
# Build example for Linux; choose .dylib on macOS or .dll on Windows.
CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -o build/cpa-plugin-set-proxies.so ./cmd/cpa-plugin-set-proxies
```

Build output, release archives, local `.env` files, local CPA configuration, and `/data/` (including saved plugin secrets) are ignored. Keep `go.mod`, `go.sum`, and `config.example.yaml` in version control. Do not put real proxy URLs, passwords, or credential files in tracked examples; `.gitignore` is not a secrets scanner.

## CI and releases

Branch pushes and pull requests run `make check build`: formatting, `go vet`, Go race tests, JavaScript tests, and a native shared-library build. A branch push does not create a release.

The `v*` tag workflow runs these checks again, then builds the following native libraries:

| OS | Architectures | Library |
| --- | --- | --- |
| Linux (glibc 2.17+) | amd64, arm64 | `cpa-plugin-set-proxies.so` |
| macOS | amd64, arm64 | `cpa-plugin-set-proxies.dylib` |
| Windows | amd64 | `cpa-plugin-set-proxies.dll` |

For version `1.0.0`, the Linux amd64 store asset is `cpa-plugin-set-proxies_1.0.0_linux_amd64.zip`, containing only `cpa-plugin-set-proxies.so` at the ZIP root. Other platforms follow the same `<id>_<version>_<os>_<arch>.zip` convention. The workflow publishes these ZIPs, optional Unix tarballs, and a single `checksums.txt` containing SHA-256 hashes of the release archives.

To publish:

1. Set `pluginVersion` in `internal/plugin/plugin.go` to the intended version (currently `1.0.0`).
2. Commit the source, `registry.json`, and `.github/workflows/` changes. Push the branch and let CI pass.
3. Push a matching tag. For the current version:

   ```bash
   git push origin master
   git tag v1.0.0
   git push origin v1.0.0
   ```

4. Wait for the **Release** workflow to finish and confirm that the GitHub Release contains all five ZIPs and `checksums.txt`.
5. Refresh your configured source in CPA's plugin store and install the plugin.

A tag that does not match `pluginVersion` fails the build. GitHub Actions must be enabled for the repository; the release job uses the repository's `GITHUB_TOKEN` with `contents: write` permission. No personal access token or manually uploaded binary is required for a public repository.
