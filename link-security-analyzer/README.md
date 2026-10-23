# TrueIntent Module A

Module A reports explainable indicators about URLs, UPI links, and QR text. It
does not make a final judgment about a link or the user's situation.

## Sandbox threat model

The browser worker opens hostile pages in a disposable, non-root Chromium
context. A fresh context is created for each scan and then closed. Every HTTP
or HTTPS request is checked with netguard before the route is allowed to
continue. Other schemes, WebSockets, media, and downloads are blocked. The
worker does not save page screenshots: it retains a perceptual hash in the
scan's sandbox feature data, never the image itself.
The loopback exception used in the integration test is a private function
argument that defaults to off. It is not an environment setting, and neither
the API nor the Celery task supplies it.

The container uses the non-root `pwuser`, Playwright's Chromium sandbox
(`chromium_sandbox=True`), and the Playwright 1.63.0 seccomp profile from
[`backend/seccomp_profile.json`](backend/seccomp_profile.json). The profile is
the version-matched profile distributed with the official Playwright Docker
support files ([source](https://github.com/microsoft/playwright/blob/v1.63.0/utils/docker/seccomp_profile.json)).
The worker also has CPU, memory, shared-memory, and temporary
filesystem limits in `docker-compose.yml`. These settings have not been
runtime-verified here because Docker Desktop's Linux engine was unavailable.

| Threat | What we do | Residual risk |
|---|---|---|
| A page asks the worker to visit a private or local address | Netguard validates the initial URL and each intercepted request, including redirects and subresources; blocked requests are reported. | DNS can change between validation and Chromium's connection (DNS rebinding). This check-to-connect gap is not fully solved. |
| A page uses a non-web scheme, socket, media stream, or download | Only HTTP/HTTPS requests are continued; WebSockets, media, and downloads are disabled. | Browser bugs or network mechanisms not exposed as routed HTTP requests remain possible; production egress filtering is still required. |
| A hostile page escapes the browser process | Run as non-root, enable Chromium's own sandbox, apply the versioned seccomp profile, and constrain resources. No `--no-sandbox` override is used. | The container and browser are not a complete security boundary; the exact host kernel and Docker configuration matter. Chromium sandbox enablement was configured but not verified in a running container. |
| A compromised worker reaches other services | The worker has no published port and requests pass the URL guard. | The worker shares a Docker network with Redis and PostgreSQL. For production, place it on a restricted network and add an egress firewall rule allowing only public web traffic needed for scans, while denying private, link-local, and service-network ranges. |
| Private scan data is retained in an image | Screenshots exist only in memory; sandbox features retain the perceptual hash and host-only navigation metadata, never image bytes. | Page text and request destinations are transiently processed by Chromium; this does not remove browser or memory risks. |

Production deployments should additionally isolate the worker from the database
and cache networks, limit outbound connections at the host or cloud firewall,
and review the browser image and seccomp profile on every upgrade.
