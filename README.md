# traefik-gate

A tiny cookie-based access gate for Traefik's
[`forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/)
middleware. Users authenticate once via a password form and receive a 30-day
HMAC-signed cookie — replacing basic auth, which re-prompts on every browser
session and breaks multi-user demo flows.

Single-file Python stdlib HTTP server, no dependencies. ~50MB image.

## How it works

1. Traefik routes every request through the `forwardAuth` middleware, which
   calls this gate.
2. Cookie valid → `200` → Traefik lets the request through.
3. No/invalid cookie → `307` redirect to `/__gate/login` (served by this app via
   its own Traefik router), which sets the cookie on a correct password and
   redirects back to the original URL.

## Configuration

| Env var | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GATE_PASSWORD` | yes | — | The password users enter |
| `GATE_SECRET_KEY` | yes | — | HMAC key that signs the cookie |
| `GATE_COOKIE_MAX_AGE` | no | `2592000` (30d) | Cookie lifetime, seconds |
| `GATE_COOKIE_NAME` | no | `__boxrank_gate` | Cookie name |
| `PORT` | no | `8080` | Listen port |

## Traefik wiring (example)

```yaml
# middleware on the protected routers
traefik.http.middlewares.my-gate.forwardauth.address: http://<gate-host>:<gate-port>
traefik.http.middlewares.my-gate.forwardauth.authResponseHeaders: Set-Cookie

# public router for the login page (no auth middleware on this one!)
traefik.http.routers.my-gate.rule: PathPrefix(`/__gate`) && Host(`example.com`)
traefik.http.routers.my-gate.priority: 100
```

## Image

Built by GitHub Actions and published to GitHub Packages:

```
ghcr.io/<owner>/traefik-gate:<version>
```

- Push to `main` → `:latest` + `:sha-<short>`
- Tag `vX.Y.Z` → `:X.Y.Z`, `:X.Y` and `:latest`

Pin a version tag in consumers (the boxrank `gate.nomad.j2` job's
`gate_docker_image` var) rather than `:latest`, so gate rollouts are deliberate
and reproducible.

**One-time setup after the first publish:** GHCR packages start private. Make it
public under the package's *Package settings → Danger Zone → Change visibility*,
so the Nomad hosts can pull without registry credentials.

## Local run

```bash
docker build -t traefik-gate .
docker run -e GATE_PASSWORD=letmein -e GATE_SECRET_KEY=dev-secret -p 8080:8080 traefik-gate
# then: curl -i localhost:8080/            -> 307 to the login page
#       curl -i localhost:8080/__gate/login -> 200 login form
```
