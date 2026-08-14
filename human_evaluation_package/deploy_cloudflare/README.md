# Deploying the six artifacts for inclusivity evaluation

Puts each of the six evaluated applications on a public URL, giving every human
judge their own private instance, without modifying a single byte of any
`app.ts`.

## Why not Cloudflare Pages

Pages serves static assets and Workers-runtime functions. All six artifacts are
**Bun HTTP servers**: `Bun.serve()` with mandatory TLS, `Bun.password`
(argon2id), `node:fs`, and `node:crypto` calls such as `createCipheriv` and
`pbkdf2Sync`. None of that exists on the Workers runtime, and none of the
artifacts fall back to plain HTTP. Making them run on Pages would mean rewriting
them, at which point the judges would be evaluating the rewrite rather than the
model's output — and the security experts reading `source_code/` would be
reading different software from the one the inclusivity experts clicked through.

Cloudflare **Containers** runs the real thing. Each artifact runs under Bun, in
its own VM, exactly as generated.

## Architecture

```
   judge's browser
        │  https, public URL
        ▼
   Cloudflare Worker            worker/index.ts
        │  routes by judge id → getByName("judge-<id>")
        ▼
   Container instance, one per judge
        │  http :8080
        ▼
   proxy.ts   ← harness: presents the request as https://localhost:8443
        │  https :8443 (loopback, self-signed)
        ▼
   artifacts/<name>.ts          ← UNMODIFIED, sha256 matches batch_manifest.json
```

### The two problems this solves

**1. TLS.** The artifacts refuse to start without `certs/cert.pem` and
`certs/key.pem` and serve HTTPS only. Cloudflare reaches a container over plain
HTTP. The image mints a self-signed certificate at build time for the loopback
hop; the certificate the judge's browser sees is Cloudflare's, and is real.

**2. Origin pinning.** Three of the six accept state-changing requests only from
a localhost origin, and two of those hardcode it with no environment override:

| Artifact | Origin rule |
|---|---|
| `story2 … case1_no_spec` | `TRUSTED_ORIGINS` env var, defaults to localhost |
| `story2 … case2_condition_named` | hardcoded: `Origin` must equal the request origin **and** be localhost / 127.0.0.1 / `[::1]` |
| `story2 … case3_detailed_guidance` | hardcoded: https, localhost family, **and** the port must equal `PORT` |

Served from `https://something.workers.dev`, those two would reject every POST
and a judge could not get past the first screen. `proxy.ts` therefore rewrites
`Host`, `Origin` and `Referer` on the inbound hop so the artifact sees a request
from `https://localhost:8443`, which is the only origin it trusts.

Measured, on the strictest of the six:

```
POST /api/signin, Origin: https://llm-auth-s2-case2.example.workers.dev
  straight to the artifact   -> 403   the origin check, working as designed
  through proxy.ts           -> 200
```

**This is a deployment shim, not a patch.** The origin check is fully intact in
the source the security experts read, and the artifact hash is unchanged. What
the shim does is satisfy that check from outside the loopback interface. It must
be disclosed in any write-up of the inclusivity evaluation, in the same way the
smoke test's `PORT` hint is disclosed.

### Why one instance per judge

Every artifact keeps its state in process memory, and several key it globally
rather than per session. Measured on `story2 … case1_no_spec`:

```
judge A completes enrolment       -> /api/mfa/status = enabled:true
judge B, brand-new browser        -> /api/mfa/status = enabled:true
                                     B never sees the enrolment flow at all

judge C types a wrong password 5x -> account locked for 10 minutes
judge D, correct password         -> 401
```

`getByName("judge-<id>")` gives each judge a separate container, so none of that
can happen. The isolation costs nothing beyond the instances themselves.

## Deploying

### Prerequisites

| | Why |
|---|---|
| **Workers Paid plan**, $5/month | Containers is not on the free tier |
| **Docker running locally** | `wrangler deploy` builds the image on your machine and pushes it to Cloudflare's registry. It is not built in the cloud. |
| **Bun** (or Node.js) | for `bunx wrangler`. `bun install` is used because npm hard-errors on a wrangler peer-dependency conflict. |

On an Apple-silicon Mac, Docker builds arm64 by default while Cloudflare runs
linux/amd64. The Dockerfile pins `--platform=linux/amd64` so this is handled;
the first build is slower because it runs under emulation.

### Deploy one first

```bash
cd human_evaluation_package/deploy_cloudflare
bun install
bunx wrangler login

./deploy.sh --dry-run      # render the six configs, print the artifact hashes
./deploy.sh s2_case3       # one artifact, to shake out account-level problems
```

Check it, then do the rest:

```bash
curl https://llm-auth-s2-case3.<subdomain>.workers.dev/healthz
./deploy.sh                # all six
```

This creates six Workers:

| Worker | Artifact |
|---|---|
| `llm-auth-s1-case1` | Password recovery — no inclusivity specification |
| `llm-auth-s1-case2` | Password recovery — condition named |
| `llm-auth-s1-case3` | Password recovery — detailed guidance |
| `llm-auth-s2-case1` | MFA enrolment — no inclusivity specification |
| `llm-auth-s2-case2` | MFA enrolment — condition named |
| `llm-auth-s2-case3` | MFA enrolment — detailed guidance |

Set `WORKER_PREFIX` to rename them. First deploy builds and pushes a container
image per Worker, which takes a few minutes; later deploys are quicker.

### Verifying a deployment

```bash
curl https://llm-auth-s2-case3.<your-subdomain>.workers.dev/healthz
# {"ok":true,"artifact":"story2_mfa_enrolment_dyslexia__case3_detailed_guidance"}
```

Then open `/?judge=smoketest` in a browser and walk one journey end to end
before sending any URL to a judge. Container cold start is 1–3 seconds, so the
first request after an idle period is slow; `sleepAfter` is 30 minutes.

## Handing URLs to judges

Each judge gets an ID and one link per artifact:

```
https://llm-auth-s1-case1.<subdomain>.workers.dev/?judge=evaluator_3
https://llm-auth-s1-case2.<subdomain>.workers.dev/?judge=evaluator_3
...
```

The Worker stores the ID in a cookie and redirects to `/`, so the judge's
address bar stays clean and the artifact's own client-side routing is
unaffected. Opening the bare URL without `?judge=` shows a short page telling
them to use their assigned link.

IDs must match `[A-Za-z0-9_-]{1,32}`. Anything else is ignored, which prevents a
malformed link from silently sharing one instance between two judges.

To give a judge a clean slate, issue a new ID: `evaluator_3b` is a brand-new
container with no state from `evaluator_3`.

**Randomise presentation order per judge.** The URLs say which case each
artifact is, and a judge who works through case 1 → 2 → 3 in order may score
the later ones differently for that reason alone.

## What runs where

| File | Role |
|---|---|
| `artifacts/*.ts` | the six evaluated applications, unmodified |
| `proxy.ts` | harness: TLS termination and origin rewriting |
| `entrypoint.sh` | harness: starts one artifact, waits for it to bind, starts the proxy, exits if either dies |
| `worker/index.ts` | harness: per-judge routing |
| `Dockerfile` | Bun 1.3.14, openssl for the loopback certificate |
| `wrangler.template.jsonc` | rendered per artifact by `deploy.sh` |

## Local check without Cloudflare

The container contents can be exercised directly:

```bash
mkdir -p /tmp/check/certs && cd /tmp/check
cp -r <repo>/human_evaluation_package/deploy_cloudflare/{artifacts,proxy.ts,entrypoint.sh} .
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/key.pem -out certs/cert.pem -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

APP_PORT=8443 PROXY_PORT=8090 \
  ARTIFACT=story2_mfa_enrolment_dyslexia__case3_detailed_guidance ./entrypoint.sh
# then: curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8090/
```

All six were verified this way: each boots and serves 200 through the proxy, and
the two origin-pinned artifacts accept POSTs from a public origin only when the
proxy is in front of them.

### What has and has not been verified

Built and run as a real `linux/amd64` container image:

- all six artifacts boot and serve HTTP 200 through the proxy;
- `uname -m` reports `x86_64`, so the emulated build produces the architecture
  Cloudflare runs;
- a POST from a public origin returns 200 inside the container, where the same
  request straight to the artifact returns 403;
- each artifact's SHA-256 is printed at startup and matches
  `batch_manifest.json`;
- image 259 MB, 265 MB resident while serving.

**Deployed and verified in production on 2026-08-14.** All six Workers are live
at `https://llm-auth-<slug>.japskua.workers.dev`. Each returns `/healthz` naming
its artifact, and each serves page bodies byte-identical to the same artifact run
locally. A full journey was completed on `s2-case3` over the public URL — sign
in, enrol, confirm the OTP, receive eight recovery codes, use one — and a second
evaluator ID opened afterwards saw a clean, un-enrolled application. The origin
rewrite was confirmed on `s2-case2`, the strictest of the six, which returns 200
through the proxy where a direct request from the same public origin returns 403.

Judge links and the coordinator's runbook: [`../JUDGE_LINKS.md`](../JUDGE_LINKS.md).

## If a deploy fails

| Symptom | Cause and fix |
|---|---|
| `Cannot connect to the Docker daemon` | Docker is not running. Start Docker Desktop and retry. |
| `npm error ERESOLVE` on install | wrangler needs `@cloudflare/workers-types@5`. Use `bun install`, which resolves it. |
| `✘ [ERROR] Unauthorized` after the image builds | The account is on the Workers **free** plan. The failing call is `GET /accounts/<id>/containers/me`. `bunx wrangler containers list` states it plainly: *"You do not have access to Cloudflare Containers. Deploying containers requires the Workers Paid plan."* Upgrade at <https://dash.cloudflare.com/?to=/:account/workers/plans> and re-run. Nothing else needs changing — the image, the config and the Worker bundle are all fine at this point. |
| Image pushes, container never becomes healthy | Check `bunx wrangler tail llm-auth-s2-case3`. The entrypoint prints the artifact name, its SHA-256 and `artifact is serving`; if that last line is missing, the artifact itself failed to boot. |
| `exec format error` in the container log | An arm64 image reached the platform. Confirm `--platform=linux/amd64` is still on the `FROM` line and rebuild with `--no-cache`. |
| Container is OOM-killed | Raise `instance_type` from `basic` (1 GiB) to `standard-1` (4 GiB) in `wrangler.template.jsonc` and redeploy. |
| Judge sees the landing page instead of the app | The link is missing `?judge=<id>`, or the ID has characters outside `[A-Za-z0-9_-]`. |
| Every POST returns 403 | The proxy is not in front, or is not rewriting `Origin`. Compare against the local check above, which reproduces the same conditions. |
| First request after a break is slow | Container cold start, 1–3 seconds. Expected; `sleepAfter` is 30 minutes. |

### Cost

**Expect $5–10 in total for a two-week evaluation.** Almost all of it is the
$5/month plan fee; the container usage itself lands in the range of pocket
change.

Containers bill for every 10 ms they are *actively running*, at the allocated
instance size. `basic` is 1 GiB memory, ¼ vCPU, 4 GB disk, and the Workers Paid
plan includes 25 GiB-hours of memory, 375 vCPU-minutes and 200 GB-hours of disk
each month.

The unit that costs money is an **instance-hour**: one judge, one artifact, from
their first request until `sleepAfter` (30 minutes) elapses. A judge who spends
15 minutes on an artifact therefore consumes about 45 minutes — the 30-minute
idle tail dominates, not the work.

| Scenario | Instance-hours | Usage cost | Total incl. plan |
|---|---|---|---|
| 5 judges × 6 artifacts, one sitting each | ~27 | ~$0.07 | **~$5** |
| 10 judges, two sittings each, longer sessions | ~100 | ~$2 | **~$7** |

Sanity check from the built image: 259 MB on disk, 265 MB resident while
serving. `basic` is comfortable, and disk never approaches its allowance.

Two things that actually affect the bill more than usage does:

- **The plan is monthly.** A two-week window that straddles a billing boundary
  is charged twice. Starting early in a billing month is worth more than any
  tuning below.
- **`sleepAfter`.** Lowering it from `30m` to `10m` in `worker/index.ts` roughly
  halves instance-hours, at the price of more 1–3 second cold starts for judges
  who pause to fill in the questionnaire. Given the numbers above, leave it at
  30 minutes — judge experience is worth more than two dollars.

Delete the Workers when the evaluation is finished:

```bash
for s in s1-case1 s1-case2 s1-case3 s2-case1 s2-case2 s2-case3; do
  bunx wrangler delete --name "llm-auth-$s"
done
```
