# Inclusivity evaluation — links for judges

Six applications, live on Cloudflare. Each judge has an **evaluator ID**, and
every link carries it. That ID gives them their own private copy, so nothing one
judge does can affect another.

## The links

Replace `YOUR_ID` with the judge's assigned ID:

| # | Application | Link |
|---|---|---|
| 1 | Password recovery — no inclusivity specification | `https://llm-auth-s1-case1.japskua.workers.dev/?judge=YOUR_ID` |
| 2 | Password recovery — condition named | `https://llm-auth-s1-case2.japskua.workers.dev/?judge=YOUR_ID` |
| 3 | Password recovery — detailed guidance | `https://llm-auth-s1-case3.japskua.workers.dev/?judge=YOUR_ID` |
| 4 | MFA enrolment — no inclusivity specification | `https://llm-auth-s2-case1.japskua.workers.dev/?judge=YOUR_ID` |
| 5 | MFA enrolment — condition named | `https://llm-auth-s2-case2.japskua.workers.dev/?judge=YOUR_ID` |
| 6 | MFA enrolment — detailed guidance | `https://llm-auth-s2-case3.japskua.workers.dev/?judge=YOUR_ID` |

IDs must be letters, digits, `_` or `-`, up to 32 characters. `evaluator_1`,
`anna`, `p07` are all fine.

> **Do not send this table as-is.** The link names give away which experimental
> condition each application belongs to. Send each judge a plain list of six
> links, numbered, **in a different order for each judge**, with no case labels.

## Message to send a judge

> You will look at six small banking and healthcare web applications and score
> each one for how easy it is to use. Each link below is yours alone — please do
> not share it, and do not use anyone else's.
>
> 1. **Use your phone, or make your browser window narrow** (about the width of
>    a phone). These are mobile web applications.
> 2. **Work through one application at a time, from start to finish**, before
>    moving to the next. Three are about recovering a forgotten password; three
>    are about setting up two-factor authentication.
> 3. **All codes are simulated.** One-time passcodes, reset codes and backup
>    codes appear on screen — there is no real email or SMS. Each application
>    shows its own demo account details on the first screen.
> 4. **The first page may take a couple of seconds to load.** That is the
>    hosting waking up, not the application. Please do not score it.
> 5. Fill in the questionnaire for each application straight after using it.
> 6. If an application gets stuck in a state you cannot get out of, tell me and
>    I will send you a fresh link. Please do not skip to another judge's link.

## Demo accounts, for the coordinator

| Application | Email | Other |
|---|---|---|
| MFA enrolment — no spec | `marcus@example.test` | password `Marcus!2025`, phone `+15551234567` |
| MFA enrolment — condition named | `marcus@northstar.demo` | phone `+15550123456` |
| MFA enrolment — detailed guidance | `marcus@example.com` | — |

The three password-recovery applications each state their account on screen.

## Running the evaluation

**Giving a judge a clean slate.** Issue a new ID. `evaluator_1b` is a brand-new
copy with nothing carried over from `evaluator_1`. This is the fix for a judge
who has locked an account out, used up the backup codes, or reached a state they
cannot leave.

**Checking an application is up:**

```bash
curl https://llm-auth-s2-case3.japskua.workers.dev/healthz
```

**Watching what a judge's instance is doing:**

```bash
bunx wrangler tail llm-auth-s2-case3
```

**When the evaluation is finished**, remove the six Workers so they stop
billing:

```bash
cd human_evaluation_package/deploy_cloudflare
for s in s1-case1 s1-case2 s1-case3 s2-case1 s2-case2 s2-case3; do
  bunx wrangler delete --name "llm-auth-$s"
done
```

## Deployment record

Deployed 2026-08-14. Each Worker serves one artifact, unmodified; the SHA-256
below is printed by the container at startup and matches
`generations/<story>/batch_manifest.json`.

| Worker | Artifact SHA-256 |
|---|---|
| `llm-auth-s1-case1` | `dd919db6c46d435a4395fbd6c5d383fdf23013f639ab84eb58ad2b157be067a6` |
| `llm-auth-s1-case2` | `c43f687abc2a0bd6c32d9c194677456a716e23dd223e7cff75a916ca005d46d1` |
| `llm-auth-s1-case3` | `d320e4bf4ae12b623b125b0cd1c4c1017f170fcd9a28368c182b56f0a146b753` |
| `llm-auth-s2-case1` | `8bc53cae8942e3434619dfbc1959c6a9ae1ffebede51fe946e91eca93618bb98` |
| `llm-auth-s2-case2` | `0f3d6292f9e220cbdffca811d0ddd5f705ab37cb33484e66ff4136891f7e4a0f` |
| `llm-auth-s2-case3` | `e2523743e6748e8fa4d2c78a75fe0c8f0d4948d3cb707513e4d7acf4307a964a` |

Verified in production: all six return `/healthz`, serve their landing page, and
respond with page bodies byte-identical to the same artifacts run locally.
A full journey was completed on `s2-case3` — sign in, enrol an authenticator,
confirm the one-time passcode, receive eight recovery codes, use one — and a
second evaluator ID opened afterwards saw a clean, un-enrolled application,
confirming the per-judge isolation works.
