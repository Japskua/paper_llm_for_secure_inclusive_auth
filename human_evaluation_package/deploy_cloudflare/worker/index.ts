/**
 * Routes each human judge to their own private instance of one evaluated
 * artifact.
 *
 * Why per judge: every artifact keeps its state in process memory, and several
 * key it globally rather than per session. On a shared instance one judge
 * enrolling MFA leaves the next judge looking at an already-enrolled account,
 * and five wrong passwords lock the demo account for everybody for ten minutes.
 * A Container is addressed by name, so `getByName("judge-3")` is all the
 * isolation this needs.
 */
import { Container } from "@cloudflare/containers";

interface Env {
  EVAL_APP: DurableObjectNamespace<EvalApp>;
  ARTIFACT: string;
  ARTIFACT_LABEL: string;
}

export class EvalApp extends Container<Env> {
  defaultPort = 8080;
  requiredPorts = [8080];
  // Long enough that a judge reading the questionnaire between steps does not
  // come back to a cold start, short enough that instances do not linger.
  sleepAfter = "30m";

  onError(error: unknown) {
    console.error("container error", error);
    return new Response("The evaluated application failed to start.", { status: 502 });
  }
}

const COOKIE = "eval_judge";
const JUDGE_RE = /^[A-Za-z0-9_-]{1,32}$/;

function judgeFromRequest(request: Request): string | null {
  const fromQuery = new URL(request.url).searchParams.get("judge");
  if (fromQuery && JUDGE_RE.test(fromQuery)) return fromQuery;

  const cookies = request.headers.get("cookie") ?? "";
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (match && JUDGE_RE.test(match[1])) return match[1];

  return null;
}

function landingPage(label: string, host: string): Response {
  const html = `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${label}</title>
<style>
 body{font:16px/1.6 system-ui,sans-serif;max-width:34rem;margin:12vh auto;padding:0 1.2rem;color:#1a1a1a}
 code{background:#f2f2f2;padding:.15em .4em;border-radius:4px}
 .box{background:#f7f7f7;border-left:4px solid #666;padding:1rem 1.1rem;border-radius:6px}
</style>
<h1>${label}</h1>
<p>This link needs your evaluator ID, so that you get your own private copy of
the application and are not affected by anyone else's session.</p>
<div class="box">
<p>Open the address you were given, which ends in <code>?judge=YOUR_ID</code>:</p>
<p><code>https://${host}/?judge=evaluator_1</code></p>
</div>
<p>If you were not given an ID, ask the study coordinator before continuing.</p>`;
  return new Response(html, {
    status: 400,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true, artifact: env.ARTIFACT });
    }

    const judge = judgeFromRequest(request);
    if (!judge) return landingPage(env.ARTIFACT_LABEL, url.host);

    const container = env.EVAL_APP.getByName(`judge-${judge}`);
    await container.startAndWaitForPorts({
      startOptions: { envVars: { ARTIFACT: env.ARTIFACT } },
    });

    // Strip the routing parameter before the artifact sees it, so a judge's URL
    // bar matches what the application itself thinks it served.
    const fromQuery = url.searchParams.has("judge");
    if (fromQuery) {
      url.searchParams.delete("judge");
      const clean = url.pathname + (url.searchParams.size ? `?${url.searchParams}` : "");
      const redirect = new Response(null, { status: 302, headers: { location: clean } });
      redirect.headers.append(
        "set-cookie",
        `${COOKIE}=${judge}; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=Lax`,
      );
      return redirect;
    }

    return container.fetch(request);
  },
};
