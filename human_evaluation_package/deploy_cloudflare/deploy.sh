#!/usr/bin/env bash
# Deploy one Cloudflare Worker per evaluated artifact. Each Worker owns a
# container image running that artifact and hands every judge their own
# instance.
#
#   ./deploy.sh            deploy all six
#   ./deploy.sh s2_case3   deploy one
#   ./deploy.sh --dry-run  render the configs and stop
set -euo pipefail
cd "$(dirname "$0")"

PREFIX="${WORKER_PREFIX:-llm-auth}"

# slug | artifact file stem | human-readable label
ARTIFACTS=(
  "s1_case1|story1_password_recovery_ADHD__case1_no_spec|Password recovery — no inclusivity specification"
  "s1_case2|story1_password_recovery_ADHD__case2_condition_named|Password recovery — condition named"
  "s1_case3|story1_password_recovery_ADHD__case3_detailed_guidance|Password recovery — detailed guidance"
  "s2_case1|story2_mfa_enrolment_dyslexia__case1_no_spec|MFA enrolment — no inclusivity specification"
  "s2_case2|story2_mfa_enrolment_dyslexia__case2_condition_named|MFA enrolment — condition named"
  "s2_case3|story2_mfa_enrolment_dyslexia__case3_detailed_guidance|MFA enrolment — detailed guidance"
)

DRY_RUN=0
ONLY=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) ONLY="$arg" ;;
  esac
done

command -v npx >/dev/null || { echo "npx is required (install Node.js)" >&2; exit 1; }
[ -d node_modules ] || { echo "installing dependencies..."; npm install; }

for entry in "${ARTIFACTS[@]}"; do
  IFS='|' read -r slug artifact label <<<"$entry"
  [ -n "$ONLY" ] && [ "$ONLY" != "$slug" ] && continue

  [ -f "artifacts/${artifact}.ts" ] || { echo "missing artifacts/${artifact}.ts" >&2; exit 1; }

  worker="${PREFIX}-${slug//_/-}"
  config="wrangler.${slug}.jsonc"
  sed -e "s|__SLUG__|${worker}|g" \
      -e "s|__ARTIFACT__|${artifact}|g" \
      -e "s|__LABEL__|${label}|g" \
      wrangler.template.jsonc > "$config"

  echo
  echo "=== ${worker}"
  echo "    artifact : ${artifact}.ts"
  echo "    sha256   : $(shasum -a 256 "artifacts/${artifact}.ts" | cut -d' ' -f1)"
  echo "    config   : ${config}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "    (dry run, not deployed)"
    continue
  fi

  npx wrangler deploy --config "$config"
done

echo
echo "Done. Each judge opens their own instance with ?judge=<id>, for example:"
echo "  https://${PREFIX}-s2-case3.<your-subdomain>.workers.dev/?judge=evaluator_1"
