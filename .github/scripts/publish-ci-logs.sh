#!/usr/bin/env bash
# Publish the tail of a failed CI job to the throwaway `ci-logs` branch.
#
# The actions log endpoint needs a token, so a red run is unreadable from a
# checkout — which is exactly when you need it. Every job calls this on failure
# with JOB_NAME set and its output teed to /tmp/suite.log.
set -u

mkdir -p ci-logs
{
  echo "# ${JOB_NAME:-ci} failure — $(date -u +%FT%TZ) — ${GITHUB_SHA}"
  echo
  echo '## output tail'
  echo '```'
  tail -150 /tmp/suite.log 2>/dev/null || echo '(no log)'
  echo '```'
  echo '## failing tests / checks'
  echo '```'
  grep -E '^(failures:|test .* FAILED|  FAIL|!!! )|^---- ' /tmp/suite.log 2>/dev/null || echo '(none matched)'
  echo '```'
  if [ -f /tmp/anyhop-regress.log ]; then
    echo '## gateway log tail'
    echo '```'
    tail -60 /tmp/anyhop-regress.log
    echo '```'
  fi
} > ci-logs/last-failure.md

cd ci-logs
git init -q -b ci-logs .
git add last-failure.md
git -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "ci: ${JOB_NAME:-ci} failure for ${GITHUB_SHA}"
git push -q --force \
    "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" \
    HEAD:ci-logs
echo "published to the ci-logs branch"
