#!/usr/bin/env bash
set -euo pipefail

# Wait for Nexus REST, set admin password to nexus_pass, disable anonymous.
base="${NEXUS_URL:-http://127.0.0.1:8081}"
pass="${NEXUS_PASS:-nexus_pass}"

for _ in $(seq 1 60); do
  if curl -sf "${base}/service/rest/v1/status" >/dev/null; then
    break
  fi
  sleep 5
done

init="$(docker exec nexus-brute-lab cat /nexus-data/admin.password)"
curl -sf -u "admin:${init}" -X PUT -H 'Content-Type: text/plain' \
  --data "${pass}" \
  "${base}/service/rest/v1/security/users/admin/change-password"
curl -sf -u "admin:${pass}" -X PUT -H 'Content-Type: application/json' \
  --data '{"enabled":false,"userId":"anonymous","realmName":"NexusAuthorizingRealm"}' \
  "${base}/service/rest/v1/security/anonymous" >/dev/null
echo "nexus admin password set; anonymous disabled"
