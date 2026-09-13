#!/usr/bin/env bash
set -euo pipefail

# Harbor ships as a multi-service stack (core/db/redis/registry/jobservice/nginx)
# via the official offline installer; there is no single official compose file to
# vendor here. This script installs and starts Harbor on 127.0.0.1:80 with the
# default admin password, matching tests/docker/44-harbor/pass.txt.
#
# Usage: bash tests/docker/44-harbor/init.sh
version="${HARBOR_VERSION:-v2.11.1}"
dir="${HARBOR_DIR:-/tmp/harbor}"

if [ ! -d "$dir" ]; then
  curl -sSL -o /tmp/harbor.tgz \
    "https://github.com/goharbor/harbor/releases/download/${version}/harbor-offline-installer-${version}.tgz"
  tar xzf /tmp/harbor.tgz -C /tmp
fi

cp "$dir/harbor.yml.tmpl" "$dir/harbor.yml"
sed -i 's/^hostname: .*/hostname: harbor.local/' "$dir/harbor.yml"
# Run plain HTTP on port 80: comment out the https block.
sed -i -e 's/^https:/#https:/' \
       -e 's/^  port: 443/#  port: 443/' \
       -e 's/^  certificate:.*/#  certificate: \/your\/certificate\/path/' \
       -e 's/^  private_key:.*/#  private_key: \/your\/private\/key\/path/' \
       "$dir/harbor.yml"

# install.sh runs `prepare` as root inside a container, so its output config
# files land root-owned; the compose client still needs to read them.
bash "$dir/install.sh" || true
docker run --rm -v "${dir}:${dir}" --entrypoint chmod httpd:2.4-alpine -R a+rX "$dir"
(cd "$dir" && docker compose up -d)

for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/api/v2.0/users || true)"
  [ "$code" = "401" ] && break
  sleep 5
done
echo "harbor ready on http://127.0.0.1 (admin / Harbor12345)"
