#!/usr/bin/env bash
# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.
#
# Usage: smoke-image.sh COMPONENT LOCAL_IMAGE
# The image must already exist locally; it is resolved once to an immutable ID.
# Live requires a locally available Valkey image. Backend additionally needs
# local PostgreSQL, RabbitMQ and S3-compatible server images; SMOKE_*_IMAGE
# variables may select pinned local references. No image is pulled, and no
# host port or host data is mounted. Backend runs the real migration and API
# entrypoints, but does not test the worker, browser, or external delivery.

set -u -o pipefail

if [[ $# -ne 2 ]]; then printf 'SMOKE ERROR\n'; exit 2; fi
component=$1
case "$component" in web|admin|space|live|backend) ;; *) printf 'SMOKE ERROR\n'; exit 2 ;; esac

image_id=$(docker image inspect "$2" --format '{{.Id}}' 2>/dev/null) || { printf 'SMOKE FAIL %s APP\n' "$component"; exit 1; }
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL %s APP\n' "$component"; exit 1; }
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/plane-smoke.XXXXXXXX" 2>/dev/null) || { printf 'SMOKE FAIL %s APP\n' "$component"; exit 1; }
app_id=''
redis_id=''
db_id=''
mq_id=''
s3_id=''
migrator_id=''
network=''
cleanup() {
  local cleanup_status=0
  [[ -z "$app_id" ]] || docker rm -f "$app_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$migrator_id" ]] || docker rm -f "$migrator_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$s3_id" ]] || docker rm -f "$s3_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$mq_id" ]] || docker rm -f "$mq_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$redis_id" ]] || docker rm -f "$redis_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$db_id" ]] || docker rm -f "$db_id" >/dev/null 2>&1 || cleanup_status=1
  [[ -z "$network" ]] || docker network rm "$network" >/dev/null 2>&1 || cleanup_status=1
  rm -rf "$temp_dir" >/dev/null 2>&1 || cleanup_status=1
  return "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

container_args=(--detach --pull never --memory 768m --pids-limit 256)
probe=''
isolated_network() {
  local network_name
  network_name="plane-smoke-${temp_dir##*.}"
  # An ordinary internal bridge can still reach host services bound to the
  # bridge address. Isolated gateway mode removes that address; fail closed
  # on Docker engines which do not support this option.
  network=$(docker network create --internal --opt com.docker.network.bridge.gateway_mode_ipv4=isolated "$network_name" 2>/dev/null) || { network=''; return 1; }
  [[ "$network" =~ ^[0-9a-f]{64}$ ]] || return 1
  network_mode=$(docker network inspect "$network" --format '{{.Internal}} {{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}' 2>/dev/null) || return 1
  [[ "$network_mode" == 'true isolated' ]]
}

start_redis() {
  local redis_image redis_image_id redis_ready
  redis_image=${SMOKE_REDIS_IMAGE:-valkey/valkey:7.2.11-alpine}
  redis_image_id=$(docker image inspect "$redis_image" --format '{{.Id}}' 2>/dev/null) || return 1
  [[ "$redis_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  redis_id=$(docker run --detach --pull never --network "$network" --network-alias smoke-redis \
    --memory 128m --pids-limit 128 --tmpfs /data:rw,mode=1777 "$redis_image_id" \
    valkey-server --save '' --appendonly no 2>/dev/null) || return 1
  [[ "$redis_id" =~ ^[0-9a-f]{64}$ ]] || return 1
  redis_ready=0
  for ((i=0; i<30; i++)); do
    if timeout 3 docker exec "$redis_id" redis-cli ping >/dev/null 2>&1; then redis_ready=1; break; fi
    sleep 1
  done
  (( redis_ready == 1 ))
}

case "$component" in
  web) container_args+=(--network none); probe='web' ;;
  admin) container_args+=(--network none); probe='admin' ;;
  space) container_args+=(--network none); probe='space' ;;
  live)
    isolated_network || { printf 'SMOKE FAIL live NETWORK\n'; exit 1; }
    start_redis || { printf 'SMOKE FAIL live REDIS\n'; exit 1; }
    container_args+=(--network "$network" --env API_BASE_URL=http://127.0.0.1:9 \
      --env LIVE_SERVER_SECRET_KEY=synthetic-smoke-key --env REDIS_URL=redis://smoke-redis:6379/0)
    probe='live' ;;
  backend)
    isolated_network || { printf 'SMOKE FAIL backend NETWORK\n'; exit 1; }
    start_redis || { printf 'SMOKE FAIL backend REDIS\n'; exit 1; }
    db_image=$(docker image inspect "${SMOKE_POSTGRES_IMAGE:-postgres:15.7-alpine}" --format '{{.Id}}' 2>/dev/null) || { printf 'SMOKE FAIL backend POSTGRES\n'; exit 1; }
    [[ "$db_image" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend POSTGRES\n'; exit 1; }
    mq_image=$(docker image inspect "${SMOKE_RABBIT_IMAGE:-rabbitmq:3.13.6-management-alpine}" --format '{{.Id}}' 2>/dev/null) || { printf 'SMOKE FAIL backend RABBIT\n'; exit 1; }
    [[ "$mq_image" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend RABBIT\n'; exit 1; }
    s3_image=$(docker image inspect "${SMOKE_S3_IMAGE:-pgsty/silo:RELEASE.2026-09-16T00-00-00Z}" --format '{{.Id}}' 2>/dev/null) || { printf 'SMOKE FAIL backend S3\n'; exit 1; }
    [[ "$s3_image" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend S3\n'; exit 1; }
    db_id=$(docker run --detach --pull never --network "$network" --network-alias smoke-db --memory 512m --pids-limit 128 \
      --tmpfs /var/lib/postgresql/data:rw,mode=1777 --env POSTGRES_USER=smoke --env POSTGRES_PASSWORD=synthetic-smoke-db \
      --env POSTGRES_DB=smoke "$db_image" 2>/dev/null) || { printf 'SMOKE FAIL backend POSTGRES\n'; exit 1; }
    [[ "$db_id" =~ ^[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend POSTGRES\n'; exit 1; }
    mq_id=$(docker run --detach --pull never --network "$network" --network-alias smoke-mq --memory 512m --pids-limit 256 \
      --tmpfs /var/lib/rabbitmq:rw,mode=1777 --env RABBITMQ_DEFAULT_USER=smoke --env RABBITMQ_DEFAULT_PASS=synthetic-smoke-mq \
      --env RABBITMQ_DEFAULT_VHOST=smoke "$mq_image" 2>/dev/null) || { printf 'SMOKE FAIL backend RABBIT\n'; exit 1; }
    [[ "$mq_id" =~ ^[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend RABBIT\n'; exit 1; }
    s3_id=$(docker run --detach --pull never --network "$network" --network-alias smoke-s3 --memory 256m --pids-limit 128 \
      --tmpfs /export:rw,mode=1777 --env MINIO_ROOT_USER=smokeuser --env MINIO_ROOT_PASSWORD=synthetic-smoke-s3 \
      "$s3_image" server /export 2>/dev/null) || { printf 'SMOKE FAIL backend S3\n'; exit 1; }
    [[ "$s3_id" =~ ^[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend S3\n'; exit 1; }
    ready=0
    for ((i=0; i<90; i++)); do
      if timeout 4 docker exec "$db_id" pg_isready -U smoke -d smoke >/dev/null 2>&1 && \
         timeout 5 docker exec "$mq_id" rabbitmq-diagnostics -q ping >/dev/null 2>&1; then ready=1; break; fi
      sleep 1
    done
    (( ready == 1 )) || { printf 'SMOKE FAIL backend READINESS\n'; exit 1; }
    backend_env=(--network "$network" --add-host api.github.com:127.0.0.1 \
      --env DJANGO_SETTINGS_MODULE=plane.settings.production --env SECRET_KEY=synthetic-local-smoke-only-key \
      --env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= --env http_proxy= --env https_proxy= --env all_proxy= \
      --env 'NO_PROXY=*' --env 'no_proxy=*' \
      --env DATABASE_URL=postgresql://smoke:synthetic-smoke-db@smoke-db:5432/smoke \
      --env REDIS_URL=redis://smoke-redis:6379/0 --env RABBITMQ_HOST=smoke-mq --env RABBITMQ_PORT=5672 \
      --env RABBITMQ_USER=smoke --env RABBITMQ_PASSWORD=synthetic-smoke-mq --env RABBITMQ_VHOST=smoke \
      --env AWS_ACCESS_KEY_ID=smokeuser --env AWS_SECRET_ACCESS_KEY=synthetic-smoke-s3 \
      --env AWS_S3_ENDPOINT_URL=http://smoke-s3:9000 --env AWS_S3_BUCKET_NAME=plane-smoke \
      --env AWS_REGION=us-east-1 --env USE_MINIO=1 --env GUNICORN_WORKERS=1 \
      --env AWS_EC2_METADATA_DISABLED=true --env IS_TEST=1 --env ALLOWED_HOSTS=127.0.0.1)
    migrator_id=$(docker run --detach --pull never --memory 768m --pids-limit 256 "${backend_env[@]}" \
      --entrypoint /bin/bash "$image_id" ./bin/docker-entrypoint-migrator.sh 2>/dev/null) || { printf 'SMOKE FAIL backend APP\n'; exit 1; }
    [[ "$migrator_id" =~ ^[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL backend APP\n'; exit 1; }
    migration_exit=$(timeout 300 docker wait "$migrator_id" 2>/dev/null) || { printf 'SMOKE FAIL backend MIGRATION\n'; exit 1; }
    [[ "$migration_exit" == 0 ]] || { printf 'SMOKE FAIL backend MIGRATION\n'; exit 1; }
    container_args+=("${backend_env[@]}")
    probe='backend' ;;
esac

app_id=$(docker run "${container_args[@]}" "$image_id" 2>/dev/null) || { printf 'SMOKE FAIL %s APP\n' "$component"; exit 1; }
[[ "$app_id" =~ ^[0-9a-f]{64}$ ]] || { printf 'SMOKE FAIL %s APP\n' "$component"; exit 1; }

ok=0
max_attempts=40
[[ "$component" != backend ]] || max_attempts=120
for ((i=0; i<max_attempts; i++)); do
  case "$probe" in
    web) timeout 4 docker exec "$app_id" curl -fsSL --max-time 2 http://127.0.0.1:3000/ >/dev/null 2>&1 && ok=1 ;;
    admin) timeout 4 docker exec "$app_id" curl -fsSL --max-time 2 http://127.0.0.1:3000/god-mode >/dev/null 2>&1 && ok=1 ;;
    space) timeout 4 docker exec "$app_id" curl -fsSL --max-time 2 http://127.0.0.1:3000/spaces/ >/dev/null 2>&1 && ok=1 ;;
    live) timeout 4 docker exec "$app_id" node -e 'require("http").get("http://127.0.0.1:3000/live/health/",r=>{let s="";r.on("data",c=>s+=c);r.on("end",()=>{try{process.exit(r.statusCode===200&&JSON.parse(s).status==="OK"?0:1)}catch{process.exit(1)}})}).on("error",()=>process.exit(1))' >/dev/null 2>&1 && ok=1 ;;
    backend) timeout 4 docker exec "$app_id" python -c 'import json,urllib.request; r=urllib.request.urlopen("http://127.0.0.1:8000/", timeout=2); assert r.status == 200 and json.load(r).get("status") == "OK"' >/dev/null 2>&1 && ok=1 ;;
  esac
  (( ok == 1 )) && break
  running=$(docker inspect "$app_id" --format '{{.State.Running}}' 2>/dev/null) || break
  [[ "$running" == true ]] || break
  sleep 1
done
if (( ok != 1 )); then printf 'SMOKE FAIL %s STARTUP\n' "$component"; exit 1; fi
if [[ "$component" == backend ]]; then
  # create_bucket logs errors without a nonzero status, so check the actual
  # bucket through the local S3 service before reporting the smoke as passed.
  timeout 10 docker exec "$app_id" python -c 'import boto3; boto3.client("s3", endpoint_url="http://smoke-s3:9000", aws_access_key_id="smokeuser", aws_secret_access_key="synthetic-smoke-s3", region_name="us-east-1").head_bucket(Bucket="plane-smoke")' >/dev/null 2>&1 || { printf 'SMOKE FAIL backend BUCKET\n'; exit 1; }
fi
if ! cleanup; then trap - EXIT; printf 'SMOKE FAIL %s\n' "$component"; exit 1; fi
trap - EXIT
printf 'SMOKE PASS %s\n' "$component"
