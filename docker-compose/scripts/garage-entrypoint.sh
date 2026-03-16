#!/bin/sh
set -eu

GARAGE_BIN="${GARAGE_BIN:-/garage}"
GARAGE_PRIVATE_BUCKET="${GARAGE_PRIVATE_BUCKET:-cb-faynosync-s3-private}"
GARAGE_PUBLIC_BUCKET="${GARAGE_PUBLIC_BUCKET:-cb-faynosync-s3-public}"
GARAGE_ACCESS_KEY="${GARAGE_ACCESS_KEY:?GARAGE_ACCESS_KEY is required}"
GARAGE_SECRET_KEY="${GARAGE_SECRET_KEY:?GARAGE_SECRET_KEY is required}"
GARAGE_KEY_NAME="${GARAGE_KEY_NAME:-faynosync-local-app-key}"
GARAGE_LAYOUT_ZONE="${GARAGE_LAYOUT_ZONE:-dc1}"
GARAGE_LAYOUT_CAPACITY="${GARAGE_LAYOUT_CAPACITY:-1G}"
GARAGE_LAYOUT_VERSION="${GARAGE_LAYOUT_VERSION:-1}"
GARAGE_BOOTSTRAP_TIMEOUT_SECONDS="${GARAGE_BOOTSTRAP_TIMEOUT_SECONDS:-60}"

log() {
  printf '[garage-bootstrap] %s\n' "$*"
}

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

wait_for_server() {
  attempts=0

  while ! "$GARAGE_BIN" status >/dev/null 2>&1; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      log "Garage server exited before bootstrap completed."
      wait "$SERVER_PID"
    fi

    attempts=$((attempts + 1))
    if [ "$attempts" -ge "$GARAGE_BOOTSTRAP_TIMEOUT_SECONDS" ]; then
      log "Timed out waiting for Garage to become ready."
      return 1
    fi

    sleep 1
  done
}

get_node_id() {
  "$GARAGE_BIN" status 2>/dev/null | awk '
    /^====/ { next }
    $1 == "ID" { next }
    $1 ~ /^[0-9a-f]+$/ { print $1; exit }
  '
}

get_layout_version() {
  "$GARAGE_BIN" layout show 2>/dev/null | awk -F': ' '
    /Current cluster layout version/ { print $2; exit }
  '
}

ensure_layout() {
  current_layout_version="$(get_layout_version)"
  if [ -z "$current_layout_version" ]; then
    log "Unable to detect current Garage layout version."
    return 1
  fi

  if [ "$current_layout_version" != "0" ]; then
    log "Garage layout already initialized with version $current_layout_version."
    return 0
  fi

  node_id="$(get_node_id)"
  if [ -z "$node_id" ]; then
    log "Unable to determine Garage node ID."
    return 1
  fi

  log "Applying initial Garage layout version $GARAGE_LAYOUT_VERSION for node $node_id."
  "$GARAGE_BIN" layout assign -z "$GARAGE_LAYOUT_ZONE" -c "$GARAGE_LAYOUT_CAPACITY" "$node_id"
  "$GARAGE_BIN" layout apply --version "$GARAGE_LAYOUT_VERSION"
}

ensure_bucket() {
  bucket_name="$1"

  if "$GARAGE_BIN" bucket info "$bucket_name" >/dev/null 2>&1; then
    log "Bucket already exists: $bucket_name"
    return 0
  fi

  log "Creating bucket: $bucket_name"
  "$GARAGE_BIN" bucket create "$bucket_name"
}

ensure_key() {
  if "$GARAGE_BIN" key info "$GARAGE_ACCESS_KEY" >/dev/null 2>&1; then
    current_secret="$("$GARAGE_BIN" key info --show-secret "$GARAGE_ACCESS_KEY" 2>/dev/null \
      | awk -F': ' '/Secret key/ { gsub(/^ +| +$/, "", $2); print $2; exit }'
    )"

    if [ -n "$current_secret" ] && [ "$current_secret" != "$GARAGE_SECRET_KEY" ]; then
      log "Garage access key $GARAGE_ACCESS_KEY already exists with a different secret."
      return 1
    fi

    log "Garage access key already imported: $GARAGE_ACCESS_KEY"
    return 0
  fi

  log "Importing Garage access key: $GARAGE_ACCESS_KEY"
  "$GARAGE_BIN" key import --yes -n "$GARAGE_KEY_NAME" "$GARAGE_ACCESS_KEY" "$GARAGE_SECRET_KEY"
}

ensure_bucket_access() {
  bucket_name="$1"

  log "Ensuring access permissions for bucket: $bucket_name"
  "$GARAGE_BIN" bucket allow --read --write --owner "$bucket_name" --key "$GARAGE_ACCESS_KEY"
}

ensure_public_website() {
  log "Ensuring website access is enabled for bucket: $GARAGE_PUBLIC_BUCKET"
  "$GARAGE_BIN" bucket website --allow "$GARAGE_PUBLIC_BUCKET"
}

log "Starting Garage server."
"$GARAGE_BIN" server &
SERVER_PID=$!

wait_for_server
ensure_layout
ensure_bucket "$GARAGE_PRIVATE_BUCKET"
ensure_bucket "$GARAGE_PUBLIC_BUCKET"
ensure_key
ensure_bucket_access "$GARAGE_PRIVATE_BUCKET"
ensure_bucket_access "$GARAGE_PUBLIC_BUCKET"
ensure_public_website

log "Garage bootstrap completed successfully."
trap - EXIT
wait "$SERVER_PID"
