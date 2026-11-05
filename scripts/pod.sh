#!/usr/bin/env bash
# Manage the AdGuard Stats pod with podman.
#   scripts/pod.sh build|start|stop|restart|down|update|logs|status|backup|install-systemd|uninstall-systemd
set -euo pipefail
cd "$(dirname "$0")/.."

POD=adguard-stats
CTR=adguard-stats-app
IMAGE=localhost/adguard-stats:latest
VOLUME=${VOLUME:-adguard-stats-data}
ENV_FILE=${ENV_FILE:-$PWD/.env}
HEALTH_CMD="python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=5)\""

envval() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- || true; }
need_env() {
  if [[ ! -f $ENV_FILE ]]; then
    echo "Missing $ENV_FILE. Create it:  cp .env.example .env && chmod 600 .env  (then edit it)" >&2
    exit 1
  fi
}
HOST_PORT=$(envval HOST_PORT); HOST_PORT=${HOST_PORT:-8080}
HOST_BIND=$(envval HOST_BIND); HOST_BIND=${HOST_BIND:-0.0.0.0}

build() { podman build --pull=newer -t "$IMAGE" -f Containerfile .; }

start() {
  need_env
  podman image exists "$IMAGE" || build
  if ! podman pod exists "$POD"; then
    podman pod create --name "$POD" -p "$HOST_BIND:$HOST_PORT:8080"
  fi
  podman rm -f --ignore "$CTR" >/dev/null
  podman run -d --pod "$POD" --name "$CTR" \
    --env-file "$ENV_FILE" \
    -v "$VOLUME:/data:Z" \
    --restart unless-stopped \
    --health-cmd "$HEALTH_CMD" --health-interval 60s --health-retries 3 \
    "$IMAGE" >/dev/null
  echo "AdGuard Stats running on http://$HOST_BIND:$HOST_PORT  (logs: $0 logs)"
}

stop() { podman pod stop "$POD"; }
down() { podman pod rm -f "$POD"; echo "Pod removed. Data is kept in volume '$VOLUME'."; }
update() { build; start; podman image prune -f >/dev/null; }
logs() { podman logs -f --tail 200 "$CTR"; }
status() { podman pod ps --filter "name=$POD"; podman ps -a --pod --filter "pod=$POD"; }

backup() {
  local out="backup-$(date +%Y%m%d-%H%M%S).db"
  podman exec "$CTR" python -c "import sqlite3; s=sqlite3.connect('/data/stats.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close()"
  podman cp "$CTR:/data/backup.db" "$out"
  podman exec "$CTR" rm -f /data/backup.db
  echo "Wrote $out"
}

# Quadlet units (podman >= 5.0) so the pod starts at boot via systemd.
quadlet_dir() { if [[ $EUID -eq 0 ]]; then echo /etc/containers/systemd; else echo "$HOME/.config/containers/systemd"; fi; }
sysctl() { if [[ $EUID -eq 0 ]]; then systemctl "$@"; else systemctl --user "$@"; fi; }

install_systemd() {
  need_env
  podman image exists "$IMAGE" || build
  local dir; dir=$(quadlet_dir)
  mkdir -p "$dir"
  cat >"$dir/$POD.pod" <<EOF
[Unit]
Description=AdGuard Stats pod

[Pod]
PodName=$POD
PublishPort=$HOST_BIND:$HOST_PORT:8080

[Install]
WantedBy=default.target
EOF
  cat >"$dir/$POD.container" <<EOF
[Unit]
Description=AdGuard Stats dashboard and collector

[Container]
Image=$IMAGE
ContainerName=$CTR
Pod=$POD.pod
EnvironmentFile=$ENV_FILE
Volume=$VOLUME:/data:Z
HealthCmd=$HEALTH_CMD
HealthInterval=60s

[Service]
Restart=always

[Install]
WantedBy=default.target
EOF
  podman pod rm -f --ignore "$POD" >/dev/null
  sysctl daemon-reload
  sysctl start "$POD-pod.service"
  echo "Installed quadlet units in $dir and started $POD-pod.service"
  [[ $EUID -ne 0 ]] && echo "For start at boot without login run once:  loginctl enable-linger $USER"
}

uninstall_systemd() {
  local dir; dir=$(quadlet_dir)
  sysctl stop "$POD-pod.service" || true
  rm -f "$dir/$POD.pod" "$dir/$POD.container"
  sysctl daemon-reload
  echo "Removed quadlet units. Data is kept in volume '$VOLUME'."
}

case "${1:-}" in
  build) build ;;
  start) start ;;
  stop) stop ;;
  restart) stop || true; start ;;
  down) down ;;
  update) update ;;
  logs) logs ;;
  status) status ;;
  backup) backup ;;
  install-systemd) install_systemd ;;
  uninstall-systemd) uninstall_systemd ;;
  *) echo "usage: $0 build|start|stop|restart|down|update|logs|status|backup|install-systemd|uninstall-systemd" >&2; exit 2 ;;
esac
