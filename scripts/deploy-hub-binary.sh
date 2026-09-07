#!/usr/bin/env bash
# Build, ship, verify and restart one of this repo's daemons on an LP's own host.
#
# Finding 10: deployment was a laptop build, an `scp`, a hand-named `.bak`, and
# no way to tell what was running short of `nm` or `strings` for a symbol that
# happened to have changed. The hub ran a three-day-old taker for three days
# without anyone noticing.
#
# What this does that the manual sequence did not:
#
#   - refuses to ship a build it cannot name, so a binary always answers "what
#     commit are you?";
#   - verifies the bytes that landed against the bytes that left, before
#     anything is restarted;
#   - runs `--check` against the *deployed* binary and the *deployed* config,
#     which is the only test that exercises the pair that will actually run;
#   - keeps the previous binary under its own commit hash rather than a
#     timestamped `.bak`, so a rollback names a version rather than a date;
#   - rolls back by itself if the service does not come up.
#
# Nothing here names a host, a user, a path or an account. Every one of those is
# a flag or an environment variable, because any LP can run this and none of
# them are running the same deployment.
#
# Usage:
#   scripts/deploy-hub-binary.sh --host lp-host
#   scripts/deploy-hub-binary.sh --host lp-host --binary zecp2p-taker
#   scripts/deploy-hub-binary.sh --host lp-host --dry-run
#   scripts/deploy-hub-binary.sh --host lp-host --rollback 1a705d4c9f21
#   scripts/deploy-hub-binary.sh --host lp-host --list
#
# Environment (all optional, all with the defaults the units use):
#   ZECP2P_DEPLOY_HOST     the ssh destination, same as --host
#   ZECP2P_DEPLOY_DIR      remote root                 (default ~/.zecp2p)
#   ZECP2P_DEPLOY_UNIT     systemd --user unit         (default zecp2p-v2coordinator)
#   ZECP2P_DEPLOY_CONFIG   remote config path          (default $DIR/config/config.v2coordinator.toml)
#   ZECP2P_HEALTH_URL      health endpoint to poll     (default http://127.0.0.1:3000/health)

set -euo pipefail

# Which binary. Both carry the same build stamp and both take `--version`, so
# the whole of this script works for either; the coordinator additionally takes
# `--check` and serves `/health`, and those steps are skipped for one that does
# not.
BIN_NAME="zecp2p-v2coordinator"
CRATE="zecp2p-v2coordinator"

HOST="${ZECP2P_DEPLOY_HOST:-}"
REMOTE_DIR="${ZECP2P_DEPLOY_DIR:-\$HOME/.zecp2p}"
UNIT="${ZECP2P_DEPLOY_UNIT:-}"
REMOTE_CONFIG="${ZECP2P_DEPLOY_CONFIG:-}"
HEALTH_URL="${ZECP2P_HEALTH_URL:-http://127.0.0.1:3000/health}"
DRY_RUN=0
ROLLBACK=""
LIST=0
SKIP_BUILD=0

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[36m==\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m  ok\033[0m %s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --host)      HOST="$2"; shift 2 ;;
    --binary)    BIN_NAME="$2"; CRATE="$2"; shift 2 ;;
    --dir)       REMOTE_DIR="$2"; shift 2 ;;
    --unit)      UNIT="$2"; shift 2 ;;
    --config)    REMOTE_CONFIG="$2"; shift 2 ;;
    --health)    HEALTH_URL="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --rollback)  ROLLBACK="$2"; shift 2 ;;
    --list)      LIST=1; shift ;;
    -h|--help)   sed -n '2,32p' "$0"; exit 0 ;;
    *)           die "unknown argument: $1" ;;
  esac
done

[ -n "$HOST" ] || die "no host. Pass --host, or set ZECP2P_DEPLOY_HOST."
# Same reason as the hash check below: this reaches a remote shell and a cargo
# package name, and both are ordinary identifiers.
case "$BIN_NAME" in
  *[!0-9a-zA-Z._-]*|"") die "'$BIN_NAME' is not a binary name" ;;
esac
# The unit is named after the binary unless one was given, so `--binary
# zecp2p-taker` restarts the taker's unit rather than the coordinator's.
: "${UNIT:=$BIN_NAME}"

# Only the coordinator has a `--check` and a `/health`. The taker's config path
# differs too, so both are settled from the binary.
case "$BIN_NAME" in
  zecp2p-v2coordinator)
    : "${REMOTE_CONFIG:=$REMOTE_DIR/config/config.v2coordinator.toml}"
    HAS_CHECK=1
    ;;
  *)
    : "${REMOTE_CONFIG:=$REMOTE_DIR/config/config.taker.toml}"
    HAS_CHECK=0
    ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# Shorthand for a remote command. `-o BatchMode` so a missing key fails now
# rather than sitting on a password prompt inside a deploy.
r() { ssh -o BatchMode=yes "$HOST" "$@"; }

# ---------------------------------------------------------------------------
# --list: what is on the host, and what it is running.
# ---------------------------------------------------------------------------
if [ "$LIST" = 1 ]; then
  say "versions kept on $HOST"
  r "ls -1t $REMOTE_DIR/bin/versions/ 2>/dev/null || echo '(none)'"
  say "what is running"
  r "$REMOTE_DIR/bin/$BIN_NAME --version 2>/dev/null || echo '(no binary, or it will not run)'"
  exit 0
fi

# ---------------------------------------------------------------------------
# --rollback: promote a kept version. No build, no upload.
# ---------------------------------------------------------------------------
if [ -n "$ROLLBACK" ]; then
  # Every value that reaches a remote shell below is interpolated into it, so
  # the ones that come from an argument are checked for shape first. A hash is
  # hex and nothing else; anything else is a typo at best.
  case "$ROLLBACK" in
    *[!0-9a-fA-F]*|"") die "a version is a hex commit hash, not '$ROLLBACK'. Run --list." ;;
  esac
  say "rolling back to $ROLLBACK"
  r "test -x $REMOTE_DIR/bin/versions/$BIN_NAME-$ROLLBACK" \
    || die "$HOST has no kept version $ROLLBACK. Run --list to see what it has."
  # `install` rather than `cp`: it replaces the inode rather than writing
  # through it, so a running process keeps the file it started with and the
  # restart below is what actually swaps the binary.
  r "install -m 0755 $REMOTE_DIR/bin/versions/$BIN_NAME-$ROLLBACK $REMOTE_DIR/bin/$BIN_NAME"
  r "systemctl --user restart $UNIT"
  sleep 3
  r "systemctl --user is-active $UNIT" || die "the unit did not come back up after the rollback"
  ok "rolled back to $ROLLBACK and the unit is active"
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. Name this build, and refuse to ship one that cannot be named.
# ---------------------------------------------------------------------------
say "identifying this build"
GIT_HASH="$(git rev-parse --short=12 HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  DIRTY=1
  printf '\033[33m  warning:\033[0m the tree has uncommitted changes. The build will be\n'
  printf '           stamped %s-dirty, which is a build nobody else can reproduce.\n' "$GIT_HASH"
  if [ "$DRY_RUN" = 0 ]; then
    printf '           Deploy it anyway? [y/N] '
    read -r answer
    case "$answer" in y|Y|yes) ;; *) die "stopped: commit first, or re-run with the change committed" ;; esac
  fi
else
  DIRTY=0
  ok "$GIT_HASH, clean"
fi

# ---------------------------------------------------------------------------
# 2. Build, and check the binary agrees about what it is.
# ---------------------------------------------------------------------------
LOCAL_BIN="$REPO/target/release/$BIN_NAME"
if [ "$SKIP_BUILD" = 0 ]; then
  say "building --release"
  cargo build --release -p "$CRATE"
else
  say "skipping the build, using $LOCAL_BIN"
  [ -x "$LOCAL_BIN" ] || die "no binary at $LOCAL_BIN and --skip-build was passed"
fi

# The stamp `build.rs` put in. Read out of the binary rather than trusted from
# the shell, because what matters is what the *artifact* says.
#
# `grep -o` up to the stamp's `;` terminator, not an anchored match.
#
# Rust packs string literals into `.rodata` back to back with no separator, so
# the stamp comes out of `strings` in the middle of a run of unrelated messages:
# it is never at the start of a line, and it has no whitespace after it.
# Anchoring to `^` finds nothing - a verify step that silently never verifies -
# and stopping at whitespace swallows the next literal, so the hash grows a
# suffix and every deploy is refused. The terminator is why `version.rs` puts
# one there.
STAMP="$(strings -a "$LOCAL_BIN" | grep -om1 'zecp2p-build:[^;]*' || true)"
[ -n "$STAMP" ] || die "this binary carries no build stamp. Is build.rs in place?"
STAMPED_HASH="$(printf '%s' "$STAMP" | cut -d: -f4)"
STAMPED_DIRTY="$(printf '%s' "$STAMP" | cut -d: -f5)"
[ "$STAMPED_HASH" = "$GIT_HASH" ] \
  || die "the binary says $STAMPED_HASH and the tree says $GIT_HASH. Stale build - rebuild."
[ "$STAMPED_DIRTY" = "$DIRTY" ] \
  || die "the binary's dirty flag ($STAMPED_DIRTY) disagrees with the tree ($DIRTY). Stale build."
ok "$STAMP"

LOCAL_SHA="$(sha256sum "$LOCAL_BIN" | cut -d' ' -f1)"
ok "sha256 $LOCAL_SHA"

if [ "$DRY_RUN" = 1 ]; then
  say "dry run: nothing was sent to $HOST"
  say "what is there now"
  r "$REMOTE_DIR/bin/$BIN_NAME --version 2>/dev/null || echo '(nothing deployed)'"
  exit 0
fi

# ---------------------------------------------------------------------------
# 3. Ship it beside the running one. Nothing is swapped yet.
# ---------------------------------------------------------------------------
say "sending to $HOST"
r "mkdir -p $REMOTE_DIR/bin/versions"
STAGED="$REMOTE_DIR/bin/versions/$BIN_NAME-$GIT_HASH"
scp -q "$LOCAL_BIN" "$HOST:$STAGED"
r "chmod 0755 $STAGED"

REMOTE_SHA="$(r "sha256sum $STAGED | cut -d' ' -f1")"
[ "$REMOTE_SHA" = "$LOCAL_SHA" ] \
  || die "the bytes that landed ($REMOTE_SHA) are not the bytes that left ($LOCAL_SHA)"
ok "sha256 matches on both ends"

# ---------------------------------------------------------------------------
# 4. Check the new binary against the deployed config, before swapping.
#
# This is the step the manual sequence had no equivalent of. It runs the binary
# that is about to serve against the configuration that is about to be served,
# so a config the new build reads differently is caught while the old one is
# still running.
# ---------------------------------------------------------------------------
if [ "$HAS_CHECK" = 1 ]; then
  say "checking the new binary against the live config"
  if ! r "$STAGED --config $REMOTE_CONFIG --check"; then
    r "rm -f $STAGED"
    die "the new binary will not accept the deployed config. Nothing was changed; the running binary is untouched."
  fi
  ok "configuration, node, attestor and key all check out"
else
  # No `--check` on this binary. `--version` at least proves the artifact runs
  # on this host - the right architecture, the right libc - which is the failure
  # an scp from a different machine actually produces.
  say "no --check on $BIN_NAME; confirming the binary runs at all"
  r "$STAGED --version" || { r "rm -f $STAGED"; die "the shipped binary will not run on $HOST"; }
fi

# ---------------------------------------------------------------------------
# 5. Swap and restart, keeping the outgoing version by its own hash.
# ---------------------------------------------------------------------------
PREVIOUS="$(r "$REMOTE_DIR/bin/$BIN_NAME --version 2>/dev/null | head -1" || true)"
PREVIOUS_HASH="$(r "strings -a $REMOTE_DIR/bin/$BIN_NAME 2>/dev/null | grep -om1 'zecp2p-build:[^;]*' | cut -d: -f4" || true)"
if [ -n "$PREVIOUS_HASH" ]; then
  # Kept by hash, not by date: a rollback names a version rather than guessing
  # which `.bak-2026-09-04` was the good one.
  r "cp -f $REMOTE_DIR/bin/$BIN_NAME $REMOTE_DIR/bin/versions/$BIN_NAME-$PREVIOUS_HASH 2>/dev/null || true"
  say "the outgoing build was $PREVIOUS ($PREVIOUS_HASH), kept for rollback"
fi

say "swapping and restarting $UNIT"
r "install -m 0755 $STAGED $REMOTE_DIR/bin/$BIN_NAME"
r "systemctl --user restart $UNIT"

# ---------------------------------------------------------------------------
# 6. Verify it came up, and roll back by itself if it did not.
# ---------------------------------------------------------------------------
say "waiting for it to come up"
up=0
for _ in $(seq 1 30); do
  sleep 2
  if r "systemctl --user is-active --quiet $UNIT"; then up=1; break; fi
done

if [ "$up" = 0 ]; then
  printf '\033[31m  the unit did not come up. Rolling back.\033[0m\n'
  r "systemctl --user status $UNIT --no-pager -l | tail -30" || true
  if [ -n "$PREVIOUS_HASH" ]; then
    r "install -m 0755 $REMOTE_DIR/bin/versions/$BIN_NAME-$PREVIOUS_HASH $REMOTE_DIR/bin/$BIN_NAME"
    r "systemctl --user restart $UNIT"
    sleep 3
    r "systemctl --user is-active $UNIT" && printf '\033[33m  rolled back to %s\033[0m\n' "$PREVIOUS_HASH"
  fi
  die "the deploy failed and was rolled back"
fi
ok "the unit is active"

# Health, asked of the service rather than of systemd. A unit can be `active`
# with a coordinator that cannot reach a node, and that distinction is the whole
# point of /health being truthful.
if [ "$HAS_CHECK" = 0 ]; then
  say "deployed"
  r "$REMOTE_DIR/bin/$BIN_NAME --version | head -1"
  ok "rollback with: $0 --host $HOST --binary $BIN_NAME --rollback ${PREVIOUS_HASH:-<hash>}"
  exit 0
fi

say "asking $HEALTH_URL what it thinks"
HEALTH="$(r "curl -sS --max-time 10 $HEALTH_URL" || true)"
if [ -z "$HEALTH" ]; then
  printf '\033[33m  warning:\033[0m /health did not answer. The unit is up; check it by hand.\n'
else
  printf '%s\n' "$HEALTH" | python3 -m json.tool 2>/dev/null || printf '%s\n' "$HEALTH"
  case "$HEALTH" in
    *'"status": "ok"'*|*'"status":"ok"'*)       ok "healthy" ;;
    *'"status": "degraded"'*|*'"status":"degraded"'*)
      printf '\033[33m  degraded:\033[0m it is serving, and something wants looking at. See "problems" above.\n' ;;
    *) printf '\033[33m  warning:\033[0m /health did not report ok. Read the problems above.\n' ;;
  esac
fi

# What is actually running, from the binary itself.
say "deployed"
r "$REMOTE_DIR/bin/$BIN_NAME --version | head -1"
ok "rollback with: $0 --host $HOST --rollback ${PREVIOUS_HASH:-<hash>}"
