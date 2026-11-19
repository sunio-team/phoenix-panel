#!/usr/bin/env bash
# ============================================================
#  Phoenix Panel - Termux deployer for Cloudflare Workers
#  GitHub  : https://github.com/sunio-team
#  Telegram: https://t.me/sunio_team
#
#  Usage (in Termux):
#     bash phoenix-deploy.sh
# ============================================================

set -u

API="https://api.cloudflare.com/client/v4"
RAW_URL="https://raw.githubusercontent.com/sunio-team/phoenix-panel/main/Main.js"
RAW_FALLBACK="https://cdn.jsdelivr.net/gh/sunio-team/phoenix-panel@main/Main.js"
DIR="$HOME/.phoenix_panel"
WORKER_FILE="$DIR/worker.js"
META_FILE="$DIR/metadata.json"
TOKEN=""
ACCOUNT_ID=""
ACCOUNT_NAME=""
ACC_SUB=""
NAME=""
UUID=""

mkdir -p "$DIR" && chmod 700 "$DIR"

# ---------- colors / output helpers ----------
if [ -t 1 ]; then
  R=$'\033[1;31m'; G=$'\033[1;32m'; Y=$'\033[1;33m'; B=$'\033[1;36m'; W=$'\033[1;37m'; N=$'\033[0m'
else
  R=""; G=""; Y=""; B=""; W=""; N=""
fi
info() { printf "%s[*]%s %s\n" "$B" "$N" "$*"; }
ok()   { printf "%s[OK]%s %s\n" "$G" "$N" "$*"; }
warn() { printf "%s[!]%s %s\n" "$Y" "$N" "$*"; }
err()  { printf "%s[X]%s %s\n" "$R" "$N" "$*" >&2; }
die()  { err "$*"; exit 1; }

ask_yn() {
  local a
  while true; do
    read -r -p "$1 (y/n): " a
    case "$a" in
      y|Y|yes|YES|Yes) return 0 ;;
      n|N|no|NO|No)    return 1 ;;
    esac
  done
}

banner() {
  printf "%s" "$Y"
  cat <<'EOF'

   ____  _   _  ___  _____ _   _ ___ __  __
  |  _ \| | | |/ _ \| ____| \ | |_ _\ \/ /
  | |_) | |_| | | | |  _| |  \| || | \  /
  |  __/|  _  | |_| | |___| |\  || | /  \
  |_|   |_| |_|\___/|_____|_| \_|___/_/\_\

        Phoenix Panel  -  Sunio Team
EOF
  printf "%s\n" "$N"
}

# ---------- dependencies ----------
need() { command -v "$1" >/dev/null 2>&1; }

install_deps() {
  local missing=()
  need curl || missing+=(curl)
  need jq   || missing+=(jq)
  if [ "${#missing[@]}" -gt 0 ]; then
    info "Installing required packages: ${missing[*]}"
    if need pkg; then
      pkg install -y "${missing[@]}" || die "Package install failed. Run 'pkg update' and try again."
    elif need apt-get; then
      apt-get install -y "${missing[@]}" || die "Package install failed."
    else
      die "Please install these packages manually: ${missing[*]}"
    fi
  fi
}

gen_uuid() {
  if [ -r /proc/sys/kernel/random/uuid ]; then
    cat /proc/sys/kernel/random/uuid
  elif need uuidgen; then
    uuidgen | tr 'A-Z' 'a-z'
  elif need python3; then
    python3 -c 'import uuid; print(uuid.uuid4())'
  else
    die "Cannot generate a UUID. Install 'uuid-utils' (pkg install uuid-utils)."
  fi
}

# ---------- remote worker source ----------
fetch_worker() {
  local tmp="$DIR/worker.download"
  info "Fetching worker code from GitHub..."
  if ! curl -fsSL -m 60 "$RAW_URL" -o "$tmp"; then
    warn "Primary source failed, trying jsDelivr mirror..."
    if ! curl -fsSL -m 60 "$RAW_FALLBACK" -o "$tmp"; then
      rm -f "$tmp"
      die "Could not download Main.js from GitHub. Check your connection (or VPN) and try again."
    fi
  fi

  # sanity: must look like a JS module, not the GitHub HTML page
  if ! head -c 4000 "$tmp" | grep -q 'export default'; then
    rm -f "$tmp"
    die "Downloaded content is not valid worker code (maybe GitHub returned an error page)."
  fi

  mv "$tmp" "$WORKER_FILE"
  chmod 600 "$WORKER_FILE"
  ok "Worker code downloaded ($(wc -c < "$WORKER_FILE") bytes)."
}

# ---------- Cloudflare API ----------
cf() {
  local method="$1" path="$2"
  shift 2
  curl -sS -m 60 -X "$method" "$API$path" \
    -H "Authorization: Bearer $TOKEN" "$@"
}

is_success() {
  [ "$(printf '%s' "$1" | jq -r '.success' 2>/dev/null)" = "true" ]
}

api_error() {
  printf '%s' "$1" | jq -r '.errors[0].message // "unknown error"' 2>/dev/null || echo "unknown error"
}

# ---------- 1) Login ----------
verify_token() {
  local r
  r=$(cf GET /user/tokens/verify 2>/dev/null) || return 2
  if is_success "$r" && [ "$(printf '%s' "$r" | jq -r '.result.status // empty' 2>/dev/null)" = "active" ]; then
    return 0
  fi
  r=$(cf GET "/accounts?per_page=5" 2>/dev/null) || return 2
  is_success "$r" && return 0
  return 1
}

login() {
  local rc
  if [ -s "$DIR/token" ]; then
    TOKEN=$(cat "$DIR/token")
    info "Found a saved token. Checking it..."
    verify_token; rc=$?
    if [ "$rc" -eq 0 ]; then return 0; fi
    [ "$rc" -eq 2 ] && die "Cannot reach Cloudflare. Check your internet connection (or VPN) and try again."
    warn "Saved token is no longer valid."
    rm -f "$DIR/token"
  fi

  cat <<EOF

${W}You need a Cloudflare API token:${N}
  1. Open  https://dash.cloudflare.com/profile/api-tokens
  2. Create Token -> use the template "Edit Cloudflare Workers"
  3. Account Resources: your account | Zone Resources: All zones
  4. Create the token and copy it

EOF
  while true; do
    read -r -s -p "Paste your Cloudflare API token (hidden): " TOKEN
    echo
    [ -z "$TOKEN" ] && continue
    info "Connecting to Cloudflare..."
    verify_token; rc=$?
    if [ "$rc" -eq 0 ]; then break; fi
    if [ "$rc" -eq 2 ]; then
      die "Cannot reach Cloudflare. Check your internet connection (or VPN) and try again."
    fi
    err "Invalid token or missing permissions. Please try again."
  done

  if ask_yn "Save the token on this device for next time?"; then
    printf '%s' "$TOKEN" > "$DIR/token" && chmod 600 "$DIR/token"
    ok "Token saved in $DIR/token"
  fi
}

pick_account() {
  local r n i sel
  r=$(cf GET "/accounts?per_page=50")
  n=$(printf '%s' "$r" | jq -r '.result | length' 2>/dev/null || echo 0)
  case "$n" in ''|*[!0-9]*) n=0 ;; esac

  if [ "$n" -eq 0 ]; then
    warn "Could not list your accounts automatically."
    while true; do
      read -r -p "Enter your Cloudflare Account ID: " ACCOUNT_ID
      [[ "$ACCOUNT_ID" =~ ^[a-f0-9]{32}$ ]] && break
      err "An Account ID is 32 hex characters. Find it on the Workers & Pages overview page."
    done
    ACCOUNT_NAME="$ACCOUNT_ID"
  elif [ "$n" -eq 1 ]; then
    ACCOUNT_ID=$(printf '%s' "$r" | jq -r '.result[0].id')
    ACCOUNT_NAME=$(printf '%s' "$r" | jq -r '.result[0].name')
  else
    echo "Multiple accounts found:"
    for ((i = 0; i < n; i++)); do
      printf "  %d) %s\n" "$((i + 1))" "$(printf '%s' "$r" | jq -r ".result[$i].name")"
    done
    while true; do
      read -r -p "Choose an account number: " sel
      if [[ "$sel" =~ ^[0-9]+$ ]] && [ "$sel" -ge 1 ] && [ "$sel" -le "$n" ]; then break; fi
    done
    ACCOUNT_ID=$(printf '%s' "$r" | jq -r ".result[$((sel - 1))].id")
    ACCOUNT_NAME=$(printf '%s' "$r" | jq -r ".result[$((sel - 1))].name")
  fi
  ok "Connected to Cloudflare account: ${W}${ACCOUNT_NAME}${N}"
}

# ---------- 2) Name / subdomain ----------
valid_name() { [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]; }

worker_exists() {
  local r
  r=$(cf GET "/accounts/$ACCOUNT_ID/workers/scripts" 2>/dev/null) || return 1
  printf '%s' "$r" | jq -r '.result[]?.id' 2>/dev/null | grep -Fxq "$1"
}

choose_name() {
  local n
  while true; do
    read -r -p "Choose a name for your subdomain (a-z, 0-9, dash): " n
    n=$(printf '%s' "$n" | tr 'A-Z' 'a-z')
    if ! valid_name "$n"; then
      err "Invalid name. Use only lowercase letters, numbers and dashes (must start and end with a letter or number)."
      continue
    fi
    if worker_exists "$n"; then
      warn "A worker named '$n' already exists in this account."
      ask_yn "Overwrite it with the Phoenix Panel?" || continue
    fi
    NAME="$n"
    return 0
  done
}

get_account_subdomain() {
  local r s
  r=$(cf GET "/accounts/$ACCOUNT_ID/workers/subdomain" 2>/dev/null)
  ACC_SUB=$(printf '%s' "$r" | jq -r '.result.subdomain // empty' 2>/dev/null)
  if [ -z "$ACC_SUB" ]; then
    warn "Your account has no workers.dev subdomain yet. Let's create one."
    while true; do
      read -r -p "Choose your account subdomain (example: myname): " s
      s=$(printf '%s' "$s" | tr 'A-Z' 'a-z')
      valid_name "$s" || { err "Invalid name."; continue; }
      r=$(cf PUT "/accounts/$ACCOUNT_ID/workers/subdomain" \
        -H "Content-Type: application/json" --data "{\"subdomain\":\"$s\"}")
      if is_success "$r"; then
        ACC_SUB=$(printf '%s' "$r" | jq -r '.result.subdomain // empty')
        [ -z "$ACC_SUB" ] && ACC_SUB="$s"
        break
      fi
      err "Could not create it: $(api_error "$r")"
    done
  fi
}

# ---------- 3) Deploy ----------
deploy() {
  local r

  if [ -s "$DIR/$NAME.uuid" ]; then
    UUID=$(cat "$DIR/$NAME.uuid")
  else
    UUID=$(gen_uuid)
    printf '%s' "$UUID" > "$DIR/$NAME.uuid"
  fi

  fetch_worker

  printf '{"main_module":"worker.js","compatibility_date":"2024-09-23","bindings":[{"type":"plain_text","name":"UUID","text":"%s"}]}' \
    "$UUID" > "$META_FILE"

  info "Uploading code to Cloudflare..."
  r=$(cf PUT "/accounts/$ACCOUNT_ID/workers/scripts/$NAME" \
    -F "metadata=@$META_FILE;type=application/json" \
    -F "worker.js=@$WORKER_FILE;type=application/javascript+module;filename=worker.js")
  if ! is_success "$r"; then
    err "Deploy failed: $(api_error "$r")"
    err "Make sure your token has the 'Workers Scripts: Edit' permission."
    exit 1
  fi

  info "Enabling the workers.dev address..."
  r=$(cf POST "/accounts/$ACCOUNT_ID/workers/scripts/$NAME/subdomain" \
    -H "Content-Type: application/json" --data '{"enabled":true,"previews_enabled":false}')
  is_success "$r" || warn "Could not enable workers.dev automatically: $(api_error "$r")"
}

wait_live() {
  local host="$1" i code
  for i in 1 2 3 4 5 6; do
    code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "https://$host/" 2>/dev/null || true)
    [ "$code" = "200" ] && return 0
    sleep 4
  done
  return 1
}

# ---------- main ----------
main() {
  banner
  install_deps

  login
  pick_account

  echo
  if ! ask_yn "Do you want to deploy the Phoenix Panel now?"; then
    info "Okay, nothing was deployed. Bye!"
    exit 0
  fi

  choose_name
  get_account_subdomain

  deploy

  local host="${NAME}.${ACC_SUB}.workers.dev"
  info "Waiting for the worker to go live (this can take up to a minute)..."
  if wait_live "$host"; then
    ok "Your worker is live."
  else
    warn "Could not verify it from here (workers.dev may be filtered on your network). It is deployed anyway."
  fi

  cat <<EOF

${G}==================================================${N}
${G}  Deployed successfully!${N}
${G}==================================================${N}

  Panel home page:
    ${W}https://${host}${N}

  To enter the config generator, go to this link:
    ${W}https://${host}/${UUID}${N}

  Keep the UUID link private. Your UUID:
    ${UUID}

  Saved in: ${DIR}
  Sunio Team  |  https://t.me/sunio_team

EOF
}

main "$@"
