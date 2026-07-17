#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
export LC_ALL=C

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd -P)"
readonly TOOLS_ROOT="${OCTOBENCH_TOOLS_ROOT:-${REPO_ROOT}/.benchmark-tools}"
readonly SOURCES_ROOT="${TOOLS_ROOT}/src"
readonly VENVS_ROOT="${TOOLS_ROOT}/venvs"
readonly UV_VERSION="0.11.28"
readonly UV_VENV="${VENVS_ROOT}/uv-${UV_VERSION}"
readonly UV_BIN="${UV_VENV}/bin/uv"
readonly OCTOPUS_VENV="${REPO_ROOT}/venv"
readonly OCTOPUS_RUNTIME_LOCK="${REPO_ROOT}/requirements/locks/linux-x86_64/cp312/runtime.txt"

readonly STRIX_URL="https://github.com/usestrix/strix.git"
readonly STRIX_TAG="v1.1.0"
readonly STRIX_REVISION="91d9a847166fe2f82125643d13e099b0d989bbe4"
readonly STRIX_SOURCE="${SOURCES_ROOT}/strix"
readonly STRIX_VENV="${VENVS_ROOT}/strix-1.1.0"
readonly STRIX_IMAGE="ghcr.io/usestrix/strix-sandbox@sha256:2e3a7e63a90428979ce34fbf80a8e83bb375d0d1146597a5d74087a259ee925c"

readonly PENTESTGPT_URL="https://github.com/GreyDGL/PentestGPT.git"
readonly PENTESTGPT_TAG="v1.0.0"
readonly PENTESTGPT_REVISION="83ae3647603de8c66229f0877faef77a53f5c8f6"
readonly PENTESTGPT_SOURCE="${SOURCES_ROOT}/pentestgpt"

readonly PENTAGI_URL="https://github.com/vxcontrol/pentagi.git"
readonly PENTAGI_TAG="v2.1.0"
readonly PENTAGI_REVISION="a112db206b2fb7866c367c33348f52f5cdc207d0"
readonly PENTAGI_SOURCE="${SOURCES_ROOT}/pentagi"

readonly SHANNON_URL="https://github.com/KeygraphHQ/shannon.git"
readonly SHANNON_TAG="v1.9.0"
readonly SHANNON_REVISION="00e56455dfb0f2626b63e7e9231980cfb48e2fe2"
readonly SHANNON_SOURCE="${SOURCES_ROOT}/shannon"

profile="core"
with_pentestgpt=0
with_pentagi=0
with_shannon=0

usage() {
  printf '%s\n' \
    'Usage: bootstrap_competitors_linux.sh [options]' \
    '' \
    'Clone and verify exact competitor releases. The default core profile' \
    'installs Strix and its pinned Linux amd64 sandbox image.' \
    '' \
    'Options:' \
    '  --profile core       Prepare runnable Strix (default).' \
    '  --profile extended   Prepare core and clone the pinned PentAGI source.' \
    '  --with-pentestgpt    Clone/install the separate CTF-only candidate.' \
    '  --with-pentagi       Also clone and verify PentAGI; service setup is separate.' \
    '  --with-shannon       Also clone and verify Shannon for a white-box campaign.' \
    '  --all                Clone every non-excluded candidate; prepare core.' \
    '  -h, --help           Show this help.' \
    '' \
    'Environment:' \
    '  OCTOBENCH_TOOLS_ROOT  Install root (default: <repo>/.benchmark-tools).' \
    '  OCTOBENCH_PYTHON      CPython 3.12 executable used for all benchmark venvs.'
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[octobench-bootstrap] %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_glibc_234() {
  local reported
  local major
  local minor

  command -v getconf >/dev/null 2>&1 \
    || die 'glibc 2.34 or newer is required (getconf is unavailable)'
  reported="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [[ ! "$reported" =~ ^glibc[[:space:]]+([0-9]+)\.([0-9]+) ]]; then
    die "glibc 2.34 or newer is required (detected: ${reported:-unknown})"
  fi
  major=$((10#${BASH_REMATCH[1]}))
  minor=$((10#${BASH_REMATCH[2]}))
  if (( major < 2 || (major == 2 && minor < 34) )); then
    die "glibc 2.34 or newer is required (detected: ${reported})"
  fi
}

normalize_git_url() {
  local value="${1%/}"
  printf '%s\n' "${value%.git}"
}

clone_verified_release() {
  local name="$1"
  local url="$2"
  local tag="$3"
  local expected_revision="$4"
  local destination="$5"
  local include_submodules="${6:-no}"
  local origin
  local resolved_revision
  local head_revision

  if [[ ! -e "$destination" ]]; then
    log "cloning ${name} ${tag}"
    git clone --filter=blob:none --depth 1 --single-branch --branch "$tag" "$url" "$destination"
  elif ! git -C "$destination" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    die "existing path is not a Git worktree: ${destination}"
  fi

  origin="$(git -C "$destination" remote get-url origin)"
  if [[ "$(normalize_git_url "$origin")" != "$(normalize_git_url "$url")" ]]; then
    die "unexpected origin for ${name}: ${origin}"
  fi
  if [[ -n "$(git -C "$destination" status --porcelain --untracked-files=all)" ]]; then
    die "refusing to change a dirty competitor checkout: ${destination}"
  fi

  if ! git -C "$destination" show-ref --verify --quiet "refs/tags/${tag}"; then
    log "fetching missing ${name} tag ${tag}"
    git -C "$destination" fetch --depth 1 origin "refs/tags/${tag}:refs/tags/${tag}"
  fi
  resolved_revision="$(git -C "$destination" rev-parse "refs/tags/${tag}^{commit}")"
  if [[ "$resolved_revision" != "$expected_revision" ]]; then
    die "${name} tag ${tag} resolved to ${resolved_revision}, expected ${expected_revision}"
  fi

  head_revision="$(git -C "$destination" rev-parse HEAD)"
  if [[ "$head_revision" != "$expected_revision" ]] || git -C "$destination" symbolic-ref --quiet HEAD >/dev/null 2>&1; then
    git -C "$destination" checkout --detach "$expected_revision"
  fi
  head_revision="$(git -C "$destination" rev-parse HEAD)"
  if [[ "$head_revision" != "$expected_revision" ]]; then
    die "${name} checkout verification failed: ${head_revision}"
  fi

  if [[ "$include_submodules" == "yes" ]]; then
    git -C "$destination" submodule sync --recursive
    git -C "$destination" submodule update --init --recursive --depth 1
  fi
  log "verified ${name} ${tag} at ${head_revision}"
}

select_python() {
  local candidate="${OCTOBENCH_PYTHON:-}"
  if [[ -z "$candidate" ]] && command -v python3.12 >/dev/null 2>&1; then
    candidate="$(command -v python3.12)"
  fi
  if [[ -z "$candidate" ]] && command -v python3 >/dev/null 2>&1; then
    candidate="$(command -v python3)"
  fi
  [[ -n "$candidate" ]] || die 'CPython 3.12 is required for the benchmark locks'
  "$candidate" -c \
    'import platform, sys; raise SystemExit(platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 12))' \
    || die "CPython 3.12 is required for the benchmark locks: ${candidate}"
  printf '%s\n' "$candidate"
}

prepare_uv() {
  local python_bin="$1"
  if [[ ! -x "${UV_VENV}/bin/python" ]]; then
    log "creating pinned uv environment: ${UV_VENV}"
    "$python_bin" -m venv "$UV_VENV"
  fi
  if ! "${UV_VENV}/bin/python" -c \
    "import importlib.metadata as m; raise SystemExit(m.version('uv') != '${UV_VERSION}')" \
    >/dev/null 2>&1; then
    log "installing uv ${UV_VERSION}"
    "${UV_VENV}/bin/python" -m pip install \
      --disable-pip-version-check "uv==${UV_VERSION}"
  fi
  [[ -x "$UV_BIN" ]] || die "uv ${UV_VERSION} executable was not installed"
}

prepare_octopus() {
  local python_bin="$1"
  [[ -f "$OCTOPUS_RUNTIME_LOCK" ]] || die "missing OCTOPUS runtime lock: ${OCTOPUS_RUNTIME_LOCK}"
  if [[ ! -e "$OCTOPUS_VENV" ]]; then
    log "creating OCTOPUS runtime venv: ${OCTOPUS_VENV}"
    "$python_bin" -m venv "$OCTOPUS_VENV"
  elif [[ ! -x "${OCTOPUS_VENV}/bin/python" ]]; then
    die "existing OCTOPUS venv is incomplete: ${OCTOPUS_VENV}"
  fi
  "${OCTOPUS_VENV}/bin/python" -c \
    'import sys; raise SystemExit(sys.version_info[:2] != (3, 12))' \
    || die "existing OCTOPUS venv must use CPython 3.12: ${OCTOPUS_VENV}"
  log 'syncing OCTOPUS from the checked-in hashed runtime lock'
  "$UV_BIN" pip sync \
    --python "${OCTOPUS_VENV}/bin/python" \
    --require-hashes \
    "$OCTOPUS_RUNTIME_LOCK"
}

prepare_strix() {
  local python_bin="$1"
  local marker="${STRIX_VENV}/.octobench-source-revision"
  local installed=0

  if [[ ! -e "$STRIX_VENV" ]]; then
    log "creating Strix venv: ${STRIX_VENV}"
    "$python_bin" -m venv "$STRIX_VENV"
  elif [[ ! -x "${STRIX_VENV}/bin/python" ]]; then
    die "existing Strix venv is incomplete: ${STRIX_VENV}"
  fi

  if [[ -f "$marker" ]] && [[ "$(<"$marker")" == "$STRIX_REVISION" ]]; then
    if "${STRIX_VENV}/bin/python" -c \
      'import importlib.metadata as m; raise SystemExit(m.version("strix-agent") != "1.1.0")' \
      >/dev/null 2>&1; then
      installed=1
    fi
  fi
  if (( installed == 0 )); then
    log 'syncing Strix from its verified source and frozen uv.lock'
    VIRTUAL_ENV="$STRIX_VENV" "$UV_BIN" sync \
      --project "$STRIX_SOURCE" \
      --frozen \
      --active \
      --no-dev
    "${STRIX_VENV}/bin/python" -c \
      'import importlib.metadata as m; raise SystemExit(m.version("strix-agent") != "1.1.0")'
    printf '%s\n' "$STRIX_REVISION" >"$marker"
  else
    log 'Strix v1.1.0 is already installed and verified'
  fi
  [[ -x "${STRIX_VENV}/bin/strix" ]] || die 'Strix executable was not installed'
}

prepare_strix_sandbox_image() {
  local platform
  local repo_digests

  log "pulling pinned Strix sandbox image: ${STRIX_IMAGE}"
  docker pull --platform linux/amd64 "$STRIX_IMAGE"
  platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$STRIX_IMAGE")"
  [[ "$platform" == "linux/amd64" ]] \
    || die "unexpected Strix sandbox platform: ${platform:-missing}"
  repo_digests="$(docker image inspect --format '{{json .RepoDigests}}' "$STRIX_IMAGE")"
  [[ "$repo_digests" == *"\"${STRIX_IMAGE}\""* ]] \
    || die 'pinned Strix sandbox digest is not present after pull'
  log 'verified pinned Strix sandbox image for linux/amd64'
}

prepare_pentestgpt() {
  local python_bin="$1"
  log 'syncing PentestGPT from uv.lock'
  "$UV_BIN" sync \
    --project "$PENTESTGPT_SOURCE" \
    --python "$python_bin" \
    --frozen \
    --no-dev
  [[ -x "${PENTESTGPT_SOURCE}/.venv/bin/pentestgpt" ]] \
    || die 'PentestGPT executable was not installed by uv sync'
}

while (( $# > 0 )); do
  case "$1" in
    --profile)
      (( $# >= 2 )) || die '--profile requires core or extended'
      profile="$2"
      shift 2
      ;;
    --with-pentagi)
      with_pentagi=1
      shift
      ;;
    --with-pentestgpt)
      with_pentestgpt=1
      shift
      ;;
    --with-shannon)
      with_shannon=1
      shift
      ;;
    --all)
      with_pentestgpt=1
      with_pentagi=1
      with_shannon=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

case "$profile" in
  core)
    ;;
  extended)
    with_pentagi=1
    ;;
  *)
    die "unsupported profile: ${profile}"
    ;;
esac

[[ "$(uname -s)" == "Linux" ]] || die 'this bootstrap is supported only on Linux'
[[ "$(uname -m)" == "x86_64" ]] || die 'the checked-in OCTOPUS benchmark lock targets Linux x86_64'
require_glibc_234
require_command git
require_command docker
docker compose version >/dev/null 2>&1 || die 'Docker Compose plugin is required'
prepare_strix_sandbox_image
install -d "$SOURCES_ROOT" "$VENVS_ROOT"
python_bin="$(select_python)"
prepare_uv "$python_bin"
prepare_octopus "$python_bin"

clone_verified_release \
  'Strix' "$STRIX_URL" "$STRIX_TAG" "$STRIX_REVISION" "$STRIX_SOURCE"
prepare_strix "$python_bin"

if (( with_pentestgpt == 1 )); then
  clone_verified_release \
    'PentestGPT' "$PENTESTGPT_URL" "$PENTESTGPT_TAG" "$PENTESTGPT_REVISION" \
    "$PENTESTGPT_SOURCE" 'yes'
  prepare_pentestgpt "$python_bin"
  log 'PentestGPT is ready only as a separate CTF/flag-capture candidate'
fi

if (( with_pentagi == 1 )); then
  clone_verified_release \
    'PentAGI' "$PENTAGI_URL" "$PENTAGI_TAG" "$PENTAGI_REVISION" "$PENTAGI_SOURCE"
  log 'PentAGI source is pinned; configure its service separately before an extended run'
fi
if (( with_shannon == 1 )); then
  clone_verified_release \
    'Shannon' "$SHANNON_URL" "$SHANNON_TAG" "$SHANNON_REVISION" "$SHANNON_SOURCE"
  log 'Shannon source is pinned; use it only in a separate white-box campaign'
fi

printf '\n%s\n' \
  'Core benchmark runtimes are ready:' \
  "  OCTOPUS:    ${OCTOPUS_VENV}/bin/python" \
  "  Strix:      ${STRIX_VENV}/bin/strix" \
  "  Sandbox:    ${STRIX_IMAGE}" \
  '' \
  'Next: copy benchmarks/competitors/secrets.env.example to secrets.env,' \
  'set mode 0600, fill the selected providers, and run the benchmark launcher.'
