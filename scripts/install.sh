#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------
# Tactical RMM Linux Automated Deployment Bootstrap
# ---------------------------------------------------------

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="rmmagent"
TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"

SERVER_URL=""
ENROLL_TOKEN=""
CA_CERT_PATH=""

log_info() {
    printf "[*] %s\n" "$1"
}

log_success() {
    printf "[+] %s\n" "$1"
}

log_error() {
    printf "[-] ERROR: %s\n" "$1" >&2
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server)
                SERVER_URL="${2:-}"
                shift 2
                ;;
            --token)
                ENROLL_TOKEN="${2:-}"
                shift 2
                ;;
            --ca-cert)
                CA_CERT_PATH="${2:-}"
                shift 2
                ;;
            -h|--help)
                echo "Usage: install.sh --server <URL> --token <TOKEN> [--ca-cert <PATH>]"
                exit 0
                ;;
            *)
                log_error "Unknown parameter: $1"
                echo "Usage: install.sh --server <URL> --token <TOKEN> [--ca-cert <PATH>]"
                exit 1
                ;;
        esac
    done
}

validate_prerequisites() {
    if [[ "${EUID}" -ne 0 ]]; then
        log_error "This deployment script must be run as root (or via sudo)."
        exit 1
    fi

    if [[ ! -d "/run/systemd/system" ]]; then
        log_error "Unsupported init system. Systemd is strictly required."
        exit 1
    fi

    if [[ -z "${SERVER_URL}" || -z "${ENROLL_TOKEN}" ]]; then
        log_error "Missing required parameters. Both --server and --token must be supplied."
        exit 1
    fi

    if [[ "${SERVER_URL}" =~ ^http:// && ! "${SERVER_URL}" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?$ ]]; then
        log_error "Insecure transport rejected: Server URL must use HTTPS outside local test loops."
        exit 1
    fi
}

detect_architecture() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        *)
            log_error "Unsupported system architecture: ${arch}"
            exit 1
            ;;
    esac
}

install_agent_binary() {
    local detected_arch="$1"
    mkdir -p "${INSTALL_DIR}"

    # 1. البحث عن الثنائي المبني محلياً في مجلد المشروع لتسهيل بيئة التطوير
    if [[ -f "agent/${BINARY_NAME}" ]]; then
        log_info "Discovered local pre-compiled artifact at agent/${BINARY_NAME}. Installing directly..."
        cp "agent/${BINARY_NAME}" "${TARGET_PATH}"
    elif [[ -f "${BINARY_NAME}" ]]; then
        log_info "Discovered local pre-compiled artifact at ./${BINARY_NAME}. Installing directly..."
        cp "${BINARY_NAME}" "${TARGET_PATH}"
    else
        # 2. في حال عدم وجود الثنائي محلياً، جلبه عبر الشبكة
        local download_url="${SERVER_URL}/api/v1/download/linux/${detected_arch}"
        local tmp_binary="/tmp/${BINARY_NAME}_bootstrap.$$"
        log_info "Fetching ${detected_arch} agent binary from: ${download_url}"

        local curl_cmd=(curl -sSL --fail --connect-timeout 10 --max-time 120)
        if [[ -n "${CA_CERT_PATH}" ]]; then
            curl_cmd+=(--cacert "${CA_CERT_PATH}")
        fi

        if ! "${curl_cmd[@]}" "${download_url}" -o "${tmp_binary}"; then
            log_error "Failed to retrieve binary artifact from control plane."
            rm -f "${tmp_binary}"
            exit 1
        fi

        mv "${tmp_binary}" "${TARGET_PATH}"
    fi

    chmod 0750 "${TARGET_PATH}"
    chown root:root "${TARGET_PATH}"
    log_success "Binary successfully staged at ${TARGET_PATH} (Permissions: 0750)"
}

stop_existing_service() {
    if systemctl is-active --quiet "${BINARY_NAME}"; then
        log_info "Existing active instance detected. Halting running daemon..."
        if [[ -x "${TARGET_PATH}" ]]; then
            "${TARGET_PATH}" -service stop || systemctl stop "${BINARY_NAME}" || true
        else
            systemctl stop "${BINARY_NAME}" || true
        fi
    fi
}

enroll_agent() {
    log_info "Initiating cryptographic hardware enrollment against control plane..."

    local enroll_cmd=("${TARGET_PATH}" -server "${SERVER_URL}" -token "${ENROLL_TOKEN}")
    if [[ -n "${CA_CERT_PATH}" ]]; then
        enroll_cmd+=(-ca-cert "${CA_CERT_PATH}")
    fi

    if ! "${enroll_cmd[@]}"; then
        log_error "Endpoint enrollment failed. Verify token validity and network routes."
        exit 1
    fi

    log_success "Endpoint identity registered and credentials persisted."
}

register_and_start_service() {
    log_info "Registering native systemd background unit..."

    if [[ -f "/etc/systemd/system/${BINARY_NAME}.service" ]]; then
        if [[ -x "${TARGET_PATH}" ]]; then
            "${TARGET_PATH}" -service uninstall || true
        fi
    fi

    if ! "${TARGET_PATH}" -service install; then
        log_error "Failed to register systemd service."
        exit 1
    fi

    log_info "Launching background daemon..."
    if ! "${TARGET_PATH}" -service start; then
        log_error "Failed to start daemon via service manager."
        exit 1
    fi

    sleep 1

    if systemctl is-active --quiet "${BINARY_NAME}"; then
        log_success "Tactical RMM agent daemon is ACTIVE and running in background."
    else
        log_error "Service registered but not active. Inspect journal via: journalctl -u ${BINARY_NAME} -e"
        exit 1
    fi
}

main() {
    parse_arguments "$@"
    validate_prerequisites

    stop_existing_service

    local arch
    arch="$(detect_architecture)"

    install_agent_binary "${arch}"
    enroll_agent
    register_and_start_service

    log_success "Linux endpoint deployment completed cleanly."
}

main "$@"
