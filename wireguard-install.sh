#!/bin/bash

# ============================================================================
# WireGuard Auto-Install Script v2.0
# Complete VPN server deployment and management solution
# 
# Author: SatkiExE808
# Repository: https://github.com/SatkiExE808/wireguard-auto-install
# License: MIT
# 
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux
# Features: Auto-installation, Client management, Router compatibility,
#           QR codes, Backup/Restore, Performance monitoring
# ============================================================================

set -euo pipefail

# Script version and information
SCRIPT_VERSION="2.0.0"
SCRIPT_NAME="WireGuard Auto-Install"
GITHUB_REPO="https://github.com/SatkiExE808/wireguard-auto-install"

# Color codes for enhanced UI
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r MAGENTA='\033[0;35m'
declare -r CYAN='\033[0;36m'
declare -r WHITE='\033[1;37m'
declare -r GRAY='\033[0;90m'
declare -r NC='\033[0m' # No Color

# Configuration variables
WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NET="10.66.66"
SERVER_IP=""
CLIENT_DNS="1.1.1.1,8.8.8.8"
BACKUP_DIR="/var/backups/wireguard"
LOG_FILE="/var/log/wireguard-install.log"

# System information
OS=""
VERSION=""
ARCH=""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Enhanced logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Print functions with enhanced formatting
print_header() {
    echo -e "\n${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "INFO" "$1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARN" "$1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log "ERROR" "$1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log "INFO" "$1"
}

print_progress() {
    echo -e "${MAGENTA}[⟳]${NC} $1"
}

# Progress bar function
show_progress() {
    local duration=$1
    local description=$2
    local progress=0
    local bar_length=50
    
    echo -ne "${BLUE}$description${NC} ["
    
    while [ $progress -le 100 ]; do
        local filled=$((progress * bar_length / 100))
        local empty=$((bar_length - filled))
        
        printf "\r${BLUE}$description${NC} ["
        printf "%${filled}s" | tr ' ' '█'
        printf "%${empty}s" | tr ' ' '░'
        printf "] %d%%" $progress
        
        progress=$((progress + 2))
        sleep $(echo "scale=3; $duration / 50" | bc -l 2>/dev/null || echo "0.02")
    done
    
    echo -e " ${GREEN}✓${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# SYSTEM DETECTION AND VALIDATION
# ============================================================================

# Detect operating system and architecture
detect_system() {
    print_progress "Detecting system information..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) 
            print_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    print_status "System detected: $OS $VERSION ($ARCH)"
    log "INFO" "System: $OS $VERSION ($ARCH)"
}

# Validate system requirements
validate_requirements() {
    print_progress "Validating system requirements..."
    
    local requirements_met=true
    
    # Check supported OS
    case $OS in
        ubuntu|debian|centos|rhel|fedora|rocky|almalinux)
            print_status "Operating system supported: $OS"
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            requirements_met=false
            ;;
    esac
    
    # Check if virtualization is supported
    if [[ ! -e /dev/net/tun ]]; then
        print_error "TUN/TAP is not available. VPN functionality requires kernel TUN support"
        requirements_met=false
    else
        print_status "TUN/TAP support available"
    fi
    
    # Check available memory (minimum 512MB)
    local available_memory=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 256 ]]; then
        print_warning "Low available memory: ${available_memory}MB (recommended: 512MB+)"
    else
        print_status "Memory check passed: ${available_memory}MB available"
    fi
    
    # Check disk space (minimum 100MB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local available_space_mb=$((available_space / 1024))
    if [[ $available_space_mb -lt 100 ]]; then
        print_error "Insufficient disk space: ${available_space_mb}MB (minimum: 100MB)"
        requirements_met=false
    else
        print_status "Disk space check passed: ${available_space_mb}MB available"
    fi
    
    if [[ $requirements_met == false ]]; then
        print_error "System requirements not met. Aborting installation."
        exit 1
    fi
    
    print_status "All system requirements validated"
}

# ============================================================================
# NETWORK CONFIGURATION
# ============================================================================

# Get server public IP with multiple fallbacks
get_server_ip() {
    print_progress "Detecting server public IP address..."
    
    local ip_services=(
        "ipv4.icanhazip.com"
        "ifconfig.me"
        "ipinfo.io/ip"
        "checkip.amazonaws.com"
        "ip.42.pl/raw"
        "whatismyip.akamai.com"
    )
    
    for service in "${ip_services[@]}"; do
        SERVER_IP=$(curl -4 -s --max-time 5 "$service" 2>/dev/null | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if [[ -n $SERVER_IP ]]; then
            print_status "Public IP detected: $SERVER_IP (via $service)"
            return 0
        fi
    done
    
    # Manual IP input as fallback
    print_warning "Could not automatically detect public IP"
    echo -e "${YELLOW}Please enter your server's public IP address:${NC}"
    read -p "> " SERVER_IP
    
    # Validate IP format
    if [[ ! $SERVER_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Invalid IP address format"
        exit 1
    fi
    
    print_status "Using IP address: $SERVER_IP"
}

# Check if port is available
check_port_availability() {
    local port=$1
    if ss -tulpn | grep -q ":$port "; then
        print_warning "Port $port is already in use"
        echo -e "${YELLOW}Choose a different port (default: 51820):${NC}"
        read -p "> " custom_port
        WG_PORT=${custom_port:-51820}
        check_port_availability "$WG_PORT"
    else
        print_status "Port $WG_PORT is available"
    fi
}

# ============================================================================
# PACKAGE INSTALLATION
# ============================================================================

# Update system packages
update_system() {
    print_progress "Updating system packages..."
    
    case $OS in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null 2>&1
            apt-get upgrade -y -qq >/dev/null 2>&1
            ;;
        centos|rhel|rocky|almalinux)
            if command_exists dnf; then
                dnf update -y -q >/dev/null 2>&1
            else
                yum update -y -q >/dev/null 2>&1
            fi
            ;;
        fedora)
            dnf update -y -q >/dev/null 2>&1
            ;;
    esac
    
    print_status "System packages updated"
}

# Install required dependencies
install_dependencies() {
    print_progress "Installing dependencies..."
    
    local packages_common="curl wget gnupg software-properties-common"
    local packages_specific=""
    
    case $OS in
        ubuntu|debian)
            packages_specific="iptables-persistent resolvconf qrencode bc"
            apt-get install -y -qq $packages_common $packages_specific >/dev/null 2>&1
            ;;
        centos|rhel|rocky|almalinux)
            packages_specific="iptables-services qrencode bc bind-utils"
            if command_exists dnf; then
                dnf install -y -q epel-release >/dev/null 2>&1
                dnf install -y -q $packages_common $packages_specific >/dev/null 2>&1
            else
                yum install -y -q epel-release >/dev/null 2>&1
                yum install -y -q $packages_common $packages_specific >/dev/null 2>&1
            fi
            ;;
        fedora)
            packages_specific="iptables-services qrencode bc bind-utils"
            dnf install -y -q $packages_common $packages_specific >/dev/null 2>&1
            ;;
    esac
    
    print_status "Dependencies installed successfully"
}

# Install WireGuard
install_wireguard() {
    print_progress "Installing WireGuard..."
    
    case $OS in
        ubuntu)
            if [[ $(echo "$VERSION >= 20.04" | bc -l) -eq 1 ]]; then
                apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
            else
                # For Ubuntu < 20.04
                add-apt-repository ppa:wireguard/wireguard -y >/dev/null 2>&1
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
            fi
            ;;
        debian)
            if [[ $(echo "$VERSION >= 11" | bc -l) -eq 1 ]]; then
                apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
            else
                echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
                printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
            fi
            ;;
        centos|rhel|rocky|almalinux)
            if command_exists dnf; then
                dnf install -y -q wireguard-tools >/dev/null 2>&1
            else
                yum install -y -q wireguard-tools >/dev/null 2>&1
            fi
            ;;
        fedora)
            dnf install -y -q wireguard-tools >/dev/null 2>&1
            ;;
    esac
    
    # Verify installation
    if ! command_exists wg; then
        print_error "WireGuard installation failed"
        exit 1
    fi
    
    print_status "WireGuard installed successfully"
}

# ============================================================================
# WIREGUARD CONFIGURATION
# ============================================================================

# Generate server keys
generate_server_keys() {
    print_progress "Generating server cryptographic keys..."
    
    mkdir -p "$WG_CONFIG_DIR"
    cd "$WG_CONFIG_DIR"
    
    # Generate private key
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key server_public.key
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    print_status "Server keys generated and secured"
    print_info "Server public key: $SERVER_PUBLIC_KEY"
}

# Create server configuration
create_server_config() {
    print_progress "Creating server configuration..."
    
    # Get default network interface
    local default_interface=$(ip route | grep default | head -1 | awk '{print $5}')
    
    cat > "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF
# WireGuard Server Configuration
# Generated by $SCRIPT_NAME v$SCRIPT_VERSION
# $(date)

[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $WG_NET.1/24
ListenPort = $WG_PORT
SaveConfig = false

# Firewall rules and IP forwarding
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
PostUp = iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $default_interface -j MASQUERADE
PostUp = echo 1 > /proc/sys/net/ipv4/ip_forward

PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT
PostDown = iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $default_interface -j MASQUERADE

EOF
    
    chmod 600 "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    print_status "Server configuration created"
}

# Enable IP forwarding
enable_ip_forwarding() {
    print_progress "Configuring IP forwarding..."
    
    # Enable IP forwarding permanently
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
    echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1
    
    print_status "IP forwarding enabled"
}

# Configure firewall
configure_firewall() {
    print_progress "Configuring firewall rules..."
    
    # Detect and configure firewall
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        # Ubuntu/Debian UFW
        ufw allow "$WG_PORT/udp" >/dev/null 2>&1
        ufw --force reload >/dev/null 2>&1
        print_status "UFW firewall configured"
        
    elif command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
        # CentOS/RHEL/Fedora firewalld
        firewall-cmd --permanent --add-port="$WG_PORT/udp" >/dev/null 2>&1
        firewall-cmd --permanent --add-masquerade >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_status "Firewalld configured"
        
    else
        # Direct iptables rules
        iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        
        # Save iptables rules based on system
        if command_exists netfilter-persistent; then
            netfilter-persistent save >/dev/null 2>&1
        elif [[ -d /etc/iptables ]]; then
            iptables-save > /etc/iptables/rules.v4
        fi
        
        print_status "Iptables rules configured"
    fi
}

# ============================================================================
# SERVICE MANAGEMENT
# ============================================================================

# Start and enable WireGuard service
start_wireguard_service() {
    print_progress "Starting WireGuard service..."
    
    # Enable and start WireGuard
    systemctl enable wg-quick@"$WG_INTERFACE" >/dev/null 2>&1
    systemctl start wg-quick@"$WG_INTERFACE" >/dev/null 2>&1
    
    # Verify service is running
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE"; then
        print_status "WireGuard service started and enabled"
    else
        print_error "Failed to start WireGuard service"
        print_info "Check logs: journalctl -u wg-quick@$WG_INTERFACE"
        exit 1
    fi
}

# ============================================================================
# CLIENT MANAGEMENT
# ============================================================================

# Generate client configuration
generate_client_config() {
    local client_name=$1
    local client_number=$2
    local client_ip="$WG_NET.$client_number"
    
    print_progress "Generating client configuration: $client_name"
    
    # Read server public key
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        SERVER_PUBLIC_KEY=$(cat "$WG_CONFIG_DIR/server_public.key")
    else
        print_error "Server public key not found"
        return 1
    fi
    
    # Generate client keys
    local client_private_key client_public_key
    client_private_key=$(wg genkey)
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    
    # Create client configuration directory
    mkdir -p "$WG_CONFIG_DIR/clients"
    
    # Create client configuration file
    cat > "$WG_CONFIG_DIR/clients/$client_name.conf" << EOF
# WireGuard Client Configuration: $client_name
# Generated: $(date)
# Server: $SERVER_IP:$WG_PORT

[Interface]
PrivateKey = $client_private_key
Address = $client_ip/32
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Add client peer to server configuration
    cat >> "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF

# Client: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32
EOF
    
    # Generate router-compatible versions
    create_router_configs "$client_name" "$client_private_key" "$client_ip"
    
    print_status "Client '$client_name' configuration created"
    print_info "Client IP: $client_ip"
    
    return 0
}

# Create router-compatible configurations
create_router_configs() {
    local client_name=$1
    local client_private_key=$2
    local client_ip=$3
    
    local router_dir="$WG_CONFIG_DIR/clients/$client_name-router-configs"
    mkdir -p "$router_dir"
    
    # Standard format (most routers)
    cat > "$router_dir/standard.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/32
DNS = 1.1.1.1,8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Single DNS (Asus/Netgear)
    cat > "$router_dir/single-dns.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # No DNS (OpenWrt/DD-WRT)
    cat > "$router_dir/no-dns.conf" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/32

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
}

# Add new client
add_client() {
    print_header "Add New WireGuard Client"
    
    echo -e "${BLUE}Enter client name (alphanumeric only):${NC}"
    read -p "> " client_name
    
    # Validate client name
    if [[ ! $client_name =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Invalid client name. Use only letters, numbers, hyphens, and underscores."
        return 1
    fi
    
    # Check if client already exists
    if [[ -f "$WG_CONFIG_DIR/clients/$client_name.conf" ]]; then
        print_error "Client '$client_name' already exists"
        return 1
    fi
    
    # Find next available IP
    local next_ip=2
    while wg show "$WG_INTERFACE" 2>/dev/null | grep -q "$WG_NET.$next_ip"; do
        ((next_ip++))
        if [[ $next_ip -gt 254 ]]; then
            print_error "No available IP addresses in the range"
            return 1
        fi
    done
    
    # Generate client configuration
    if generate_client_config "$client_name" "$next_ip"; then
        # Reload WireGuard configuration
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")
        
        # Display client configuration
        echo ""
        print_header "Client Configuration Generated"
        echo -e "${YELLOW}Client:${NC} $client_name"
        echo -e "${YELLOW}IP Address:${NC} $WG_NET.$next_ip"
        echo -e "${YELLOW}Configuration File:${NC} $WG_CONFIG_DIR/clients/$client_name.conf"
        
        # Show QR code if qrencode is available
        if command_exists qrencode; then
            echo ""
            print_info "QR Code for mobile devices:"
            echo ""
            qrencode -t ansiutf8 < "$WG_CONFIG_DIR/clients/$client_name.conf"
            echo ""
        fi
        
        # Show configuration content
        echo -e "${CYAN}Configuration content:${NC}"
        echo -e "${GRAY}$(cat "$WG_CONFIG_DIR/clients/$client_name.conf")${NC}"
        
        print_status "Client added successfully!"
        return 0
    else
        print_error "Failed to generate client configuration"
        return 1
    fi
}

# List all clients
list_clients() {
    print_header "WireGuard Clients Overview"
    
    echo -e "${BLUE}Active connections:${NC}"
    if wg show "$WG_INTERFACE" 2>/dev/null | grep -q "peer:"; then
        wg show "$WG_INTERFACE" | grep -E "(peer|endpoint|latest handshake|transfer)"
    else
        echo "  No active connections"
    fi
    
    echo ""
    echo -e "${BLUE}Available client configurations:${NC}"
    
    if [[ -d "$WG_CONFIG_DIR/clients" ]]; then
        local count=0
        for config in "$WG_CONFIG_DIR/clients"/*.conf; do
            if [[ -f $config ]]; then
                local client_name=$(basename "$config" .conf)
                local client_ip=$(grep "Address" "$config" | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
                printf "  %-20s %s\n" "$client_name" "$client_ip"
                ((count++))
            fi
        done
        
        if [[ $count -eq 0 ]]; then
            echo "  No client configurations found"
        else
            echo ""
            print_info "Total clients: $count"
        fi
    else
        echo "  No client configurations found"
    fi
}

# Show client configuration
show_client_config() {
    print_header "Show Client Configuration"
    
    if [[ ! -d "$WG_CONFIG_DIR/clients" ]] || [[ -z $(find "$WG_CONFIG_DIR/clients" -name "*.conf" 2>/dev/null) ]]; then
        print_warning "No client configurations found"
        return 1
    fi
    
    echo -e "${BLUE}Available clients:${NC}"
    local clients=()
    local count=1
    
    for config in "$WG_CONFIG_DIR/clients"/*.conf; do
        if [[ -f $config ]]; then
            local client_name=$(basename "$config" .conf)
            echo "  $count. $client_name"
            clients+=("$client_name")
            ((count++))
        fi
    done
    
    echo ""
    echo -e "${BLUE}Enter client name or number:${NC}"
    read -p "> " selection
    
    local client_name=""
    if [[ $selection =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -lt $count ]]; then
        client_name="${clients[$((selection-1))]}"
    else
        client_name="$selection"
    fi
    
    local config_file="$WG_CONFIG_DIR/clients/$client_name.conf"
    
    if [[ ! -f $config_file ]]; then
        print_error "Client '$client_name' not found"
        return 1
    fi
    
    print_header "Configuration: $client_name"
    
    echo -e "${CYAN}Main configuration:${NC}"
    cat "$config_file"
    
    echo ""
    if command_exists qrencode; then
        print_info "QR Code:"
        qrencode -t ansiutf8 < "$config_file"
    fi
    
    # Show router configurations if they exist
    local router_dir="$WG_CONFIG_DIR/clients/$client_name-router-configs"
    if [[ -d $router_dir ]]; then
        echo ""
        print_info "Router-compatible configurations available in: $router_dir"
        ls -1 "$router_dir"
    fi
}

# Remove client
remove_client() {
    print_header "Remove WireGuard Client"
    
    if [[ ! -d "$WG_CONFIG_DIR/clients" ]] || [[ -z $(find "$WG_CONFIG_DIR/clients" -name "*.conf" 2>/dev/null) ]]; then
        print_warning "No client configurations found"
        return 1
    fi
    
    echo -e "${BLUE}Available clients:${NC}"
    local clients=()
    local count=1
    
    for config in "$WG_CONFIG_DIR/clients"/*.conf; do
        if [[ -f $config ]]; then
            local client_name=$(basename "$config" .conf)
            echo "  $count. $client_name"
            clients+=("$client_name")
            ((count++))
        fi
    done
    
    echo ""
    echo -e "${BLUE}Enter client name or number to remove:${NC}"
    read -p "> " selection
    
    local client_name=""
    if [[ $selection =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -lt $count ]]; then
        client_name="${clients[$((selection-1))]}"
    else
        client_name="$selection"
    fi
    
    local config_file="$WG_CONFIG_DIR/clients/$client_name.conf"
    
    if [[ ! -f $config_file ]]; then
        print_error "Client '$client_name' not found"
        return 1
    fi
    
    # Confirmation
    echo ""
    echo -e "${RED}Warning: This will permanently remove client '$client_name'${NC}"
    echo -e "${BLUE}Are you sure? (y/N):${NC}"
    read -p "> " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Operation cancelled"
        return 0
    fi
    
    # Get client public key for removal from server config
    local client_private_key client_public_key
    client_private_key=$(grep "PrivateKey" "$config_file" | cut -d'=' -f2 | tr -d ' ')
    client_public_key=$(echo "$client_private_key" | wg pubkey)
    
    # Remove client files
    rm -f "$config_file"
    rm -rf "$WG_CONFIG_DIR/clients/$client_name-router-configs"
    
    # Remove client from server configuration
    create_backup "before-client-removal-$client_name"
    
    # Create temporary file without the client peer
    local temp_config=$(mktemp)
    local in_peer_section=false
    local peer_to_remove=false
    
    while IFS= read -r line; do
        if [[ $line =~ ^\[Peer\] ]]; then
            in_peer_section=true
            peer_to_remove=false
            peer_section="$line"
            continue
        elif [[ $line =~ ^\[.*\] ]] && [[ $in_peer_section == true ]]; then
            # New section started, write previous peer if not the one to remove
            if [[ $peer_to_remove == false ]] && [[ -n $peer_section ]]; then
                echo "$peer_section" >> "$temp_config"
                echo "$peer_content" >> "$temp_config"
            fi
            in_peer_section=false
            echo "$line" >> "$temp_config"
            peer_section=""
            peer_content=""
            continue
        fi
        
        if [[ $in_peer_section == true ]]; then
            peer_content+="$line"\n'
            if [[ $line =~ PublicKey.*$client_public_key ]]; then
                peer_to_remove=true
            fi
        else
            echo "$line" >> "$temp_config"
        fi
    done < "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    
    # Write the final peer if it's not the one to remove
    if [[ $in_peer_section == true ]] && [[ $peer_to_remove == false ]] && [[ -n $peer_section ]]; then
        echo "$peer_section" >> "$temp_config"
        echo "$peer_content" >> "$temp_config"
    fi
    
    # Replace server config with cleaned version
    mv "$temp_config" "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    chmod 600 "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    
    # Reload WireGuard configuration
    wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")
    
    print_status "Client '$client_name' removed successfully"
}

# ============================================================================
# BACKUP AND RESTORE
# ============================================================================

# Create configuration backup
create_backup() {
    local backup_name=${1:-"manual-$(date +%Y%m%d-%H%M%S)"}
    local backup_path="$BACKUP_DIR/$backup_name"
    
    print_progress "Creating backup: $backup_name"
    
    mkdir -p "$backup_path"
    
    # Backup WireGuard configuration
    cp -r "$WG_CONFIG_DIR" "$backup_path/"
    
    # Backup system configuration
    mkdir -p "$backup_path/system"
    cp /etc/sysctl.d/99-wireguard.conf "$backup_path/system/" 2>/dev/null || true
    
    # Create backup info file
    cat > "$backup_path/backup-info.txt" << EOF
Backup created: $(date)
Script version: $SCRIPT_VERSION
Server IP: $SERVER_IP
WireGuard interface: $WG_INTERFACE
WireGuard port: $WG_PORT
Network: $WG_NET.0/24
System: $OS $VERSION ($ARCH)
EOF
    
    # Compress backup
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name" >/dev/null 2>&1
    rm -rf "$backup_path"
    
    print_status "Backup created: $backup_path.tar.gz"
    return 0
}

# List available backups
list_backups() {
    print_header "Available Backups"
    
    if [[ ! -d $BACKUP_DIR ]] || [[ -z $(find "$BACKUP_DIR" -name "*.tar.gz" 2>/dev/null) ]]; then
        print_warning "No backups found"
        return 1
    fi
    
    echo -e "${BLUE}Backup files:${NC}"
    local count=1
    for backup in "$BACKUP_DIR"/*.tar.gz; do
        if [[ -f $backup ]]; then
            local backup_name=$(basename "$backup" .tar.gz)
            local backup_size=$(du -h "$backup" | cut -f1)
            local backup_date=$(date -r "$backup" '+%Y-%m-%d %H:%M:%S')
            printf "  %d. %-30s %8s  %s\n" "$count" "$backup_name" "$backup_size" "$backup_date"
            ((count++))
        fi
    done
}

# Restore from backup
restore_backup() {
    print_header "Restore Configuration"
    
    if [[ ! -d $BACKUP_DIR ]] || [[ -z $(find "$BACKUP_DIR" -name "*.tar.gz" 2>/dev/null) ]]; then
        print_warning "No backups found"
        return 1
    fi
    
    list_backups
    
    echo ""
    echo -e "${BLUE}Enter backup name or number to restore:${NC}"
    read -p "> " selection
    
    local backups=()
    for backup in "$BACKUP_DIR"/*.tar.gz; do
        if [[ -f $backup ]]; then
            backups+=($(basename "$backup" .tar.gz))
        fi
    done
    
    local backup_name=""
    if [[ $selection =~ ^[0-9]+$ ]] && [[ $selection -ge 1 ]] && [[ $selection -le ${#backups[@]} ]]; then
        backup_name="${backups[$((selection-1))]}"
    else
        backup_name="$selection"
    fi
    
    local backup_file="$BACKUP_DIR/$backup_name.tar.gz"
    
    if [[ ! -f $backup_file ]]; then
        print_error "Backup '$backup_name' not found"
        return 1
    fi
    
    # Confirmation
    echo ""
    echo -e "${RED}Warning: This will replace current configuration with backup '$backup_name'${NC}"
    echo -e "${BLUE}Are you sure? (y/N):${NC}"
    read -p "> " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Restore cancelled"
        return 0
    fi
    
    # Create backup of current configuration before restore
    create_backup "before-restore-$(date +%Y%m%d-%H%M%S)"
    
    # Stop WireGuard
    systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    
    # Extract and restore
    local temp_dir=$(mktemp -d)
    tar -xzf "$backup_file" -C "$temp_dir" >/dev/null 2>&1
    
    # Restore WireGuard configuration
    rm -rf "$WG_CONFIG_DIR"
    cp -r "$temp_dir/$backup_name/wireguard" "$WG_CONFIG_DIR"
    
    # Restore system configuration
    if [[ -f "$temp_dir/$backup_name/system/99-wireguard.conf" ]]; then
        cp "$temp_dir/$backup_name/system/99-wireguard.conf" /etc/sysctl.d/
        sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1
    fi
    
    # Clean up
    rm -rf "$temp_dir"
    
    # Restart WireGuard
    systemctl start wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    
    print_status "Configuration restored from backup: $backup_name"
}

# ============================================================================
# MONITORING AND STATISTICS
# ============================================================================

# Show server status and statistics
show_server_status() {
    print_header "WireGuard Server Status"
    
    # Service status
    echo -e "${BLUE}Service Status:${NC}"
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE"; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo -e "  Uptime: $(systemctl show -p ActiveEnterTimestamp wg-quick@"$WG_INTERFACE" --value | xargs -I {} date -d {} +'%Y-%m-%d %H:%M:%S')"
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    
    # Server configuration
    echo ""
    echo -e "${BLUE}Server Configuration:${NC}"
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        local server_public_key=$(cat "$WG_CONFIG_DIR/server_public.key")
        echo -e "  Public Key: $server_public_key"
    fi
    echo -e "  Listen Port: $WG_PORT"
    echo -e "  Server IP: ${SERVER_IP:-"Not detected"}"
    echo -e "  Network: $WG_NET.0/24"
    
    # Interface statistics
    echo ""
    echo -e "${BLUE}Interface Statistics:${NC}"
    if wg show "$WG_INTERFACE" >/dev/null 2>&1; then
        wg show "$WG_INTERFACE"
    else
        echo "  Interface not active"
    fi
    
    # System resources
    echo ""
    echo -e "${BLUE}System Resources:${NC}"
    echo -e "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
    echo -e "  Memory Usage: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
    echo -e "  Disk Usage: $(df / | awk 'NR==2 {printf "%.1f%%", $5}' | sed 's/%//')"
    
    # Network statistics
    echo ""
    echo -e "${BLUE}Network Statistics:${NC}"
    if [[ -f "/sys/class/net/$WG_INTERFACE/statistics/rx_bytes" ]]; then
        local rx_bytes=$(cat "/sys/class/net/$WG_INTERFACE/statistics/rx_bytes")
        local tx_bytes=$(cat "/sys/class/net/$WG_INTERFACE/statistics/tx_bytes")
        echo -e "  Received: $(numfmt --to=iec-i --suffix=B $rx_bytes)"
        echo -e "  Transmitted: $(numfmt --to=iec-i --suffix=B $tx_bytes)"
    fi
}

# Monitor real-time connections
monitor_connections() {
    print_header "Real-time Connection Monitor"
    print_info "Press Ctrl+C to exit"
    
    echo ""
    
    trap 'echo; print_info "Monitoring stopped"; exit 0' INT
    
    while true; do
        clear
        echo -e "${CYAN}WireGuard Connection Monitor - $(date)${NC}"
        echo -e "${GRAY}$(printf '=%.0s' {1..60})${NC}"
        
        if wg show "$WG_INTERFACE" >/dev/null 2>&1; then
            wg show "$WG_INTERFACE"
        else
            echo "WireGuard interface not active"
        fi
        
        echo ""
        echo -e "${GRAY}Refreshing every 5 seconds... Press Ctrl+C to exit${NC}"
        sleep 5
    done
}

# ============================================================================
# MAINTENANCE AND UTILITIES
# ============================================================================

# Update script
update_script() {
    print_header "Update WireGuard Script"
    
    local latest_url="https://raw.githubusercontent.com/SatkiExE808/wireguard-auto-install/main/wireguard-install.sh"
    local script_path="$0"
    
    print_progress "Checking for updates..."
    
    # Download latest version info
    local latest_version
    if ! latest_version=$(curl -s --max-time 10 "$latest_url" | grep "SCRIPT_VERSION=" | head -1 | cut -d'"' -f2); then
        print_error "Failed to check for updates"
        return 1
    fi
    
    if [[ $latest_version == "$SCRIPT_VERSION" ]]; then
        print_info "You are running the latest version ($SCRIPT_VERSION)"
        return 0
    fi
    
    print_info "New version available: $latest_version (current: $SCRIPT_VERSION)"
    
    echo -e "${BLUE}Do you want to update? (y/N):${NC}"
    read -p "> " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Update cancelled"
        return 0
    fi
    
    # Backup current script
    cp "$script_path" "$script_path.backup-$(date +%Y%m%d-%H%M%S)"
    
    # Download new version
    if curl -s --max-time 30 "$latest_url" -o "$script_path"; then
        chmod +x "$script_path"
        print_status "Script updated successfully to version $latest_version"
        print_info "Please restart the script to use the new version"
    else
        print_error "Failed to download update"
        # Restore backup
        mv "$script_path.backup-"* "$script_path" 2>/dev/null || true
        return 1
    fi
}

# Run system diagnostics
run_diagnostics() {
    print_header "System Diagnostics"
    
    local issues_found=0
    
    print_progress "Running comprehensive system diagnostics..."
    
    echo -e "${BLUE}WireGuard Installation:${NC}"
    if command_exists wg; then
        print_status "WireGuard tools installed"
        echo -e "  Version: $(wg --version | head -1)"
    else
        print_error "WireGuard tools not found"
        ((issues_found++))
    fi
    
    echo ""
    echo -e "${BLUE}Service Status:${NC}"
    if systemctl is-enabled wg-quick@"$WG_INTERFACE" >/dev/null 2>&1; then
        print_status "Service enabled"
    else
        print_warning "Service not enabled"
        ((issues_found++))
    fi
    
    if systemctl is-active wg-quick@"$WG_INTERFACE" >/dev/null 2>&1; then
        print_status "Service running"
    else
        print_error "Service not running"
        ((issues_found++))
    fi
    
    echo ""
    echo -e "${BLUE}Configuration Files:${NC}"
    if [[ -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
        print_status "Server configuration exists"
        
        # Validate configuration
        if wg-quick strip "$WG_INTERFACE" >/dev/null 2>&1; then
            print_status "Server configuration is valid"
        else
            print_error "Server configuration has errors"
            ((issues_found++))
        fi
    else
        print_error "Server configuration not found"
        ((issues_found++))
    fi
    
    if [[ -f "$WG_CONFIG_DIR/server_private.key" && -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        print_status "Server keys exist"
    else
        print_warning "Server keys missing"
    fi
    
    echo ""
    echo -e "${BLUE}Network Configuration:${NC}"
    
    # Check IP forwarding
    if [[ $(cat /proc/sys/net/ipv4/ip_forward) == "1" ]]; then
        print_status "IP forwarding enabled"
    else
        print_error "IP forwarding disabled"
        ((issues_found++))
    fi
    
    # Check TUN device
    if [[ -e /dev/net/tun ]]; then
        print_status "TUN device available"
    else
        print_error "TUN device not available"
        ((issues_found++))
    fi
    
    # Check port binding
    if ss -tulpn | grep -q ":$WG_PORT "; then
        print_status "WireGuard port ($WG_PORT) is bound"
    else
        print_warning "WireGuard port ($WG_PORT) not bound"
    fi
    
    echo ""
    echo -e "${BLUE}Firewall Status:${NC}"
    
    # Check various firewall systems
    local firewall_configured=false
    
    if command_exists ufw && ufw status | grep -q "Status: active"; then
        if ufw status | grep -q "$WG_PORT/udp"; then
            print_status "UFW configured for WireGuard"
            firewall_configured=true
        else
            print_warning "UFW active but WireGuard port not allowed"
        fi
    fi
    
    if command_exists firewall-cmd && systemctl is-active firewalld >/dev/null 2>&1; then
        if firewall-cmd --list-ports | grep -q "$WG_PORT/udp"; then
            print_status "Firewalld configured for WireGuard"
            firewall_configured=true
        else
            print_warning "Firewalld active but WireGuard port not open"
        fi
    fi
    
    if [[ $firewall_configured == false ]]; then
        print_info "Using iptables rules directly"
    fi
    
    echo ""
    echo -e "${BLUE}Client Configurations:${NC}"
    if [[ -d "$WG_CONFIG_DIR/clients" ]]; then
        local client_count=$(find "$WG_CONFIG_DIR/clients" -name "*.conf" 2>/dev/null | wc -l)
        print_info "Client configurations: $client_count"
    else
        print_info "No client configurations found"
    fi
    
    echo ""
    if [[ $issues_found -eq 0 ]]; then
        print_status "All diagnostics passed! ✅"
    else
        print_warning "Found $issues_found issue(s) that may need attention ⚠️"
    fi
}

# Uninstall WireGuard completely
uninstall_wireguard() {
    print_header "Uninstall WireGuard"
    
    echo -e "${RED}⚠️  WARNING: This will completely remove WireGuard and all configurations!${NC}"
    echo -e "${YELLOW}The following will be removed:${NC}"
    echo "  • WireGuard service and configuration"
    echo "  • All client configurations"
    echo "  • Server keys and certificates"
    echo "  • Firewall rules"
    echo "  • System configuration changes"
    echo ""
    echo -e "${BLUE}Do you want to create a backup before uninstalling? (Y/n):${NC}"
    read -p "> " backup_confirm
    
    if [[ $backup_confirm != [nN] ]]; then
        create_backup "final-backup-$(date +%Y%m%d-%H%M%S)"
    fi
    
    echo ""
    echo -e "${RED}Are you absolutely sure you want to uninstall WireGuard? (y/N):${NC}"
    read -p "> " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Uninstallation cancelled"
        return 0
    fi
    
    print_progress "Uninstalling WireGuard..."
    
    # Stop and disable service
    systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl disable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    
    # Remove configurations
    rm -rf "$WG_CONFIG_DIR"
    rm -f /etc/sysctl.d/99-wireguard.conf
    
    # Remove firewall rules
    if command_exists ufw; then
        ufw delete allow "$WG_PORT/udp" 2>/dev/null || true
    fi
    
    if command_exists firewall-cmd; then
        firewall-cmd --permanent --remove-port="$WG_PORT/udp" 2>/dev/null || true
        firewall-cmd --permanent --remove-masquerade 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
    
    # Reset sysctl
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    
    print_status "WireGuard uninstalled successfully"
    print_info "Backups (if any) are preserved in: $BACKUP_DIR"
}

# ============================================================================
# MAIN MENU AND USER INTERFACE
# ============================================================================

# Display main menu
show_main_menu() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║               🛡️  WireGuard Auto-Install v$SCRIPT_VERSION                ║"
    echo "║                                                              ║"
    echo "║         Complete VPN Server Management Solution             ║"
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE" 2>/dev/null; then
        echo -e "${GREEN}Status: WireGuard is running${NC} 🟢"
        if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
            echo -e "${GRAY}Server: $(cat "$WG_CONFIG_DIR/server_public.key" | cut -c1-20)...${NC}"
        fi
        echo -e "${GRAY}Network: $WG_NET.0/24 | Port: $WG_PORT${NC}"
    else
        echo -e "${YELLOW}Status: WireGuard not installed or stopped${NC} 🟡"
    fi
    
    echo ""
    echo -e "${BLUE}📋 Main Menu:${NC}"
    echo ""
    echo -e "  ${WHITE}Installation & Setup:${NC}"
    echo -e "    1️⃣   Install WireGuard Server"
    echo -e "    2️⃣   Run System Diagnostics"
    echo ""
    echo -e "  ${WHITE}Client Management:${NC}"
    echo -e "    3️⃣   Add New Client"
    echo -e "    4️⃣   List All Clients"
    echo -e "    5️⃣   Show Client Configuration"
    echo -e "    6️⃣   Remove Client"
    echo ""
    echo -e "  ${WHITE}Monitoring & Status:${NC}"
    echo -e "    7️⃣   Show Server Status"
    echo -e "    8️⃣   Monitor Connections (Real-time)"
    echo ""
    echo -e "  ${WHITE}Backup & Maintenance:${NC}"
    echo -e "    9️⃣   Create Backup"
    echo -e "    🔟   List Backups"
    echo -e "    1️⃣1️⃣   Restore from Backup"
    echo ""
    echo -e "  ${WHITE}System Management:${NC}"
    echo -e "    1️⃣2️⃣   Update Script"
    echo -e "    1️⃣3️⃣   Uninstall WireGuard"
    echo -e "    1️⃣4️⃣   Exit"
    echo ""
    echo -e "${GRAY}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Handle menu selection
handle_menu_selection() {
    echo -e "${BLUE}Enter your choice [1-14]:${NC}"
    read -p "> " choice
    
    case $choice in
        1)
            install_complete_server
            ;;
        2)
            run_diagnostics
            ;;
        3)
            add_client
            ;;
        4)
            list_clients
            ;;
        5)
            show_client_config
            ;;
        6)
            remove_client
            ;;
        7)
            show_server_status
            ;;
        8)
            monitor_connections
            ;;
        9)
            create_backup
            ;;
        10)
            list_backups
            ;;
        11)
            restore_backup
            ;;
        12)
            update_script
            ;;
        13)
            uninstall_wireguard
            ;;
        14)
            print_info "Thank you for using WireGuard Auto-Install!"
            exit 0
            ;;
        *)
            print_error "Invalid option. Please choose 1-14."
            ;;
    esac
}

# ============================================================================
# COMPLETE INSTALLATION PROCESS
# ============================================================================

# Complete server installation
install_complete_server() {
    if [[ -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
        print_warning "WireGuard is already installed"
        echo -e "${BLUE}Do you want to reinstall? This will remove all current configurations. (y/N):${NC}"
        read -p "> " reinstall_confirm
        
        if [[ $reinstall_confirm != [yY] ]]; then
            return 0
        fi
        
        # Create backup before reinstallation
        create_backup "before-reinstall-$(date +%Y%m%d-%H%M%S)"
        
        # Stop and remove current installation
        systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
        systemctl disable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
        rm -rf "$WG_CONFIG_DIR"
    fi
    
    print_header "$SCRIPT_NAME v$SCRIPT_VERSION - Complete Installation"
    
    # Pre-installation steps
    show_progress 0.5 "Initializing"
    detect_system
    validate_requirements
    
    # Network configuration
    show_progress 0.5 "Configuring network"
    get_server_ip
    check_port_availability "$WG_PORT"
    
    # System updates and packages
    show_progress 2 "Updating system"
    update_system
    
    show_progress 1.5 "Installing dependencies"
    install_dependencies
    
    show_progress 1 "Installing WireGuard"
    install_wireguard
    
    # WireGuard configuration
    show_progress 0.5 "Generating keys"
    generate_server_keys
    
    show_progress 0.5 "Creating configuration"
    create_server_config
    
    # System configuration
    show_progress 0.5 "Configuring IP forwarding"
    enable_ip_forwarding
    
    show_progress 1 "Configuring firewall"
    configure_firewall
    
    # Service management
    show_progress 0.5 "Starting service"
    start_wireguard_service
    
    # Create initial backup
    create_backup "initial-install-$(date +%Y%m%d-%H%M%S)"
    
    # Installation complete
    echo ""
    print_header "🎉 Installation Complete!"
    
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║               ✅ WireGuard Server Ready!                      ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    
    echo ""
    echo -e "${YELLOW}Server Details:${NC}"
    echo -e "  🔑 Public Key: $SERVER_PUBLIC_KEY"
    echo -e "  🌐 Server IP: $SERVER_IP"
    echo -e "  🔌 Listen Port: $WG_PORT"
    echo -e "  📡 Network: $WG_NET.0/24"
    
    echo ""
    print_status "WireGuard server is now running and ready for clients!"
    print_info "Use option 3 from the main menu to add your first client"
    
    log "INFO" "WireGuard installation completed successfully"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Initialize logging
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/wireguard-install.log"
    log "INFO" "Script started - $SCRIPT_NAME v$SCRIPT_VERSION"
}

# Main function
main() {
    # Initialize
    setup_logging
    check_root
    
    # Handle command line arguments
    case "${1:-}" in
        --install|-i)
            install_complete_server
            exit 0
            ;;
        --add-client|-a)
            add_client
            exit 0
            ;;
        --list-clients|-l)
            list_clients
            exit 0
            ;;
        --status|-s)
            show_server_status
            exit 0
            ;;
        --backup|-b)
            create_backup
            exit 0
            ;;
        --help|-h)
            echo "WireGuard Auto-Install v$SCRIPT_VERSION"
            echo ""
            echo "Usage: $0 [option]"
            echo ""
            echo "Options:"
            echo "  -i, --install      Install WireGuard server"
            echo "  -a, --add-client   Add new client"
            echo "  -l, --list-clients List all clients"
            echo "  -s, --status       Show server status"
            echo "  -b, --backup       Create backup"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Interactive mode: $0 (no arguments)"
            exit 0
            ;;
        --version|-v)
            echo "$SCRIPT_NAME v$SCRIPT_VERSION"
            exit 0
            ;;
    esac
    
    # Interactive mode
    while true; do
        show_main_menu
        handle_menu_selection
        
        echo ""
        echo -e "${GRAY}Press Enter to continue...${NC}"
        read -r
    done
}

# Run main function with all arguments
main "$@"
