#!/bin/bash

# WireGuard Auto-Install Script - Complete Final Version
# Includes automatic reinstall and full management features

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NET="10.66.66"
SERVER_IP=""
CLIENT_DNS="1.1.1.1,8.8.8.8"
SCRIPT_VERSION="2.1.0"

# Print functions
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC} ${WHITE}$1${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        print_status "System detected: $OS $VERSION"
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
}

# Get server IP
get_server_ip() {
    SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    if [[ -z "$SERVER_IP" ]]; then
        print_warning "Could not detect IP automatically"
        read -p "Enter your server's public IP: " SERVER_IP
    fi
    print_status "Server IP: $SERVER_IP"
}

# Install WireGuard
install_wireguard() {
    print_info "Installing WireGuard..."
    
    case $OS in
        ubuntu|debian)
            apt update -qq
            apt install -y wireguard wireguard-tools qrencode iptables-persistent
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y epel-release
                dnf install -y wireguard-tools qrencode
            else
                yum install -y epel-release
                yum install -y wireguard-tools qrencode
            fi
            ;;
        *)
            print_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    print_status "WireGuard installed"
}

# Generate server keys
generate_server_keys() {
    print_info "Generating server keys..."
    
    mkdir -p "$WG_CONFIG_DIR"
    cd "$WG_CONFIG_DIR"
    
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key server_public.key
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    print_status "Server keys generated"
}

# Create server config
create_server_config() {
    print_info "Creating server configuration..."
    
    cat > "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $WG_NET.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o \$(ip route | awk '/default/ { print \$5 }') -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o \$(ip route | awk '/default/ { print \$5 }') -j MASQUERADE

EOF
    
    chmod 600 "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    print_status "Server configuration created"
}

# Enable IP forwarding
enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1
    print_status "IP forwarding enabled"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$WG_PORT/udp" >/dev/null 2>&1
        ufw --force reload >/dev/null 2>&1
        print_status "UFW configured"
    elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$WG_PORT/udp" >/dev/null 2>&1
        firewall-cmd --permanent --add-masquerade >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        print_status "Firewalld configured"
    else
        iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT
        print_status "Iptables configured"
    fi
}

# Start WireGuard service
start_wireguard() {
    print_info "Starting WireGuard service..."
    systemctl enable wg-quick@"$WG_INTERFACE" >/dev/null 2>&1
    systemctl start wg-quick@"$WG_INTERFACE" >/dev/null 2>&1
    
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE"; then
        print_status "WireGuard service started"
    else
        print_error "Failed to start WireGuard"
        exit 1
    fi
}

# Automatic clean uninstall (for reinstall)
clean_uninstall() {
    local silent=${1:-false}
    
    if [[ $silent == false ]]; then
        print_info "Performing clean uninstall..."
    fi
    
    # Stop and disable WireGuard service
    systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl disable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    
    # Remove WireGuard package
    case $OS in
        ubuntu|debian)
            apt-get remove --purge -y wireguard wireguard-tools 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf remove -y wireguard-tools 2>/dev/null || true
            else
                yum remove -y wireguard-tools 2>/dev/null || true
            fi
            ;;
    esac
    
    # Remove all configuration files
    rm -rf "$WG_CONFIG_DIR" 2>/dev/null || true
    
    # Remove system configuration
    rm -f /etc/sysctl.d/99-wireguard.conf 2>/dev/null || true
    
    # Reset IP forwarding
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    
    # Remove firewall rules
    if command -v ufw &> /dev/null; then
        ufw delete allow "$WG_PORT/udp" 2>/dev/null || true
    fi
    
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --remove-port="$WG_PORT/udp" 2>/dev/null || true
        firewall-cmd --permanent --remove-masquerade 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    fi
    
    # Clean up iptables rules (basic cleanup)
    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -t nat -F POSTROUTING 2>/dev/null || true
    
    if [[ $silent == false ]]; then
        print_status "Clean uninstall completed"
    fi
}

# Fresh reinstall with automatic cleanup
fresh_reinstall() {
    print_header "🔄 Fresh WireGuard Reinstallation"
    
    echo -e "${YELLOW}This will:${NC}"
    echo "  • Stop WireGuard service"
    echo "  • Remove WireGuard packages"
    echo "  • Delete all configurations"
    echo "  • Clean firewall rules"
    echo "  • Perform fresh installation"
    echo ""
    echo -e "${RED}⚠️  All existing clients will be removed!${NC}"
    echo ""
    
    read -p "Continue with fresh reinstall? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        print_info "Reinstall cancelled"
        return 0
    fi
    
    # Detect system first for cleanup
    detect_system
    
    # Perform clean uninstall
    print_info "Step 1/2: Cleaning previous installation..."
    clean_uninstall true
    
    # Wait a moment for cleanup to complete
    sleep 2
    
    # Perform fresh installation
    print_info "Step 2/2: Installing WireGuard..."
    get_server_ip
    install_wireguard
    generate_server_keys
    create_server_config
    enable_ip_forwarding
    configure_firewall
    start_wireguard
    
    print_header "🎉 Fresh Installation Complete!"
    echo -e "${GREEN}WireGuard has been completely reinstalled!${NC}"
    echo ""
    echo "Server details:"
    echo "  Public Key: $SERVER_PUBLIC_KEY"
    echo "  Server IP: $SERVER_IP"
    echo "  Port: $WG_PORT"
    echo "  Network: $WG_NET.0/24"
    echo ""
    echo -e "${CYAN}📁 Configuration files are stored in: $WG_CONFIG_DIR/${NC}"
    echo ""
    print_status "Ready to add clients!"
}

# Generate client config
generate_client_config() {
    local client_name=$1
    local client_number=$2
    local client_ip="$WG_NET.$client_number"
    
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
    
    # Create client directory
    mkdir -p "$WG_CONFIG_DIR/clients"
    
    # Create client config
    cat > "$WG_CONFIG_DIR/clients/$client_name.conf" << EOF
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
    
    # Add to server config
    cat >> "$WG_CONFIG_DIR/$WG_INTERFACE.conf" << EOF

[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32
EOF
    
    print_status "Client '$client_name' created with IP: $client_ip"
    return 0
}

# Add client
add_client() {
    print_header "Add New Client"
    
    read -p "Enter client name: " client_name
    
    if [[ ! $client_name =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Invalid client name"
        return 1
    fi
    
    if [[ -f "$WG_CONFIG_DIR/clients/$client_name.conf" ]]; then
        print_error "Client already exists"
        return 1
    fi
    
    # Find next IP
    local next_ip=2
    while wg show "$WG_INTERFACE" 2>/dev/null | grep -q "$WG_NET.$next_ip"; do
        ((next_ip++))
    done
    
    if generate_client_config "$client_name" "$next_ip"; then
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")
        
        echo ""
        print_info "Configuration for $client_name:"
        echo -e "${CYAN}────────────────────────────────────────${NC}"
        cat "$WG_CONFIG_DIR/clients/$client_name.conf"
        echo -e "${CYAN}────────────────────────────────────────${NC}"
        
        if command -v qrencode &> /dev/null; then
            echo ""
            print_info "📱 QR Code for mobile devices:"
            qrencode -t ansiutf8 < "$WG_CONFIG_DIR/clients/$client_name.conf"
        fi
        
        echo ""
        print_info "📁 Configuration files saved to:"
        echo "   Main config: $WG_CONFIG_DIR/clients/$client_name.conf"
        echo "   Copy command: cp $WG_CONFIG_DIR/clients/$client_name.conf ~/Downloads/"
        echo ""
        print_status "Client added successfully!"
    else
        print_error "Failed to create client"
    fi
}

# List clients
list_clients() {
    print_header "WireGuard Clients"
    
    echo -e "${BLUE}📊 Active connections:${NC}"
    wg show "$WG_INTERFACE" 2>/dev/null || echo "   No active connections"
    
    echo ""
    echo -e "${BLUE}📁 Client configurations:${NC}"
    if [[ -d "$WG_CONFIG_DIR/clients" ]]; then
        local count=0
        for config in "$WG_CONFIG_DIR/clients"/*.conf; do
            if [[ -f $config ]]; then
                local name=$(basename "$config" .conf)
                local ip=$(grep "Address" "$config" | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
                local file_path="$config"
                printf "   %-15s %s\n" "$name:" "$ip"
                printf "   %-15s %s\n" "File:" "$file_path"
                echo ""
                ((count++))
            fi
        done
        
        if [[ $count -gt 0 ]]; then
            echo -e "${CYAN}💾 All client configs stored in: $WG_CONFIG_DIR/clients/${NC}"
            echo -e "${CYAN}📋 Copy all configs: cp $WG_CONFIG_DIR/clients/*.conf ~/Downloads/${NC}"
        else
            echo "   No clients found"
        fi
    else
        echo "   No clients found"
    fi
}

# Show client config
show_client_config() {
    print_header "Show Client Configuration"
    
    if [[ ! -d "$WG_CONFIG_DIR/clients" ]]; then
        print_warning "No clients found"
        return 1
    fi
    
    echo "Available clients:"
    ls -1 "$WG_CONFIG_DIR/clients"/*.conf 2>/dev/null | sed 's/.*\///' | sed 's/.conf$//' || {
        print_warning "No clients found"
        return 1
    }
    
    read -p "Enter client name: " client_name
    
    local config_file="$WG_CONFIG_DIR/clients/$client_name.conf"
    if [[ ! -f $config_file ]]; then
        print_error "Client not found"
        return 1
    fi
    
    echo ""
    print_info "📁 Configuration file location:"
    echo "   Path: $config_file"
    echo "   Copy to Downloads: cp $config_file ~/Downloads/"
    echo "   View file: cat $config_file"
    echo ""
    print_info "Configuration content:"
    echo -e "${CYAN}────────────────────────────────────────${NC}"
    cat "$config_file"
    echo -e "${CYAN}────────────────────────────────────────${NC}"
    
    if command -v qrencode &> /dev/null; then
        echo ""
        print_info "📱 QR Code for mobile devices:"
        qrencode -t ansiutf8 < "$config_file"
    fi
}

# Remove client
remove_client() {
    print_header "Remove Client"
    
    if [[ ! -d "$WG_CONFIG_DIR/clients" ]]; then
        print_warning "No clients found"
        return 1
    fi
    
    echo "Available clients:"
    ls -1 "$WG_CONFIG_DIR/clients"/*.conf 2>/dev/null | sed 's/.*\///' | sed 's/.conf$//' || {
        print_warning "No clients found"
        return 1
    }
    
    read -p "Enter client name to remove: " client_name
    
    local config_file="$WG_CONFIG_DIR/clients/$client_name.conf"
    if [[ ! -f $config_file ]]; then
        print_error "Client not found"
        return 1
    fi
    
    read -p "Are you sure? (y/N): " confirm
    if [[ $confirm != [yY] ]]; then
        print_info "Cancelled"
        return 0
    fi
    
    # Get client public key
    local client_private=$(grep "PrivateKey" "$config_file" | cut -d'=' -f2 | tr -d ' ')
    local client_public=$(echo "$client_private" | wg pubkey)
    
    # Remove from server config
    local temp_config=$(mktemp)
    awk -v pubkey="$client_public" '
    BEGIN { skip = 0 }
    /^\[Peer\]/ { 
        peer_section = ""
        in_peer = 1
        next
    }
    /^\[/ && in_peer {
        if (peer_section !~ pubkey) {
            print "[Peer]"
            print peer_section
        }
        in_peer = 0
        peer_section = ""
        print
        next
    }
    in_peer {
        peer_section = peer_section $0 "\n"
        next
    }
    !in_peer { print }
    END {
        if (in_peer && peer_section !~ pubkey) {
            print "[Peer]"
            print peer_section
        }
    }
    ' "$WG_CONFIG_DIR/$WG_INTERFACE.conf" > "$temp_config"
    
    mv "$temp_config" "$WG_CONFIG_DIR/$WG_INTERFACE.conf"
    rm -f "$config_file"
    
    wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")
    print_status "Client '$client_name' removed"
}

# Show status
show_status() {
    print_header "WireGuard Status"
    
    if systemctl is-active --quiet wg-quick@"$WG_INTERFACE"; then
        echo -e "${GREEN}Status: Running${NC}"
    else
        echo -e "${RED}Status: Stopped${NC}"
    fi
    
    echo ""
    echo "Server configuration:"
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        echo "Public Key: $(cat "$WG_CONFIG_DIR/server_public.key")"
    fi
    echo "Port: $WG_PORT"
    echo "Network: $WG_NET.0/24"
    
    echo ""
    echo "Interface status:"
    wg show "$WG_INTERFACE" 2>/dev/null || echo "Interface not active"
}

# Show all config file locations
show_config_locations() {
    print_header "📁 Configuration File Locations"
    
    echo -e "${BLUE}🔧 Server Configuration:${NC}"
    echo "   Main config: $WG_CONFIG_DIR/$WG_INTERFACE.conf"
    echo "   Private key: $WG_CONFIG_DIR/server_private.key"
    echo "   Public key:  $WG_CONFIG_DIR/server_public.key"
    
    echo ""
    echo -e "${BLUE}👥 Client Configurations:${NC}"
    if [[ -d "$WG_CONFIG_DIR/clients" ]]; then
        local count=0
        for config in "$WG_CONFIG_DIR/clients"/*.conf; do
            if [[ -f $config ]]; then
                local name=$(basename "$config" .conf)
                echo "   Client '$name': $config"
                ((count++))
            fi
        done
        
        if [[ $count -eq 0 ]]; then
            echo "   No client configurations found"
        else
            echo ""
            echo -e "${CYAN}📂 Client directory: $WG_CONFIG_DIR/clients/${NC}"
            echo -e "${CYAN}📋 Copy all clients: cp $WG_CONFIG_DIR/clients/*.conf ~/Downloads/${NC}"
            echo -e "${CYAN}🗂️  List all files: ls -la $WG_CONFIG_DIR/clients/${NC}"
        fi
    else
        echo "   No client configurations found"
    fi
    
    echo ""
    echo -e "${BLUE}💾 Useful Commands:${NC}"
    echo "   View server config: cat $WG_CONFIG_DIR/$WG_INTERFACE.conf"
    echo "   View client config: cat $WG_CONFIG_DIR/clients/CLIENT_NAME.conf"
    echo "   Copy to Downloads:  cp $WG_CONFIG_DIR/clients/CLIENT_NAME.conf ~/Downloads/"
    echo "   List all configs:   find $WG_CONFIG_DIR -name '*.conf'"
}

# Uninstall
uninstall() {
    print_header "Uninstall WireGuard"
    
    echo -e "${RED}This will remove WireGuard and all configurations!${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_info "Uninstall cancelled"
        return 0
    fi
    
    detect_system
    clean_uninstall false
    print_status "WireGuard completely uninstalled"
}

# Install complete server
install_server() {
    print_header "WireGuard Auto-Install v$SCRIPT_VERSION"
    
    if [[ -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
        print_warning "WireGuard already installed"
        read -p "Reinstall? (y/N): " reinstall
        if [[ $reinstall != [yY] ]]; then
            return 0
        fi
        systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
        rm -rf "$WG_CONFIG_DIR"
    fi
    
    detect_system
    get_server_ip
    install_wireguard
    generate_server_keys
    create_server_config
    enable_ip_forwarding
    configure_firewall
    start_wireguard
    
    print_header "Installation Complete!"
    echo -e "${GREEN}WireGuard server is ready!${NC}"
    echo ""
    echo "Server details:"
    echo "  Public Key: $SERVER_PUBLIC_KEY"
    echo "  Server IP: $SERVER_IP"
    echo "  Port: $WG_PORT"
    echo "  Network: $WG_NET.0/24"
    echo ""
    echo -e "${CYAN}📁 Configuration files are stored in: $WG_CONFIG_DIR/${NC}"
    echo ""
    print_status "Use option 3 to add your first client"
}

# Main menu
show_menu() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}                 ${WHITE}🛡️  WireGuard Management${NC}                     ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${WHITE}📋 Installation Options:${NC}"
    echo "   1. Install WireGuard Server (new install)"
    echo "   2. Fresh Reinstall (clean uninstall + install)"
    echo ""
    echo -e "${WHITE}📋 Client Management:${NC}"
    echo "   3. Add Client (with config file paths)"
    echo "   4. List Clients (shows file locations)"
    echo "   5. Show Client Config (with copy commands)"
    echo "   6. Remove Client"
    echo ""
    echo -e "${WHITE}📋 System Management:${NC}"
    echo "   7. Show Server Status"
    echo "   8. Show All Config File Locations"
    echo "   9. Uninstall WireGuard"
    echo "  10. Exit"
    echo ""
    echo -e "${CYAN}💡 All config files are stored in: $WG_CONFIG_DIR/clients/${NC}"
    echo ""
}

# Main function
main() {
    check_root
    
    while true; do
        show_menu
        read -p "Choose option [1-10]: " choice
        
        case $choice in
            1) install_server ;;
            2) fresh_reinstall ;;
            3) add_client ;;
            4) list_clients ;;
            5) show_client_config ;;
            6) remove_client ;;
            7) show_status ;;
            8) show_config_locations ;;
            9) uninstall ;;
            10) print_info "Goodbye!"; exit 0 ;;
            *) print_error "Invalid option. Please choose 1-10." ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
}

# Run main function
main "$@"
