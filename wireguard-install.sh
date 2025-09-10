#!/bin/bash

# WireGuard Auto Install Script for VPS
# Supports Ubuntu, Debian, CentOS, and RHEL
# Run with: curl -O https://raw.githubusercontent.com/SatkiExE808/wireguard-auto-install/main/wireguard-install.sh && bash wireguard-install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NET="10.66.66"
SERVER_IP=""
CLIENT_DNS="1.1.1.1, 8.8.8.8"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect operating system"
        exit 1
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to get server public IP
get_server_ip() {
    SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    if [[ -z "$SERVER_IP" ]]; then
        print_warning "Could not automatically detect public IP"
        read -p "Please enter your server's public IP: " SERVER_IP
    fi
    print_status "Server IP: $SERVER_IP"
}

# Function to install WireGuard
install_wireguard() {
    print_status "Installing WireGuard..."
    
    case $OS in
        ubuntu|debian)
            apt update
            apt install -y wireguard wireguard-tools qrencode iptables-persistent
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y epel-release
                dnf install -y wireguard-tools qrencode iptables-services
            else
                yum install -y epel-release
                yum install -y wireguard-tools qrencode iptables-services
            fi
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    print_status "WireGuard installed successfully"
}

# Function to generate server keys
generate_server_keys() {
    print_status "Generating server keys..."
    
    cd $WG_CONFIG_DIR
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    chmod 600 server_private.key
    
    SERVER_PRIVATE_KEY=$(cat server_private.key)
    SERVER_PUBLIC_KEY=$(cat server_public.key)
    
    print_status "Server keys generated"
}

# Function to create server configuration
create_server_config() {
    print_status "Creating server configuration..."
    
    cat > $WG_CONFIG_DIR/$WG_INTERFACE.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $WG_NET.1/24
ListenPort = $WG_PORT
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o \$(ip route | awk '/default/ { print \$5 }') -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -D FORWARD -o $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o \$(ip route | awk '/default/ { print \$5 }') -j MASQUERADE

EOF
    
    print_status "Server configuration created"
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    print_status "Enabling IP forwarding..."
    
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
    sysctl -p /etc/sysctl.d/99-wireguard.conf
    
    print_status "IP forwarding enabled"
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Allow WireGuard port
    if command -v ufw &> /dev/null; then
        ufw allow $WG_PORT/udp
        ufw reload
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$WG_PORT/udp
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
    
    print_status "Firewall configured"
}

# Function to start and enable WireGuard service
start_wireguard() {
    print_status "Starting WireGuard service..."
    
    systemctl enable wg-quick@$WG_INTERFACE
    systemctl start wg-quick@$WG_INTERFACE
    
    print_status "WireGuard service started and enabled"
}

# Function to generate client configuration
generate_client_config() {
    local client_name=$1
    local client_number=$2
    
    print_status "Generating configuration for client: $client_name"
    
    # Read server public key from file
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        SERVER_PUBLIC_KEY=$(cat $WG_CONFIG_DIR/server_public.key)
    else
        print_error "Server public key not found. Please reinstall the server."
        return 1
    fi
    
    # Get server IP if not set
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    fi
    
    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Create client config
    cat > $WG_CONFIG_DIR/$client_name.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $WG_NET.$client_number/32
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Add client to server config
    cat >> $WG_CONFIG_DIR/$WG_INTERFACE.conf << EOF

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $WG_NET.$client_number/32
EOF
    
    # Generate QR code
    qrencode -t ansiutf8 < $WG_CONFIG_DIR/$client_name.conf
    echo ""
    print_status "QR code generated above for $client_name"
    print_status "Client configuration saved to: $WG_CONFIG_DIR/$client_name.conf"
    
    # Show the config content for verification
    echo ""
    echo -e "${YELLOW}Client Configuration:${NC}"
    echo "====================="
    cat $WG_CONFIG_DIR/$client_name.conf
    echo "====================="
    
    # Restart WireGuard to apply new peer
    systemctl restart wg-quick@$WG_INTERFACE
}

# Function to add new client
add_client() {
    echo ""
    echo -e "${BLUE}=== Add New Client ===${NC}"
    read -p "Enter client name: " CLIENT_NAME
    
    # Check if client already exists
    if [[ -f "$WG_CONFIG_DIR/$CLIENT_NAME.conf" ]]; then
        print_error "Client $CLIENT_NAME already exists"
        return 1
    fi
    
    # Find next available IP
    NEXT_IP=2
    while grep -q "$WG_NET.$NEXT_IP" $WG_CONFIG_DIR/$WG_INTERFACE.conf; do
        ((NEXT_IP++))
    done
    
    generate_client_config $CLIENT_NAME $NEXT_IP
    
    echo ""
    print_status "Client $CLIENT_NAME added successfully!"
    print_status "Client IP: $WG_NET.$NEXT_IP"
    echo ""
    echo -e "${YELLOW}Configuration file location:${NC} $WG_CONFIG_DIR/$CLIENT_NAME.conf"
    echo -e "${YELLOW}Import this configuration to your WireGuard client${NC}"
}

# Function to list clients
list_clients() {
    echo ""
    echo -e "${BLUE}=== Current Clients ===${NC}"
    
    if [[ ! -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
        print_warning "Server not configured yet"
        return 1
    fi
    
    echo "Connected clients:"
    wg show
    
    echo ""
    echo "Available client configurations:"
    ls -1 $WG_CONFIG_DIR/*.conf 2>/dev/null | grep -v $WG_INTERFACE.conf | sed 's/.*\///' | sed 's/.conf$//' || echo "No client configurations found"
}

# Function to show client config
show_client_config() {
    echo ""
    echo -e "${BLUE}=== Show Client Configuration ===${NC}"
    
    # List available clients
    echo "Available clients:"
    ls -1 $WG_CONFIG_DIR/*.conf 2>/dev/null | grep -v $WG_INTERFACE.conf | sed 's/.*\///' | sed 's/.conf$//' || {
        print_warning "No clients found"
        return 1
    }
    
    echo ""
    read -p "Enter client name to show: " CLIENT_NAME
    
    if [[ ! -f "$WG_CONFIG_DIR/$CLIENT_NAME.conf" ]]; then
        print_error "Client $CLIENT_NAME not found"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}Configuration for $CLIENT_NAME:${NC}"
    echo "================================="
    cat $WG_CONFIG_DIR/$CLIENT_NAME.conf
    echo "================================="
    
    echo ""
    echo -e "${YELLOW}QR Code for $CLIENT_NAME:${NC}"
    qrencode -t ansiutf8 < $WG_CONFIG_DIR/$CLIENT_NAME.conf
}

# Function to remove client
remove_client() {
    echo ""
    echo -e "${BLUE}=== Remove Client ===${NC}"
    
    # List available clients
    echo "Available clients:"
    ls -1 $WG_CONFIG_DIR/*.conf 2>/dev/null | grep -v $WG_INTERFACE.conf | sed 's/.*\///' | sed 's/.conf$//' || {
        print_warning "No clients found"
        return 1
    }
    
    echo ""
    read -p "Enter client name to remove: " CLIENT_NAME
    
    if [[ ! -f "$WG_CONFIG_DIR/$CLIENT_NAME.conf" ]]; then
        print_error "Client $CLIENT_NAME not found"
        return 1
    fi
    
    # Get client public key
    CLIENT_PUBLIC_KEY=$(grep -A 10 "\[Interface\]" $WG_CONFIG_DIR/$CLIENT_NAME.conf | grep "PrivateKey" | cut -d' ' -f3 | wg pubkey)
    
    # Remove client config file
    rm -f $WG_CONFIG_DIR/$CLIENT_NAME.conf
    
    # Remove client from server config
    # This is a simple approach - in production you might want a more sophisticated method
    cp $WG_CONFIG_DIR/$WG_INTERFACE.conf $WG_CONFIG_DIR/$WG_INTERFACE.conf.backup
    
    # Remove the peer section for this client
    awk -v pubkey="$CLIENT_PUBLIC_KEY" '
    /^\[Peer\]/ { peer_section = 1; peer_content = $0 "\n"; next }
    peer_section && /^$/ { 
        if (peer_content !~ pubkey) print peer_content
        peer_section = 0; peer_content = ""
        next 
    }
    peer_section { peer_content = peer_content $0 "\n"; next }
    !peer_section { print }
    END { if (peer_section && peer_content !~ pubkey) printf "%s", peer_content }
    ' $WG_CONFIG_DIR/$WG_INTERFACE.conf.backup > $WG_CONFIG_DIR/$WG_INTERFACE.conf
    
    # Restart WireGuard
    systemctl restart wg-quick@$WG_INTERFACE
    
    print_status "Client $CLIENT_NAME removed successfully"
}

# Function to show server status
show_status() {
    echo ""
    echo -e "${BLUE}=== WireGuard Server Status ===${NC}"
    
    if systemctl is-active --quiet wg-quick@$WG_INTERFACE; then
        print_status "WireGuard is running"
    else
        print_warning "WireGuard is not running"
    fi
    
    echo ""
    echo "Interface status:"
    wg show
    
    echo ""
    echo "Server configuration:"
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        SERVER_PUBLIC_KEY=$(cat $WG_CONFIG_DIR/server_public.key)
        echo -e "${YELLOW}Public Key:${NC} $SERVER_PUBLIC_KEY"
    else
        echo -e "${RED}Server public key not found${NC}"
    fi
    echo -e "${YELLOW}Listen Port:${NC} $WG_PORT"
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    fi
    echo -e "${YELLOW}Server IP:${NC} $SERVER_IP"
}

# Function to fix existing client configs
fix_client_configs() {
    echo ""
    echo -e "${BLUE}=== Fix Client Configurations ===${NC}"
    
    if [[ ! -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        print_error "Server public key not found. Cannot fix client configs."
        return 1
    fi
    
    SERVER_PUBLIC_KEY=$(cat $WG_CONFIG_DIR/server_public.key)
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP=$(curl -s ipv4.icanhazip.com 2>/dev/null || curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null)
    fi
    
    print_status "Fixing client configurations..."
    
    # Find and fix all client configs missing public key
    for config in $WG_CONFIG_DIR/*.conf; do
        if [[ "$config" != "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]] && [[ -f "$config" ]]; then
            if ! grep -q "PublicKey" "$config" || ! grep -q "Endpoint" "$config"; then
                echo "Fixing $(basename $config)..."
                
                # Get the current content
                PRIVATE_KEY=$(grep "PrivateKey" "$config" | cut -d" " -f3)
                ADDRESS=$(grep "Address" "$config" | cut -d" " -f3)
                DNS=$(grep "DNS" "$config" | cut -d" " -f3- || echo "$CLIENT_DNS")
                
                # Recreate the config with all fields
                cat > "$config" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
DNS = $DNS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
                
                print_status "Fixed: $(basename $config)"
            fi
        fi
    done
    
    print_status "Client configurations fixed!"
}

# Function to uninstall WireGuard
uninstall_wireguard() {
    echo ""
    echo -e "${RED}=== Uninstall WireGuard ===${NC}"
    echo -e "${YELLOW}This will remove WireGuard and all configurations!${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ $confirm != [yY] ]]; then
        print_status "Uninstall cancelled"
        return 0
    fi
    
    # Stop and disable service
    systemctl stop wg-quick@$WG_INTERFACE 2>/dev/null || true
    systemctl disable wg-quick@$WG_INTERFACE 2>/dev/null || true
    
    # Remove configurations
    rm -rf $WG_CONFIG_DIR
    
    # Remove sysctl config
    rm -f /etc/sysctl.d/99-wireguard.conf
    
    print_status "WireGuard uninstalled successfully"
}

# Main menu function
show_menu() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    WireGuard Management Menu   ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo "1. Install WireGuard Server"
    echo "2. Add Client"
    echo "3. List Clients"
    echo "4. Show Client Config"
    echo "5. Remove Client"
    echo "6. Show Server Status"
    echo "7. Fix Client Configs"
    echo "8. Uninstall WireGuard"
    echo "9. Exit"
    echo ""
}

# Main installation function
install_server() {
    print_status "Starting WireGuard server installation..."
    
    detect_os
    get_server_ip
    install_wireguard
    
    # Create config directory if it doesn't exist
    mkdir -p $WG_CONFIG_DIR
    
    generate_server_keys
    create_server_config
    enable_ip_forwarding
    configure_firewall
    start_wireguard
    
    echo ""
    echo -e "${GREEN}==================================${NC}"
    echo -e "${GREEN}  WireGuard Server Installed!     ${NC}"
    echo -e "${GREEN}==================================${NC}"
    echo -e "${YELLOW}Server Public Key:${NC} $SERVER_PUBLIC_KEY"
    echo -e "${YELLOW}Server IP:${NC} $SERVER_IP"
    echo -e "${YELLOW}Listen Port:${NC} $WG_PORT"
    echo ""
    print_status "You can now add clients using option 2 in the menu"
}

# Main script execution
main() {
    check_root
    
    # Check if WireGuard is already installed
    if [[ -f "$WG_CONFIG_DIR/$WG_INTERFACE.conf" ]]; then
        # WireGuard is already configured, show menu
        while true; do
            show_menu
            read -p "Choose an option [1-9]: " choice
            
            case $choice in
                1)
                    print_warning "WireGuard is already installed"
                    show_status
                    ;;
                2)
                    add_client
                    ;;
                3)
                    list_clients
                    ;;
                4)
                    show_client_config
                    ;;
                5)
                    remove_client
                    ;;
                6)
                    show_status
                    ;;
                7)
                    fix_client_configs
                    ;;
                8)
                    uninstall_wireguard
                    break
                    ;;
                9)
                    print_status "Goodbye!"
                    break
                    ;;
                *)
                    print_error "Invalid option"
                    ;;
            esac
            
            echo ""
            read -p "Press Enter to continue..."
        done
    else
        # First time installation
        echo -e "${BLUE}WireGuard Auto-Install Script${NC}"
        echo ""
        read -p "Install WireGuard server? (y/N): " install_confirm
        
        if [[ $install_confirm == [yY] ]]; then
            install_server
            
            # After installation, show menu
            while true; do
                show_menu
                read -p "Choose an option [1-9]: " choice
                
                case $choice in
                    1)
                        print_warning "WireGuard is already installed"
                        ;;
                    2)
                        add_client
                        ;;
                    3)
                        list_clients
                        ;;
                    4)
                        show_client_config
                        ;;
                    5)
                        remove_client
                        ;;
                    6)
                        show_status
                        ;;
                    7)
                        fix_client_configs
                        ;;
                    8)
                        uninstall_wireguard
                        break
                        ;;
                    9)
                        print_status "Goodbye!"
                        break
                        ;;
                    *)
                        print_error "Invalid option"
                        ;;
                esac
                
                echo ""
                read -p "Press Enter to continue..."
            done
        else
            print_status "Installation cancelled"
        fi
    fi
}

# Run main function
main "$@"
