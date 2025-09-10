#!/bin/bash

# Fix Existing WireGuard Installation
# This script adapts the management script to work with your current setup

WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT="51820"
SERVER_IP="103.49.63.38"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to extract and save server keys
extract_server_keys() {
    print_status "Extracting server configuration..."
    
    # Get server public key from wg show command
    SERVER_PUBLIC_KEY=$(wg show wg0 public-key 2>/dev/null)
    
    if [[ -n "$SERVER_PUBLIC_KEY" ]]; then
        echo "$SERVER_PUBLIC_KEY" > $WG_CONFIG_DIR/server_public.key
        print_status "Server public key saved: $SERVER_PUBLIC_KEY"
    else
        print_error "Could not extract server public key"
        return 1
    fi
    
    # Extract private key from config file
    if [[ -f "$WG_CONFIG_DIR/wg0.conf" ]]; then
        SERVER_PRIVATE_KEY=$(grep "PrivateKey" $WG_CONFIG_DIR/wg0.conf | cut -d'=' -f2 | tr -d ' ')
        if [[ -n "$SERVER_PRIVATE_KEY" ]]; then
            echo "$SERVER_PRIVATE_KEY" > $WG_CONFIG_DIR/server_private.key
            chmod 600 $WG_CONFIG_DIR/server_private.key
            print_status "Server private key extracted and saved"
        fi
    fi
}

# Function to detect current network configuration
detect_network_config() {
    print_status "Detecting current network configuration..."
    
    # Check what network is being used
    if grep -q "10.7.0" $WG_CONFIG_DIR/wg0.conf; then
        WG_NET="10.7.0"
        print_status "Detected network: 10.7.0.0/24"
    elif grep -q "10.66.66" $WG_CONFIG_DIR/wg0.conf; then
        WG_NET="10.66.66"
        print_status "Detected network: 10.66.66.0/24"
    else
        # Try to extract from config
        NETWORK=$(grep "Address" $WG_CONFIG_DIR/wg0.conf | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3)
        if [[ -n "$NETWORK" ]]; then
            WG_NET="$NETWORK"
            print_status "Detected network: ${WG_NET}.0/24"
        else
            WG_NET="10.7.0"
            print_warning "Could not detect network, using default: 10.7.0.0/24"
        fi
    fi
}

# Function to create client configuration
create_client_config() {
    local client_name=$1
    local client_ip=$2
    
    # Read server public key
    if [[ -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        SERVER_PUBLIC_KEY=$(cat $WG_CONFIG_DIR/server_public.key)
    else
        SERVER_PUBLIC_KEY=$(wg show wg0 public-key 2>/dev/null)
    fi
    
    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Create client config
    cat > $WG_CONFIG_DIR/$client_name.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $client_ip/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Add client to server config
    cat >> $WG_CONFIG_DIR/wg0.conf << EOF

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $client_ip/32
EOF
    
    print_status "Client configuration created: $WG_CONFIG_DIR/$client_name.conf"
    
    # Show config
    echo ""
    echo -e "${YELLOW}Client Configuration for $client_name:${NC}"
    echo "======================================"
    cat $WG_CONFIG_DIR/$client_name.conf
    echo "======================================"
    
    # Generate QR code if qrencode is available
    if command -v qrencode &> /dev/null; then
        echo ""
        echo -e "${YELLOW}QR Code for $client_name:${NC}"
        qrencode -t ansiutf8 < $WG_CONFIG_DIR/$client_name.conf
    fi
    
    # Restart WireGuard
    systemctl restart wg-quick@wg0
    
    return 0
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
    
    # Find next available IP based on current network
    NEXT_IP=2
    while wg show wg0 | grep -q "${WG_NET}.$NEXT_IP"; do
        ((NEXT_IP++))
        if [[ $NEXT_IP -gt 254 ]]; then
            print_error "No more IP addresses available"
            return 1
        fi
    done
    
    CLIENT_IP="${WG_NET}.$NEXT_IP"
    print_status "Assigning IP: $CLIENT_IP"
    
    create_client_config $CLIENT_NAME $CLIENT_IP
    
    echo ""
    print_status "Client $CLIENT_NAME added successfully!"
    print_status "Client IP: $CLIENT_IP"
}

# Function to list clients
list_clients() {
    echo ""
    echo -e "${BLUE}=== Current Clients ===${NC}"
    
    echo "Connected clients (from wg show):"
    wg show
    
    echo ""
    echo "Client configuration files:"
    ls -1 $WG_CONFIG_DIR/*.conf 2>/dev/null | grep -v wg0.conf | sed 's/.*\///' | sed 's/.conf$//' || echo "No client configurations found"
}

# Function to show client config
show_client_config() {
    echo ""
    echo -e "${BLUE}=== Show Client Configuration ===${NC}"
    
    # List available clients
    echo "Available clients:"
    ls -1 $WG_CONFIG_DIR/*.conf 2>/dev/null | grep -v wg0.conf | sed 's/.*\///' | sed 's/.conf$//' || {
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
    
    if command -v qrencode &> /dev/null; then
        echo ""
        echo -e "${YELLOW}QR Code for $CLIENT_NAME:${NC}"
        qrencode -t ansiutf8 < $WG_CONFIG_DIR/$CLIENT_NAME.conf
    fi
}

# Function to show current status
show_status() {
    echo ""
    echo -e "${BLUE}=== WireGuard Server Status ===${NC}"
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_status "WireGuard is running"
    else
        print_warning "WireGuard is not running"
    fi
    
    echo ""
    echo "Interface status:"
    wg show
    
    echo ""
    echo "Server configuration:"
    SERVER_PUBLIC_KEY=$(wg show wg0 public-key 2>/dev/null)
    echo -e "${YELLOW}Public Key:${NC} $SERVER_PUBLIC_KEY"
    echo -e "${YELLOW}Listen Port:${NC} $WG_PORT"
    echo -e "${YELLOW}Server IP:${NC} $SERVER_IP"
    echo -e "${YELLOW}Network:${NC} ${WG_NET}.0/24"
}

# Main menu
show_menu() {
    echo ""
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  WireGuard Management (Fixed)  ${NC}"
    echo -e "${BLUE}================================${NC}"
    echo "1. Add Client"
    echo "2. List Clients" 
    echo "3. Show Client Config"
    echo "4. Show Server Status"
    echo "5. Fix Server Keys"
    echo "6. Exit"
    echo ""
}

# Main execution
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
    
    # Initial setup
    detect_network_config
    
    # Create server key files if they don't exist
    if [[ ! -f "$WG_CONFIG_DIR/server_public.key" ]]; then
        extract_server_keys
    fi
    
    while true; do
        show_menu
        read -p "Choose an option [1-6]: " choice
        
        case $choice in
            1)
                add_client
                ;;
            2)
                list_clients
                ;;
            3)
                show_client_config
                ;;
            4)
                show_status
                ;;
            5)
                extract_server_keys
                ;;
            6)
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
}

main "$@"
