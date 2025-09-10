```bash
#!/bin/bash
# Interactive WireGuard and SSH management script for VPS
# Run as root: sudo bash wireguard_menu.sh

# Exit on error
set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (use sudo)."
  exit 1
fi

# Default configuration values
WG_CONF="/etc/wireguard/wg0.conf"
INTERFACE=$(ip link | grep -o '^[0-9]: \(eth[0-9]\|ens[0-9]\|enp[0-9]s[0-9]\)' | awk '{print $2}' | head -n 1)
[ -z "$INTERFACE" ] && INTERFACE="eth0"
SERVER_IP="10.0.0.1/24"
CLIENT_IP_BASE="10.0.0"
PORT="51820"
PUBLIC_IP=$(curl -s ifconfig.me || echo "<YOUR_VPS_PUBLIC_IP>")

# Function to install WireGuard and dependencies
install_wireguard() {
  echo "Installing WireGuard and dependencies..."
  apt update && apt install -y wireguard openssh-server ufw
  echo "Enabling SSH..."
  systemctl enable sshd
  systemctl restart sshd
  echo "Installation complete."
}

# Function to enable IP forwarding
enable_ip_forwarding() {
  echo "Enabling IP forwarding..."
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  sysctl -p
}

# Function to configure firewall
configure_firewall() {
  echo "Configuring firewall..."
  ufw allow $PORT/udp
  ufw allow 22/tcp
  ufw --force enable
  echo "Firewall configured: Allowed UDP $PORT and TCP 22."
}

# Function to generate server configuration
generate_server_config() {
  echo "Generating server keys..."
  mkdir -p /etc/wireguard
  wg genkey | tee /etc/wireguard/server_privatekey | wg pubkey > /etc/wireguard/server_publickey
  SERVER_PRIVATE_KEY=$(cat /etc/wireguard/server_privatekey)
  
  echo "Creating WireGuard configuration ($WG_CONF)..."
  cat > $WG_CONF << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_IP
ListenPort = $PORT
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $INTERFACE -j MASQUERADE
PostUp = sysctl -w net.ipv4.ip_forward=1
PostDown = sysctl -w net.ipv4.ip_forward=0

# Peers will be added here
EOF
  chmod 600 $WG_CONF
  echo "Server configuration created."
}

# Function to add a new client peer
add_client_peer() {
  read -p "Enter client name (e.g., client1): " CLIENT_NAME
  CLIENT_IP="$CLIENT_IP_BASE.$(( $(grep -c AllowedIPs $WG_CONF) + 2 ))/32"
  
  echo "Generating client keys for $CLIENT_NAME..."
  wg genkey | tee /etc/wireguard/${CLIENT_NAME}_privatekey | wg pubkey > /etc/wireguard/${CLIENT_NAME}_publickey
  CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/${CLIENT_NAME}_privatekey)
  CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/${CLIENT_NAME}_publickey)
  
  echo "Adding client to $WG_CONF..."
  cat >> $WG_CONF << EOF
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
PersistentKeepalive = 25
EOF
  
  echo "Generating client configuration..."
  SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_publickey)
  CLIENT_CONF="/etc/wireguard/${CLIENT_NAME}.conf"
  cat > $CLIENT_CONF << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $PUBLIC_IP:$PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
  
  echo -e "\n=== Client Configuration for $CLIENT_NAME ==="
  echo "Save the following to '${CLIENT_NAME}.conf' on the client device:"
  cat $CLIENT_CONF
  echo -e "\nCopy this configuration to your client and run: wg-quick up ${CLIENT_NAME}.conf"
}

# Function to start WireGuard
start_wireguard() {
  echo "Starting WireGuard..."
  wg-quick up wg0
  systemctl enable wg-quick@wg0
  echo "WireGuard started."
}

# Function to stop WireGuard
stop_wireguard() {
  echo "Stopping WireGuard..."
  wg-quick down wg0 2>/dev/null || true
  systemctl disable wg-quick@wg0 2>/dev/null || true
  echo "WireGuard stopped."
}

# Function to check WireGuard status
check_status() {
  echo "WireGuard status:"
  wg show
}

# Function to restrict SSH to VPN
restrict_ssh_to_vpn() {
  echo "Restricting SSH to VPN IP ($SERVER_IP)..."
  sed -i '/^ListenAddress/d' /etc/ssh/sshd_config
  echo "ListenAddress $SERVER_IP" >> /etc/ssh/sshd_config
  systemctl restart sshd
  ufw delete allow 22/tcp 2>/dev/null || true
  echo "SSH restricted to VPN. Connect via: ssh user@$SERVER_IP"
}

# Main menu
while true; do
  echo -e "\n=== WireGuard and SSH Management Menu ==="
  echo "1. Install WireGuard and dependencies"
  echo "2. Enable IP forwarding"
  echo "3. Configure firewall"
  echo "4. Generate server configuration"
  echo "5. Add client peer"
  echo "6. Start WireGuard"
  echo "7. Stop WireGuard"
  echo "8. Check WireGuard status"
  echo "9. Restrict SSH to VPN only"
  echo "10. Exit"
  read -p "Select an option [1-10]: " OPTION
  
  case $OPTION in
    1) install_wireguard ;;
    2) enable_ip_forwarding ;;
    3) configure_firewall ;;
    4) generate_server_config ;;
    5) add_client_peer ;;
    6) start_wireguard ;;
    7) stop_wireguard ;;
    8) check_status ;;
    9) restrict_ssh_to_vpn ;;
    10) echo "Exiting..."; exit 0 ;;
    *) echo "Invalid option. Please select 1-10." ;;
  esac
done
```
