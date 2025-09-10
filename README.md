```markdown
# 🛡️ WireGuard Auto-Install Script

**One-command WireGuard VPN server deployment with advanced client management**

## ✨ Features

- 🚀 **One-Command Installation** - Deploy WireGuard server instantly
- 🐧 **Multi-OS Support** - Ubuntu, Debian, CentOS, RHEL, Fedora
- 📱 **QR Code Generation** - Easy mobile device setup
- 🔧 **Interactive Management** - Add/remove clients with ease
- 🌐 **Router Compatible** - Generate configs for various router brands
- 🔒 **Automatic Security** - Firewall and network configuration
- 📊 **Status Monitoring** - Real-time connection monitoring

## 🚀 Quick Start

```bash
curl -O https://raw.githubusercontent.com/SatkiExE808/wireguard-auto-install/main/wireguard-install.sh && sudo bash wireguard-install.sh
```

## 📋 Requirements

| OS | Version | Status |
|---|---|---|
| Ubuntu | 18.04+ | ✅ Tested |
| Debian | 10+ | ✅ Tested |
| CentOS | 7+ | ✅ Tested |
| RHEL | 7+ | ✅ Supported |
| Fedora | 34+ | ✅ Supported |

## 🎯 Usage Examples

### Basic Installation
```bash
# Download and run
wget https://raw.githubusercontent.com/SatkiExE808/wireguard-auto-install/main/wireguard-install.sh
chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```

### Add Multiple Clients
```bash
# Run the management script
sudo ./wireguard-install.sh
# Choose option 2: Add Client
# Repeat for each client
```

## 📱 Client Setup

<div align="center">

| Platform | Installation |
|----------|-------------|
| **Android** | [Google Play Store](https://play.google.com/store/apps/details?id=com.wireguard.android) |
| **iOS** | [App Store](https://apps.apple.com/us/app/wireguard/id1441195209) |
| **Windows** | [Official Website](https://www.wireguard.com/install/) |
| **macOS** | [App Store](https://apps.apple.com/us/app/wireguard/id1451685025) |
| **Linux** | `sudo apt install wireguard` |

</div>

## 🔧 Configuration

The script automatically configures:

```yaml
Network: 10.66.66.0/24
Port: 51820/UDP
DNS: 1.1.1.1, 8.8.8.8
Encryption: ChaCha20Poly1305
Key Exchange: Curve25519
```

## 🛠️ Advanced Features

### Router Compatibility
- ✅ Asus (Merlin/Stock firmware)
- ✅ Netgear
- ✅ TP-Link
- ✅ Linksys
- ✅ OpenWrt/DD-WRT
- ✅ MikroTik RouterOS

### Security Features
- 🔐 Automatic key generation
- 🛡️ Firewall integration
- 🚪 NAT configuration
- 📡 IP forwarding setup
- 🔄 Perfect forward secrecy

## 📊 Performance

| Metric | Value |
|--------|--------|
| **Setup Time** | < 2 minutes |
| **Memory Usage** | < 50MB |
| **CPU Overhead** | < 1% |
| **Throughput** | Near wire-speed |

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### 🐛 Bug Reports
Found a bug? [Open an issue](https://github.com/SatkiExE808/wireguard-auto-install/issues/new?template=bug_report.md)

### 💡 Feature Requests
Have an idea? [Request a feature](https://github.com/SatkiExE808/wireguard-auto-install/issues/new?template=feature_request.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=SatkiExE808/wireguard-auto-install&type=Date)](https://star-history.com/#SatkiExE808/wireguard-auto-install&Date)

## 💖 Support

If this project helped you, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs
- 💡 Suggesting new features
- 📢 Sharing with others

---

<div align="center">

**Made with ❤️ by [SatkiExE808](https://github.com/SatkiExE808)**

</div>
```

#### 📋 CONTRIBUTING.md
```markdown
# Contributing to WireGuard Auto-Install

Thank you for your interest in contributing! 🎉

## 🚀 Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 🐛 Bug Reports

When filing a bug report, please include:
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

## 💡 Feature Requests

For feature requests, please provide:
- Use case description
- Proposed implementation
- Benefits to other users
```

#### ⚖️ LICENSE
```
MIT License

Copyright (c) 2024 SatkiExE808

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
