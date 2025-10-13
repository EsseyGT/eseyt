# Firewall Rule Manager — Demo project

> ⚠️ Run only in a safe environment: a local VM or Docker container with `--cap-add=NET_ADMIN`.  
> Do **not** use this on a production system.

## 🚀 Quick Start

```bash
sudo apt update && sudo apt install -y iptables nodejs npm
git clone <your_repo_url>
cd firewall-rule-manager
npm install
sudo FWM_USER=admin FWM_PASS=password node server.js
