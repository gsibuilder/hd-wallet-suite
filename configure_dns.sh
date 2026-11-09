#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# DNS & Local Resolver Configuration for hd-wallet-suite.io
# ═══════════════════════════════════════════════════════════════════════════
set -e

DOMAIN="hd-wallet-suite.io"
GH_PAGES_IPS=("185.199.108.153" "185.199.109.153" "185.199.110.153" "185.199.111.153")

echo "══════════════════════════════════════════════════════════════════"
echo "  DNS Configuration Utility for: ${DOMAIN}"
echo "══════════════════════════════════════════════════════════════════"

# 1. Configure Cloudflare Public DNS automatic API if CF_API_TOKEN & CF_ZONE_ID are provided
if [[ -n "${CF_API_TOKEN:-}" && -n "${CF_ZONE_ID:-}" ]]; then
  echo "[*] Configuring public Cloudflare DNS records for ${DOMAIN}..."
  for IP in "${GH_PAGES_IPS[@]}"; do
    curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"${DOMAIN}\",\"content\":\"${IP}\",\"ttl\":3600,\"proxied\":false}" >/dev/null
  done
  curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/dns_records" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"CNAME\",\"name\":\"www.${DOMAIN}\",\"content\":\"gsibuilder.github.io\",\"ttl\":3600,\"proxied\":false}" >/dev/null
  echo "[+] Public Cloudflare DNS records created!"
fi

# 2. Configure Local /etc/hosts resolution on this machine
if ! grep -q "${DOMAIN}" /etc/hosts 2>/dev/null; then
  echo "[*] Adding ${DOMAIN} to /etc/hosts (requires sudo if not root)..."
  if [ "$EUID" -eq 0 ]; then
    echo "127.0.0.1 ${DOMAIN} www.${DOMAIN}" >> /etc/hosts
  else
    echo "127.0.0.1 ${DOMAIN} www.${DOMAIN}" | sudo tee -a /etc/hosts >/dev/null
  fi
  echo "[+] Added 127.0.0.1 -> ${DOMAIN} in /etc/hosts"
else
  echo "[✓] ${DOMAIN} is already configured in /etc/hosts"
fi

echo ""
echo "✅ Local DNS resolution active: http://${DOMAIN}:8080"
