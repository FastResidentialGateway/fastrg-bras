#!/bin/bash
# setup.sh — prepare hugepages, bind NICs, build and run dpdk-bras
#
# Prerequisites:
#   apt install dpdk dpdk-dev libnuma-dev pkg-config gcc make
#
# Adjust PCI addresses to match your environment:
#   lshw -class network -businfo   or   dpdk-devbind.py --status

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────
WAN_PCI="0000:01:00.0"   # NIC facing fastrg-node clients
LAN_PCI="0000:01:00.1"   # NIC facing upstream server

HUGEPAGES=512            # 2 MB pages = 1 GB
IP_POOL="10.64.0.0"      # PPP address pool base

# ── 1. Hugepages ───────────────────────────────────────────────────────
echo "[*] Configuring hugepages..."
echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /dev/hugepages
mountpoint -q /dev/hugepages || mount -t hugetlbfs none /dev/hugepages

# ── 2. Load vfio-pci (preferred over igb_uio) ─────────────────────────
echo "[*] Loading vfio-pci..."
modprobe vfio-pci

# ── 3. Bind NICs ───────────────────────────────────────────────────────
echo "[*] Binding NICs to vfio-pci..."
dpdk-devbind.py --bind=vfio-pci "$WAN_PCI" "$LAN_PCI"
dpdk-devbind.py --status

# ── 4. Build ───────────────────────────────────────────────────────────
echo "[*] Building dpdk-bras..."
cd "$(dirname "$0")/.."
make

# ── 5. Run ─────────────────────────────────────────────────────────────
echo "[*] Starting dpdk-bras..."
sudo ./dpdk-bras \
  -l 0-2 \
  -n 4   \
  --proc-type=primary \
  -- \
  --ip-pool "$IP_POOL"
