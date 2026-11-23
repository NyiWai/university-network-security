# University Network Security Monitoring and Access Control System

A cross-platform Python/Streamlit academic prototype for authorized network discovery, device inventory, application-level allow-list management, packet metadata capture, Suricata alert import, and hybrid rule/Isolation Forest demonstrations.

## Current capabilities

- OS and network-interface inventory (Linux/Windows/macOS detection).
- Neighbor-table discovery (`ip neigh` on Linux, `arp -a` on Windows).
- Bounded active ARP discovery of explicitly selected private IPv4 subnets (Scapy; up to 256 addresses).
- SQLite device inventory and access-policy history.
- Application allow-list with MAC normalization, validation, add/update/revoke, and authorization lookup.
- Opt-in bounded packet metadata capture (no payload storage).
- Suricata EVE JSON alert import.
- Synthetic scenario generation, rule-based detection, and Isolation Forest baseline.
- Alert status workflow and CSV export.
- nftables ruleset preview and syntax validation adapter; **does not apply firewall rules**.

## Important limitations

This is an academic prototype, not a production NAC/IDS. The allow-list is not enforced at the network layer in this release. MAC addresses can be spoofed and are not authentication. Hotspot creation, DHCP server management, automatic firewall blocking, and Windows firewall rule deployment require additional OS-specific configuration and administrator review. The Isolation Forest baseline is trained on synthetic normal data; do not report its output as real-world detection accuracy. Suricata import requires Suricata to be separately installed and its EVE file readable.

Only monitor or scan networks/devices you own or have explicit permission to test. Do not run packet capture against a university or third-party network without authorization.

## Setup — Kali Linux

```bash
cd university-network-security
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open `http://localhost:8501`.

For Scapy active discovery or packet metadata capture, Linux may require elevated packet-capture privileges. Prefer configuring narrowly scoped capture permissions rather than running the whole Streamlit web server as root. If you temporarily test with sudo, bind the dashboard to localhost and stop it immediately after testing.

## Setup — Windows 10/11

Install Python 3.11+, open PowerShell in the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Npcap may be required for Scapy packet capture/ARP discovery on Windows. Run only with the privileges needed for the authorized test lab. Windows Firewall integration in this build is inspection-only; no firewall rules are created or changed.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Database

SQLite is created automatically at `data/network_security.db`. The database is ignored by Git. Back it up before deleting it.

## Suggested authorized demo

1. Open the dashboard and inspect interfaces.
2. Discover devices from the local neighbor table.
3. If authorized, scan a small private test subnet (maximum 256 addresses).
4. Add a test device MAC to the application allow-list and verify/revoke it.
5. Generate the brute-force, unusual-transfer, and destination-sweep simulations.
6. Review events, change status, and export CSV.
7. Optionally import Suricata EVE alerts from an authorized lab sensor.

## Architecture

`app.py` (Streamlit UI) → shared Python modules → platform-specific adapters → SQLite. Linux and Windows use separate OS integration modules while discovery/event processing and AI logic are shared.

## IP-based Bandwidth Management (safe first milestone)

The dashboard now includes a **Bandwidth Management** tab. This milestone implements:

- Private IPv4 validation (public, loopback, link-local and multicast targets are rejected).
- A lab-only bandwidth ceiling of 1–10 Mbps.
- Upload/download interface fields for a gateway topology.
- SQLite policy records with `PENDING`, `APPROVED`, `PREVIEWED`, and `ROLLED_BACK` lifecycle states.
- Explicit approval and cancellation/rollback of the application policy record.
- Linux `tc` and Windows QoS command previews.

**No operating-system traffic-shaping command is executed in this milestone.** There is intentionally no Apply button. This avoids changing the host's network configuration before the actual gateway topology, existing qdiscs, administrator access, and rollback plan are known.

### Important platform distinction

- **Linux gateway:** the preview illustrates upload shaping on the WAN egress interface (matching the target IP as source) and download shaping on the LAN egress interface (matching the target IP as destination). These are separate interfaces in a typical routed lab. Existing qdiscs must be inspected and preserved before implementing enforcement.
- **Windows host:** the preview is only a host-originated QoS policy concept. A normal Windows laptop running the dashboard cannot throttle arbitrary other devices passing through the network. For centralized control of other clients, integrate a supported router/firewall QoS API or a dedicated gateway agent.
- **Both platforms:** the dashboard is the policy control plane; the actual enforcement point must be the gateway/router or a correctly configured inline host. Do not deploy to a university/production network without written authorization and a tested rollback plan.

### Run

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\\Scripts\\Activate.ps1  # Windows PowerShell
pip install -r requirements.txt
python -m streamlit run app.py
```

The Bandwidth Management tab is suitable for demonstrating policy creation, validation, approval, status tracking, and preview-only rollback/cancellation. It is not yet a production traffic shaper.
