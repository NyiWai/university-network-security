# University Network Security Monitoring and Access Control System

A cross-platform Python/Streamlit academic prototype for authorized network discovery, device inventory, application-level allow-list management, packet metadata capture, Suricata alert import, rule/Isolation Forest demonstrations, and bandwidth-policy management.

> **Maturity:** Academic prototype. The current release demonstrates management workflows and selected integrations. It is not a production NAC, firewall manager, or traffic shaper. Features described as future implementation are not currently active.

## Contents

1. [Overview](#1-overview)
2. [Features and status](#2-features-and-status)
3. [Architecture](#3-architecture)
4. [Technology and structure](#4-technology-and-structure)
5. [Installation](#5-installation)
6. [Dashboard usage](#6-dashboard-usage)
7. [How modules work](#7-how-modules-work)
8. [Real-world deployment: required connections](#8-real-world-deployment-required-connections)
9. [Implementation roadmap](#9-implementation-roadmap)
10. [Bandwidth management in depth](#10-bandwidth-management-in-depth)
11. [Suricata integration](#11-suricata-integration)
12. [Database, testing and validation](#12-database-testing-and-validation)
13. [Security and operational safety](#13-security-and-operational-safety)
14. [Troubleshooting](#14-troubleshooting)
15. [Limitations and future work](#15-limitations-and-future-work)
16. [Contributing and license](#16-contributing-and-license)

---

## 1. Overview

University networks connect students, lecturers, staff, servers, printers, access points, and personal devices. Administrators need visibility into devices, security events, and shared network-resource usage.

This project provides a centralized dashboard for an authorized lab or prototype deployment. It demonstrates:

- Network-interface and neighbor-table discovery.
- Device inventory.
- Application-level MAC allow-list records.
- Bounded packet-metadata capture without payload storage.
- Suricata EVE JSON alert import.
- Rule-based and Isolation Forest anomaly-detection demonstrations.
- Security-event review and CSV export.
- Firewall ruleset preview.
- Bandwidth-policy creation, validation, approval, status tracking, and command preview.

The application targets Windows and Linux, with shared Python logic and OS-specific adapters where appropriate.

## 2. Features and status

| Module | Current behavior | Status |
|---|---|---|
| Overview | Platform, interface, device, and alert summary | Implemented |
| Device discovery | Neighbor table (`ip neigh`, `arp -a`) and bounded Scapy ARP scan | Implemented; authorized subnet/permissions required |
| Device inventory | Stores discovered records in SQLite | Implemented |
| Access control | MAC validation, allow-list records, lookup, revoke, history | Application-level only; no network enforcement |
| Monitoring | Bounded packet metadata capture; no payload storage | Implemented; permissions and capture support required |
| Suricata | Imports EVE JSON alerts | Implemented; Suricata installed separately |
| AI detection | Synthetic scenarios, rules, Isolation Forest baseline | Demonstration using synthetic data |
| Alerts/reports | Event review/status and CSV export | Implemented |
| System | Platform information and firewall preview/validation | Preview/inspection only |
| Bandwidth | Policy validation, approval, lifecycle, Linux `tc` and Windows QoS previews | Preview-only; does not change speed |

**Do not confuse a dashboard record with an enforced network control.** An allow-list record does not make a switch/router reject a device; a firewall preview does not install a rule; an approved bandwidth record does not mean traffic is shaped. An anomaly alert is not proof of an attack.

## 3. Architecture

### Current prototype

```text
                  Administrator
                        |
                        v
              +-------------------+
              | Streamlit app.py  |
              +---------+---------+
                        |
        +---------------+----------------+
        |               |                |
        v               v                v
   Discovery        Monitoring        Detection
   ARP/Neighbor     Scapy/EVE          Rules + ML
        |               |                |
        +---------------+----------------+
                        |
                        v
                 SQLite database
          inventory / events / policies
```

### Intended real-world architecture

```text
Admin Browser --HTTPS/MFA--> Dashboard + API
                                  |
                      +-----------+-----------+
                      |                       |
                 Policy service          Event service
              validate/approve/audit    normalize/correlate
                      |                       ^
                      v                       |
                Policy database          Event database
                      |
            authenticated, scoped job
                      v
              Gateway agent / vendor API
                      |
                      v
             Router / Firewall / Gateway
                      |
                Managed clients

Switch SPAN/TAP --> Suricata sensor --> Alert ingestion --> Event store
DHCP/AP/Switch API ------------------> Inventory ingestion
```

This target architecture is **not** implemented by the current prototype. It requires authentication, an API, a gateway agent or supported vendor API, durable audit records, and integration testing.

Design principles:
- Separate the dashboard/control plane from the packet-forwarding data plane.
- Keep sensors separate from privileged enforcement where possible.
- Use least privilege; do not run the entire Streamlit server as root/Administrator.
- Require approval for disruptive changes.
- Read back and verify applied configuration.
- Fail safely and provide tested rollback.
- Audit who requested, approved, applied, and reverted every change.

## 4. Technology and structure

**Stack:** Python 3.11+, Streamlit, Pandas, NumPy, Plotly, scikit-learn, Scapy, psutil, Suricata EVE JSON, SQLite, `unittest`.

```text
university-network-security/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── adapters/
│   ├── access_control.py
│   ├── bandwidth.py
│   ├── linux/
│   │   ├── firewall.py
│   │   └── hotspot.py
│   └── windows/
│       ├── firewall.py
│       └── hotspot.py
├── core/
│   ├── database.py
│   └── platform_detector.py
├── discovery/
├── detector/
├── monitoring/
└── tests/
```

## 5. Installation

### Kali Linux / Debian-based Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip

git clone https://github.com/YOUR_USERNAME/university-network-security.git
cd university-network-security

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

python -m streamlit run app.py
```

Open `http://localhost:8501`.

### Windows 10/11

Install Python 3.11+, Git, and Npcap if needed. In PowerShell:

```powershell
git clone https://github.com/YOUR_USERNAME/university-network-security.git
cd university-network-security

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

If PowerShell blocks activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Stop Streamlit with `Ctrl+C`. The application initializes its SQLite database automatically.

**Privilege guidance:** Do not run the entire Streamlit server as root/Administrator just because packet capture may need extra permissions. Prefer a separate sensor process with narrowly scoped privileges.

## 6. Dashboard usage

### Overview
Review detected platform, interfaces, device totals, and security-event summaries.

### Devices
Refresh the local neighbor table. If explicitly authorized, run bounded ARP discovery on a private lab subnet (maximum 256 addresses). A neighbor table is not a complete inventory of every device on a switched network.

### Access Control
Add/check/revoke a test MAC address and review access history. This is an application-level allow-list only. Real enforcement requires a switch, wireless controller, RADIUS/NAC service, or firewall integration. MAC addresses can be spoofed.

### Monitoring & IDS
Select an interface, choose a bounded capture count, confirm authorization, and capture metadata. Optionally import Suricata EVE JSON. Packet metadata can still reveal sensitive communication patterns.

### AI Detection
Run synthetic normal, brute-force-like, unusual-transfer, or destination-sweep scenarios. The synthetic baseline is a demonstration, not validated production detection accuracy.

### Alerts & Reports
Review events, update status, and export CSV.

### System
Inspect platform information and view firewall configuration previews. Previewing does not apply firewall rules.

### Bandwidth Management
Create a policy for a private IPv4 target, choose Upload/Download/Both, set the prototype 1–10 Mbps limit, choose interfaces, confirm authorization, create the record, approve it, preview commands, and cancel/rollback the application record.

**The current version does not execute traffic-shaping commands and does not change actual network speed.**

## 7. How modules work

### Discovery
Linux reads `ip neigh`; Windows reads `arp -a`. Optional active discovery uses Scapy ARP requests on an explicitly selected private IPv4 subnet, capped at 256 addresses. Results depend on VLAN boundaries, wireless isolation, neighbor-cache state, and permissions.

### Access policy
MAC addresses are normalized and validated, then application allow-list and access-history records are stored in SQLite. This does not configure a switch, AP, RADIUS server, router, or firewall.

### Packet monitoring
A bounded capture records metadata such as time, interface, source/destination IP, protocol, and packet length. Payloads are not stored. Production monitoring needs explicit scope, retention, access controls, and authorization.

### AI detection
The Isolation Forest baseline uses synthetic normal data and is combined with rules. Real use requires representative labeled data, versioned features/models, drift monitoring, false-positive review, and measured precision/recall/F1.

## 8. Real-world deployment: required connections

Installing the dashboard on a laptop does not automatically connect it to or control the entire network. Each capability must connect to the component that can observe or enforce it.

### 8.1 Map the actual topology first

Document:
- Internet/WAN link and router/firewall.
- Layer-3 gateway and LAN/WAN interfaces.
- Core/access switches and supported management APIs.
- Wireless APs/controller and SSIDs.
- VLANs, subnets, DHCP and DNS services.
- Authentication service (RADIUS/802.1X, if present).
- Server networks and critical systems.
- Monitoring sensor location and available SPAN/TAP ports.

Example topology (illustrative only):

```text
Internet
   |
[Router / Firewall]
   |
[Core Switch]-------[Server VLAN]
   |
   +---------------[Access Switch]----[Student VLAN]
   |                                     +-- clients
   +---------------[Wireless AP]--------[Staff/Guest SSIDs]

[Monitoring Sensor] receives authorized SPAN/TAP traffic
[Management Server] hosts dashboard and policy API
```

Do not assume the dashboard host is the gateway. A laptop on the same Wi-Fi cannot shape another client's traffic if that traffic does not pass through the laptop.

### 8.2 Connect each feature to its real source/enforcement point

| Feature | Real component to connect | Required integration |
|---|---|---|
| Device discovery | DHCP leases, gateway, switch/AP controller, neighbor table | Read-only vendor API/polling and normalization |
| Identity | RADIUS/802.1X, DHCP, directory, controller | Correlate user/device identity; don't trust MAC alone |
| Access control | Wireless controller, managed switch, NAC/RADIUS, firewall | Enforce VLAN/port/SSID or firewall policy |
| Packet monitoring | Network TAP or switch SPAN/mirror port | Dedicated sensor NIC and approved capture scope |
| IDS | Suricata sensor | EVE JSON ingestion or event API |
| Firewall response | Existing firewall/router API or gateway agent | Approved narrow rules, read-back verification |
| Bandwidth | Router/firewall QoS or Linux gateway | Shape at the actual traffic path |
| Audit | Central database/log service | Actor, approver, request, result, timestamp, rollback |

The correct API depends on the exact vendor, model, firmware, and enabled features. Obtain the vendor's official API documentation before implementing a connector; do not guess endpoints or commands.

### 8.3 Recommended real deployment roles

1. **Management host:** Streamlit UI and authenticated policy API.
2. **Database:** SQLite is acceptable for a single-user prototype; consider PostgreSQL for concurrent/multi-user use.
3. **Monitoring sensor:** receives SPAN/TAP traffic and runs Suricata.
4. **Gateway/firewall:** remains the actual packet-forwarding and enforcement point.
5. **Gateway agent or vendor API connector:** receives authenticated, approved, narrowly scoped policy jobs.
6. **Identity source:** optional DHCP, RADIUS/802.1X, directory, switch, or wireless-controller integration.

For a small lab, some roles can share hardware, but privileged enforcement should remain isolated from the web UI.

### 8.4 Secure data flow

```text
Admin browser --HTTPS/MFA--> Dashboard/API
                                  |
                     Policy DB + audit log
                                  |
                  authenticated scoped request
                                  v
                       Gateway agent/API
                                  |
                         Router/firewall

SPAN/TAP --> Suricata sensor --> alert ingestion --> event DB
DHCP/AP/Switch API -----------> inventory ingestion --> device DB
```

Recommended controls:
- Place management services in a restricted management VLAN.
- Restrict dashboard access to administrator networks or VPN.
- Use HTTPS, MFA, and role-based access control.
- Restrict the gateway API/agent to the management service.
- Use mutual TLS or signed short-lived jobs where supported.
- Never expose an agent that accepts arbitrary shell commands.
- Separate sensor and management interfaces where possible.

### 8.5 Information required before vendor integration

Collect this before writing integration code:

| Item | Record |
|---|---|
| Router/firewall | Vendor, exact model, firmware |
| Switches | Vendor, model, firmware, API capability |
| AP/controller | Model, management mode, firmware |
| Gateway | IP, LAN/WAN interface names |
| VLAN/subnets | IDs, CIDRs, gateways |
| DHCP | Server/source and lease API |
| Authentication | RADIUS/802.1X, WPA-Enterprise, or PSK |
| QoS | Per-IP/client/VLAN support and API |
| API documentation | Official documentation/version |
| Sensor | SPAN/TAP port and NIC |
| Authorization | Written scope, approver, maintenance window |
| Rollback | Tested restore steps and responsible operator |

Without this information, a safe vendor-specific integration cannot be selected.

## 9. Implementation roadmap

Implement in milestones. Do not begin with automatic blocking or traffic shaping.

### Phase 0 — Authorization and network discovery
1. Obtain written permission and define exact scope.
2. Identify network owner and change approver.
3. Draw physical/logical topology.
4. Record gateway, switches, APs, VLANs, DHCP, DNS, and authentication.
5. Select an isolated test subnet and test client.
6. Define success criteria, maintenance window, and rollback owner.

**Deliverable:** approved scope, topology diagram, inventory, test plan.

### Phase 1 — Harden the management application
1. Add administrator authentication and roles (Viewer, Analyst, Approver, Operator).
2. Consider PostgreSQL for multi-user operation.
3. Add schema migrations, backups, structured logs, and audit history.
4. Add secure session handling, secret management, and input validation.
5. Deploy behind a reverse proxy with HTTPS.
6. Do not expose the Streamlit development server directly to the Internet.

**Deliverable:** authenticated dashboard with durable records and audit trail.

### Phase 2 — Connect inventory sources
1. Choose authoritative sources for device fields.
2. Create read-only credentials with minimum privileges.
3. Implement one adapter per vendor/source.
4. Normalize device ID, MAC, IP, VLAN, switch/AP, first/last seen, source, and confidence.
5. Deduplicate and handle changing IP addresses.
6. Record stale data and connector failures.
7. Test read-only before enabling write operations.

**Deliverable:** refreshed inventory with provenance and last-seen data.

### Phase 3 — Deploy monitoring/IDS
1. Confirm a SPAN/mirror port or approved TAP and its VLAN scope.
2. Connect a dedicated sensor NIC.
3. Install/configure Suricata using documentation for the installed version.
4. Validate EVE output, ruleset updates, time sync, log rotation, and disk capacity.
5. Build ingestion with checkpoints, normalization, and deduplication.
6. Monitor packet drops, sensor uptime, ingestion delay, and disk use.
7. Tune alerts in a lab and document false positives.

**Deliverable:** authorized sensor feeding normalized IDS events.

### Phase 4 — Implement actual access control
Choose the mechanism matching the network:
- Enterprise Wi-Fi: wireless controller + RADIUS/802.1X; prefer authenticated identity and dynamic VLAN/role assignment.
- Managed wired switch: 802.1X or supported port access controls.
- Firewall/gateway: address objects/security groups or vendor API policies.
- Small isolated lab: dedicated gateway with a test-client allow-list.

Implementation sequence:
1. Map device/user identity; do not treat MAC as secure identity.
2. Create a draft/disabled policy.
3. Validate target, scope, expiry, and conflicts.
4. Require approval.
5. Apply through supported API or constrained gateway agent.
6. Read back configuration and verify.
7. Record actor, timestamp, API result, and resource ID.
8. Provide tested rollback.
9. Test recovery through a separate management path.

**Deliverable:** applied and verified policy at the actual enforcement point.

### Phase 5 — Implement actual bandwidth shaping
1. Confirm target traffic traverses the selected gateway.
2. Check router QoS support and official API.
3. For Linux `tc`, identify LAN/WAN egress interfaces and inspect existing qdiscs/classes/filters.
4. Design upload and download separately.
5. Use stable identity/reserved DHCP leases; IPs can change.
6. Implement a gateway-side agent with fixed allowed operations, not arbitrary shell input.
7. Add approval, idempotency, expiry, read-back verification, and rollback.
8. Test one isolated client with a conservative limit.
9. Measure before/after using a controlled test endpoint and repeat trials.
10. Test gateway restart, agent outage, duplicate request, IP change, and rollback failure.

**Deliverable:** verified per-client rate limit at the gateway/router.

### Phase 6 — Pilot and acceptance
- Use an isolated pilot VLAN.
- Compare inventory with authoritative DHCP/controller data.
- Measure alert ingestion delay and packet drops.
- Evaluate detection on labeled data.
- Verify applied policies by reading configuration back.
- Test rollback and management recovery.
- Document runbooks, limitations, and training.
- Obtain sign-off before expanding scope.

**Deliverable:** pilot report and production-readiness decision.

## 10. Bandwidth management in depth

### Current implementation

The current tab supports:
- Private IPv4 validation (public, loopback, link-local, and multicast rejected).
- Prototype limit range of 1–10 Mbps.
- Upload, Download, Both selection.
- Interface-name validation.
- SQLite policy records.
- `PENDING`, `APPROVED`, `PREVIEWED`, and `ROLLED_BACK` states.
- Linux `tc` and Windows QoS command previews.

**No OS traffic-shaping command is executed. Actual Internet speed is not changed.**

### Why the gateway matters

Traffic shaping only works where the target's packets pass through the shaper.

```text
Upload:   Client --LAN--> Gateway --WAN--> Internet
Download: Internet --WAN--> Gateway --LAN--> Client
```

On a typical routed Linux gateway:
- Upload shaping is commonly on WAN egress, matching the client source IP.
- Download shaping toward a LAN client is commonly on LAN egress, matching the client destination IP.

Actual design depends on routing, NAT, VLANs, interfaces, and existing QoS. A Windows laptop on the same Wi-Fi cannot shape a client whose traffic bypasses that laptop.

### Linux `tc` integration design

A future Linux gateway connector may use `tc` queuing disciplines and classifiers; HTB is one possible class-based mechanism.

Before implementing:
1. Confirm the host is the authorized gateway.
2. Identify correct egress interfaces.
3. Inspect existing configuration with `tc -s qdisc show` and `tc -s class show dev INTERFACE`.
4. Check whether another service manages QoS.
5. Design dedicated handles/classes that do not conflict.
6. Match only the intended client and direction.
7. Save the prior state or prepare a tested rollback.
8. Apply one lab policy and read back qdisc/class/filter state.
9. Measure traffic and remove only resources created by that policy.

Do not blindly execute preview commands. Never flush all qdiscs, firewall rules, or Docker-managed networking state.

### Windows integration design

Windows QoS policies can manage traffic originating from the Windows host in supported configurations. A normal Windows laptop is not automatically a transparent gateway for other devices.

For centralized per-client control, use a supported router/firewall QoS API or a dedicated gateway that actually forwards the target's traffic.

### Production policy lifecycle

```text
DRAFT -> VALIDATED -> PENDING_APPROVAL -> APPROVED
      -> APPLY_REQUESTED -> APPLIED_AND_VERIFIED
      -> EXPIRED or ROLLBACK_REQUESTED
      -> ROLLED_BACK_AND_VERIFIED
```

Also support `FAILED`, `REJECTED`, and `ROLLBACK_FAILED`. The prototype uses a smaller lifecycle and does not apply/verify OS rules.

### Additional production fields

Policy ID/idempotency key; requester and approver; target identity/MAC/IP/VLAN and identity source; gateway and interface IDs; upload/download rates and direction; creation/approval/application/expiry/rollback times; enforcement resource IDs; apply/verification result; error details; reason/change-ticket reference; audit history.

## 11. Suricata integration

Suricata is an optional external IDS and must be installed/configured separately on an authorized sensor. The application imports EVE JSON. A common Linux path is `/var/log/suricata/eve.json`, but the actual path depends on configuration.

For operational use:
- Feed Suricata from a documented SPAN/TAP sensor.
- Enable required EVE event types.
- Configure log rotation and disk monitoring.
- Restrict log access.
- Add ingestion checkpoints and duplicate handling.
- Store sensor ID, event and ingestion timestamps, signature, severity, endpoints, and flow identifiers where available.
- Synchronize sensor clocks.

The application does not install, update, or manage the Suricata service.

## 12. Database, testing and validation

SQLite is initialized at `data/network_security.db` and stores devices, allow-list entries, access events, security events, traffic samples, and bandwidth policies. Generated databases must not be committed to GitHub.

For multi-user operation, consider PostgreSQL, schema migrations, encrypted backups, restricted DB access, retention schedules, and tested restore procedures.

Run tests:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

Unit tests do not prove live discovery, packet capture, Suricata ingestion, firewall enforcement, or traffic shaping on every OS.

Recommended integration evidence:

| Test | Evidence |
|---|---|
| Discovery | Compare observed devices with authorized lab inventory |
| Packet capture | Packet count, drops, metadata correctness |
| Suricata | Event count, deduplication, ingestion delay |
| Access enforcement | Controller/firewall read-back and test-client result |
| Bandwidth | Before/after throughput, configured rate, verified rollback |
| Failure recovery | Behavior with API/agent offline and rollback failure |
| Security | Authentication, roles, audit, secrets, exposure review |

Record versions, topology, conditions, results, and limitations.

## 13. Security and operational safety

- Only scan, capture, or manage networks/devices you own or have explicit written permission to test.
- Use an isolated lab before any pilot.
- Do not scan a university production network without authorization.
- Protect metadata and exported reports; define retention.
- Never commit secrets, tokens, credentials, private keys, live databases, or real monitoring data.
- MAC addresses can be spoofed and are not strong authentication.
- Do not expose the Streamlit development server directly to the public Internet.
- Add authentication, authorization, HTTPS, secure sessions, and network restrictions before multi-user deployment.
- Never accept arbitrary shell commands from dashboard input.
- Keep privileged operations in a constrained gateway agent or supported vendor API.
- Require approval, verify applied state, and maintain tested rollback.
- Preserve a separate management path to avoid administrator lockout.
- Follow institutional policy, privacy requirements, and applicable law.

## 14. Troubleshooting

**Streamlit not found:**
```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

**Wrong project directory:**
```bash
pwd
ls
```
Run from the folder containing `app.py`.

**PowerShell activation blocked:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

**Scapy capture fails:** check interface, Npcap on Windows, capture permissions, and authorized scope. Prefer a separate sensor process over running the full dashboard as root.

**Bandwidth policy saves but speed does not change:** expected; the current feature is preview-only.

**Windows laptop cannot throttle another client:** it is not automatically the gateway. Use the actual router/firewall QoS integration or inline gateway.

**Suricata alerts not imported:** verify Suricata is running, EVE path is correct/readable, and alert output is enabled.

## 15. Limitations and future work

Current limitations:
1. Academic prototype, not production NAC/IDS.
2. MAC allow-list is application-level only.
3. Hotspot/DHCP management is not automated.
4. Firewall previews are not applied.
5. Windows firewall adapter is inspection-oriented.
6. Discovery/capture depend on OS support and privileges.
7. Suricata is separately installed/configured.
8. Isolation Forest baseline uses synthetic data.
9. Bandwidth module does not execute `tc` or Windows QoS commands.
10. Windows host cannot shape arbitrary clients unless it is the gateway or uses gateway integration.
11. Production authentication, RBAC, gateway agent, vendor connectors, and HA are not included.

Future work:
- Authentication, MFA, RBAC.
- PostgreSQL and migrations.
- Read-only DHCP/RADIUS/switch/AP/firewall connectors.
- Suricata sensor and event streaming.
- Vendor-supported firewall/controller integration.
- Constrained gateway agent.
- Verified Linux `tc` and router QoS enforcement.
- Policy expiry, idempotency, conflict detection, rollback verification.
- Labeled datasets and formal model evaluation.
- Retention, audit, alert tuning, runbooks, staging integration tests.

## 16. Contributing and license

Contributions:
1. Fork the repository.
2. Create a feature branch.
3. Make a focused change.
4. Run unit and relevant integration tests.
5. Update documentation and label preview-only versus enforced behavior.
6. Submit a pull request with test evidence.

Do not submit secrets or private network data.

No license is currently specified. Unless a license is added, all rights remain with the copyright holder. If publishing as open source, select a license and add a `LICENSE` file before inviting reuse.
