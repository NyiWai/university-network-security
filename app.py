import json
import platform
import socket
from pathlib import Path

import pandas as pd
import streamlit as st

from core.database import (initialize_database, get_connection, get_all_devices,
                           get_security_events, update_event_status, get_access_events,
                           save_security_event)
from core.platform_detector import get_platform_details
from discovery.interface_scanner import get_network_interfaces
from discovery.device_discovery import discover_devices
from discovery.active_discovery import get_ipv4_networks, scan_network
from adapters.access_control import allow_device, revoke_device, get_allowed_devices, is_device_allowed
from adapters.linux.firewall import generate_ruleset, validate_ruleset
from detector.simulator import generate_scenario
from monitoring.event_processor import process_feature_sample
from monitoring.suricata import read_eve_alerts
from adapters.bandwidth import validate_policy, build_preview, get_platform_capabilities
from core.database import create_bandwidth_policy, get_bandwidth_policies, update_bandwidth_policy_status

st.set_page_config(page_title="University Network Security", page_icon="🛡️", layout="wide")
initialize_database()

st.title("🛡️ University Network Security Monitoring")
st.caption("Cross-Platform Integrated University Network Security Monitoring and Access Control System")

interfaces = get_network_interfaces()
devices = get_all_devices()
allowed = get_allowed_devices()
events = get_security_events()
open_alerts = sum(1 for e in events if e["status"] == "OPEN" and e["severity"] in ("HIGH", "MEDIUM"))

c1, c2, c3, c4 = st.columns(4)
c1.metric("Operating System", platform.system())
c2.metric("Interfaces", len(interfaces))
c3.metric("Recorded Devices", len(devices))
c4.metric("Open Security Alerts", open_alerts)

pages = st.tabs(["Overview", "Devices", "Access Control", "Monitoring & IDS", "AI Detection", "Alerts & Reports", "System", "Bandwidth Management"])

with pages[0]:
    st.subheader("Security Overview")
    if events:
        frame = pd.DataFrame(events)
        st.dataframe(frame[["timestamp", "source", "event_type", "severity", "score", "status"]], use_container_width=True, hide_index=True)
    else:
        st.info("No security events yet. Use the scenario simulator in AI Detection to generate test events.")
    st.subheader("Network Interfaces")
    st.dataframe(pd.DataFrame(interfaces), use_container_width=True, hide_index=True)

with pages[1]:
    st.subheader("Device Discovery")
    a, b = st.columns(2)
    with a:
        if st.button("Refresh neighbor table", use_container_width=True):
            found = discover_devices()
            from core.database import save_devices
            save_devices(found)
            st.success(f"Saved {len(found)} neighbor entries.")
            st.rerun()
    networks = get_ipv4_networks()
    if networks:
        labels = [f"{n['interface']} · {n['network']} · {n['ip']}" for n in networks]
        choice = st.selectbox("Authorized private test subnet", labels)
        selected = networks[labels.index(choice)]
        consent = st.checkbox("I confirm I own or am authorized to test this network.")
        if st.button("Run active ARP discovery", disabled=not consent):
            try:
                with st.spinner("Sending ARP requests..."):
                    found = scan_network(selected["network"], selected["interface"])
                from core.database import save_devices
                save_devices(found)
                st.success(f"Discovered {len(found)} responding devices.")
            except Exception as exc:
                st.error(str(exc))
    else:
        st.info("No eligible private IPv4 subnet detected.")
    st.subheader("Device Inventory")
    devices = get_all_devices()
    st.dataframe(pd.DataFrame(devices), use_container_width=True, hide_index=True) if devices else st.info("No devices recorded.")

with pages[2]:
    st.subheader("Application Allow-list")
    st.warning("This allow-list records authorization decisions. It does not block network traffic until a separately configured, reviewed firewall enforcement deployment is installed.")
    with st.form("allow_form"):
        mac = st.text_input("Device MAC", placeholder="AA:BB:CC:DD:EE:FF")
        name = st.text_input("Device name")
        description = st.text_input("Description / owner")
        submitted = st.form_submit_button("Add / Update allowed device")
        if submitted:
            try:
                allow_device(mac, name, description)
                st.success("Device saved to application allow-list.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    allowed = get_allowed_devices()
    if allowed:
        for item in allowed:
            x, y = st.columns([4, 1])
            x.write(f"**{item['device_name']}** · `{item['mac']}`")
            if y.button("Revoke", key=f"revoke-{item['mac']}"):
                revoke_device(item["mac"])
                st.rerun()
    st.subheader("Authorization check")
    check = st.text_input("MAC to check", key="check_mac")
    if st.button("Check MAC"):
        try:
            st.success("Registered in allow-list" if is_device_allowed(check) else "Not registered in allow-list")
        except ValueError as exc:
            st.error(str(exc))
    st.subheader("Access history")
    access_history = get_access_events()
    st.dataframe(pd.DataFrame(access_history), use_container_width=True, hide_index=True) if access_history else st.info("No access events.")

with pages[3]:
    st.subheader("Packet Metadata Capture")
    st.caption("Opt-in capture stores packet metadata only; it does not save payload contents.")
    names = [i["name"] for i in interfaces if i["is_up"]]
    if names:
        selected_iface = st.selectbox("Capture interface", names)
        count = st.slider("Maximum packets", 10, 500, 100, 10)
        consent = st.checkbox("I am authorized to monitor this interface.")
        if st.button("Start bounded metadata capture", disabled=not consent):
            try:
                from monitoring.packet_monitor import capture_metadata
                from datetime import datetime, timezone
                from core.database import get_connection
                captured = capture_metadata(selected_iface, count, 20)
                with get_connection() as db:
                    for p in captured:
                        db.execute("INSERT INTO traffic_samples(timestamp,interface,src_ip,dst_ip,protocol,packet_length) VALUES(?,?,?,?,?,?)",
                                   (p["timestamp"], p["interface"], p["src_ip"], p["dst_ip"], p["protocol"], p["packet_length"]))
                st.success(f"Stored {len(captured)} metadata records.")
                st.dataframe(pd.DataFrame(captured), use_container_width=True)
            except Exception as exc:
                st.error(f"Capture unavailable: {exc}")
    else:
        st.info("No active interface available.")
    st.subheader("Suricata EVE JSON import")
    eve_path = st.text_input("EVE JSON path", value="/var/log/suricata/eve.json")
    if st.button("Import Suricata alerts"):
        imported = read_eve_alerts(eve_path)
        for event in imported:
            save_security_event(event)
        st.success(f"Imported {len(imported)} Suricata alert records.")
    st.subheader("Recent traffic metadata")
    with get_connection() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM traffic_samples ORDER BY id DESC LIMIT 300")]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True) if rows else st.info("No traffic metadata captured.")

with pages[4]:
    st.subheader("AI + Rule-based Detection")
    st.write("The Isolation Forest baseline is trained on synthetic normal behavior. Scenario results are demonstrations, not validated real-world accuracy claims.")
    scenario = st.selectbox("Select test scenario", ["Normal activity", "Brute-force simulation", "Unusual data transfer", "Port / destination sweep simulation"])
    if st.button("Generate and analyze scenario"):
        try:
            sample = generate_scenario(scenario)
            result, generated = process_feature_sample(sample)
            st.json({"features": sample["features"], "analysis": result})
            st.success(f"Recorded {len(generated)} event(s).")
        except Exception as exc:
            st.error(str(exc))
    st.caption("Feature inputs: failed logins, connection count, outbound bytes, unique destinations, average packet size.")

with pages[5]:
    st.subheader("Security Alerts")
    events = get_security_events()
    if events:
        df = pd.DataFrame(events)
        st.dataframe(df, use_container_width=True, hide_index=True)
        event_ids = [int(e["id"]) for e in events]
        selected_id = st.selectbox("Select event ID", event_ids)
        status = st.selectbox("Set status", ["OPEN", "ACKNOWLEDGED", "CLOSED"])
        if st.button("Update event status"):
            update_event_status(selected_id, status)
            st.success("Event status updated.")
            st.rerun()
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("Download events CSV", csv, "security_events.csv", "text/csv")
    else:
        st.info("No alerts recorded.")

with pages[6]:
    st.subheader("System Information")
    st.json(get_platform_details())
    st.dataframe(pd.DataFrame(interfaces), use_container_width=True, hide_index=True)
    st.subheader("Linux nftables ruleset preview")
    if platform.system() == "Linux":
        ifnames = [i["name"] for i in interfaces]
        iface = st.selectbox("Test interface (preview only)", ifnames, key="nft_iface") if ifnames else "test-ap0"
        cidr = st.text_input("Private test subnet", "192.168.50.0/24")
        if st.button("Generate nftables preview"):
            try:
                st.code(generate_ruleset(iface, cidr), language="text")
                st.info("Preview only. This application does not apply firewall rules or change your host firewall.")
            except Exception as exc:
                st.error(str(exc))
    else:
        st.info("Linux nftables preview is available on Linux only. Windows Firewall status can be inspected separately by its adapter.")
    st.subheader("Project limitations")
    st.markdown("- Hotspot creation and firewall enforcement require explicit OS-level setup and are not automated by this release.\n- MAC allow-list is an application policy, not strong authentication.\n- Scapy capture and active discovery may require administrator/root privileges.\n- Suricata import requires an installed Suricata service and readable EVE JSON file.\n- AI demo model uses synthetic baseline data and needs labeled test datasets for formal evaluation.")

st.divider()
st.caption(f"University Network Security Monitoring · Development build · {socket.gethostname()}")


with pages[7]:
    st.subheader("IP-based Bandwidth Management")
    st.warning("Safe first milestone: policy validation, approval workflow, status tracking, and command previews only. No operating-system traffic-shaping commands are executed.")
    caps = get_platform_capabilities()
    st.write(f"Detected platform: **{caps['platform']}** · Mode: **{caps['mode']}**")
    st.info(f"Upload: {caps['upload']}\n\nDownload: {caps['download']}\n\nApply status: Disabled — {caps['reason']}")

    active_names = [i["name"] for i in interfaces if i.get("is_up")]
    with st.form("bandwidth_policy_form"):
        target_ip = st.text_input("Target private IPv4 address", placeholder="192.168.50.20")
        direction = st.selectbox("Traffic direction", ["Both", "Upload", "Download"])
        limit_mbps = st.number_input("Bandwidth limit (Mbps)", min_value=1, max_value=10, value=2, step=1)
        ifnames = active_names or ["lab-interface"]
        upload_iface = st.selectbox("Upload egress interface (gateway WAN)", ifnames)
        download_iface = st.selectbox("Download egress interface (gateway LAN)", ifnames, index=min(1, len(ifnames)-1))
        consent = st.checkbox("I confirm this is my own isolated lab or a network I am explicitly authorized to manage.")
        submitted = st.form_submit_button("Create bandwidth policy", disabled=not consent)
        if submitted:
            try:
                policy = validate_policy(target_ip, upload_iface, download_iface, limit_mbps, direction)
                policy_id = create_bandwidth_policy(policy)
                st.success(f"Policy #{policy_id} created with PENDING status. No traffic has been changed.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

    st.subheader("Policy approval and lifecycle")
    policies = get_bandwidth_policies()
    if policies:
        st.dataframe(pd.DataFrame(policies), use_container_width=True, hide_index=True)
        ids = [int(p["id"]) for p in policies]
        selected_id = st.selectbox("Select policy", ids, key="bandwidth_policy_id")
        selected = next(p for p in policies if int(p["id"]) == selected_id)
        left, middle, right = st.columns(3)
        if left.button("Approve policy", disabled=selected["status"] not in ("PENDING", "ROLLED_BACK"), use_container_width=True):
            update_bandwidth_policy_status(selected_id, "APPROVED")
            st.success("Policy approved for lab review. It is not applied.")
            st.rerun()
        if middle.button("Generate command preview", disabled=selected["status"] not in ("PENDING", "APPROVED", "PREVIEWED"), use_container_width=True):
            normalized = validate_policy(selected["target_ip"], selected["upload_interface"], selected["download_interface"], selected["limit_mbps"], selected["direction"])
            st.code(build_preview(normalized), language="bash" if platform.system() == "Linux" else "powershell")
            if selected["status"] == "APPROVED":
                update_bandwidth_policy_status(selected_id, "PREVIEWED")
                st.caption("Preview generated. No command was executed. Refresh the page to see the updated status.")
        if right.button("Rollback / cancel policy", disabled=selected["status"] == "ROLLED_BACK", use_container_width=True):
            update_bandwidth_policy_status(selected_id, "ROLLED_BACK")
            st.success("Policy cancelled in the application. Since enforcement is disabled, no OS traffic rules needed removal.")
            st.rerun()
    else:
        st.info("No bandwidth policies created yet.")
    st.subheader("Important platform limitations")
    st.markdown("- **Linux gateway:** `tc` can shape egress traffic. Upload and download generally require different gateway egress interfaces (WAN and LAN). Existing qdiscs must be inspected and preserved.\n- **Windows host:** Windows QoS policies primarily control traffic originating from that Windows host; they do not make an ordinary Windows laptop a bandwidth controller for other clients.\n- **Both platforms:** To control other devices from one dashboard, the dashboard must call an authorized router/firewall QoS API or a dedicated gateway agent.\n- This release intentionally has no Apply button. Approval is an application workflow step, not permission to change the host network automatically.")
