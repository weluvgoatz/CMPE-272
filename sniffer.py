import os
import numpy as np
import pandas as pd
from scapy.all import rdpcap

# avoids permission denied error
input_pcaps = ['captures/benign_traffic.pcap', 'captures/attacker_traffic.pcap']
output_csv = 'flows_output.csv' # saves directly to current project folder
all_packets = []

def parse_ports(spec):
    """'80' -> {80}; '1-1000' -> range; '22,80' -> {22,80}."""
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return ports

def label_flows(flows: pd.DataFrame, log_path="logs/attack_log.csv",
                start_col="flow_start_epoch", port_col="Destination Port",
                pad_before=1.0, pad_after=2.0):
    log = pd.read_csv(log_path)
    labels = pd.Series("BENIGN", index=flows.index, dtype=object)

    for _, a in log.iterrows():
        in_window = flows[start_col].between(a.start_epoch - pad_before,
                                             a.end_epoch + pad_after)
        on_port = flows[port_col].isin(parse_ports(a.target_port))
        labels[in_window & on_port] = a.attack_type

    return labels

def get_flow_key(pkt):
    if not pkt.haslayer('IP'):
        return None
    src_ip, dst_ip, proto = pkt['IP'].src, pkt['IP'].dst, pkt['IP'].proto
    if pkt.haslayer('TCP'):
        sport, dport = pkt['TCP'].sport, pkt['TCP'].dport
    elif pkt.haslayer('UDP'):
        sport, dport = pkt['UDP'].sport, pkt['UDP'].dport
    else:
        sport, dport = 0, 0
    sender, receiver = (src_ip, sport), (dst_ip, dport)
    key = (sender, receiver, proto) if sender < receiver else (receiver, sender, proto)
    return key, sender

print("Loading PCAP file...")
try:
    for file in input_pcaps:
      packets = rdpcap(file)
      all_packets.extend(packets)
    packets = all_packets
    print(f"Loaded {len(packets)} packets. Mapping full CIC-IDS 2017 feature matrix...")
except Exception as e:
    print(f"Error: {e}")
    exit(1)

raw_flows = {}
for pkt in packets:
    key_info = get_flow_key(pkt)
    if not key_info:
        continue
    flow_key, sender = key_info
    raw_flows.setdefault(flow_key, []).append((float(pkt.time), sender, pkt))

"""
raw_flows = {}
for pkt in packets:
    key_info = get_flow_key(pkt)
    if not key_info:
        continue
    flow_key, direction = key_info
    if flow_key not in raw_flows:
        raw_flows[flow_key] = {"fwd": [], "bwd": [], "all_times": []}
    raw_flows[flow_key][direction].append(pkt)
    raw_flows[flow_key]["all_times"].append(float(pkt.time))
"""

computed_flows = []

for key, entries in raw_flows.items():
    entries.sort(key=lambda e: e[0])            # also fixes unsorted merge of two pcaps
    initiator = entries[0][1]                   # whoever sent the first packet
    end_a, end_b, proto = key
    responder = end_b if initiator == end_a else end_a

    src_ip, src_port = initiator
    dst_ip, dst_port = responder                # now the server port (80, 22, 21, ...)

    fwd_pkts = [p for t, s, p in entries if s == initiator]
    bwd_pkts = [p for t, s, p in entries if s != initiator]
    all_times = [t for t, _, _ in entries]
    
    # 1. Packet Counts & Lengths
    def payload_len(p):
        if p.haslayer('TCP'): return len(p['TCP'].payload)
        if p.haslayer('UDP'): return len(p['UDP'].payload)
        return len(p['IP'].payload)

    def hdr_len(p):
        n = p['IP'].ihl * 4 if p.haslayer('IP') else 0
        if p.haslayer('TCP'): n += p['TCP'].dataofs * 4
        elif p.haslayer('UDP'): n += 8
        return n

    fwd_lens = [payload_len(p) for p in fwd_pkts]
    bwd_lens = [payload_len(p) for p in bwd_pkts]
    fwd_header_len = sum(hdr_len(p) for p in fwd_pkts)
    bwd_header_len = sum(hdr_len(p) for p in bwd_pkts)
    all_lens = fwd_lens + bwd_lens
    
    duration = (all_times[-1] - all_times[0]) if all_times else 0
    duration_ms = duration * 1000000  # CIC-IDS uses microseconds
    
    # 2. Inter-Arrival Times (IAT)
    fwd_times = sorted([float(p.time) for p in fwd_pkts])
    bwd_times = sorted([float(p.time) for p in bwd_pkts])
    
    fwd_iats = np.diff(fwd_times) * 1000000 if len(fwd_times) > 1 else [0]
    bwd_iats = np.diff(bwd_times) * 1000000 if len(bwd_times) > 1 else [0]
    flow_iats = np.diff(all_times) * 1000000 if len(all_times) > 1 else [0]

    # 3. Flag Counts (TCP Specific)
    flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "CWR": 0, "ECE": 0}
    fwd_flags = flags.copy()
    bwd_flags = flags.copy()
    win_bytes_fwd, win_bytes_bwd = 0, 0
    fwd_act_data_pkts = 0

    for p in fwd_pkts:
        if p.haslayer('TCP'):
            F = p['TCP'].flags
            # win_bytes_fwd = p['TCP'].window
            win_bytes_fwd = next((p['TCP'].window for p in fwd_pkts if p.haslayer('TCP')), 0)
            if F & 0x01: fwd_flags["FIN"] += 1; flags["FIN"] += 1
            if F & 0x02: fwd_flags["SYN"] += 1; flags["SYN"] += 1
            if F & 0x04: fwd_flags["RST"] += 1; flags["RST"] += 1
            if F & 0x08: fwd_flags["PSH"] += 1; flags["PSH"] += 1
            if F & 0x10: fwd_flags["ACK"] += 1; flags["ACK"] += 1
            if F & 0x20: fwd_flags["URG"] += 1; flags["URG"] += 1
            if len(p['TCP'].payload) > 0: fwd_act_data_pkts += 1
            if F & 0x80: fwd_flags["CWR"] += 1; flags["CWR"] += 1 
            if len(p['TCP'].payload) > 0: fwd_act_data_pkts += 1

    for p in bwd_pkts:
        if p.haslayer('TCP'):
            F = p['TCP'].flags
            # win_bytes_bwd = p['TCP'].window
            win_bytes_bwd = next((p['TCP'].window for p in bwd_pkts if p.haslayer('TCP')), 0)
            if F & 0x01: bwd_flags["FIN"] += 1; flags["FIN"] += 1
            if F & 0x02: bwd_flags["SYN"] += 1; flags["SYN"] += 1
            if F & 0x04: bwd_flags["RST"] += 1; flags["RST"] += 1
            if F & 0x08: bwd_flags["PSH"] += 1; flags["PSH"] += 1
            if F & 0x10: bwd_flags["ACK"] += 1; flags["ACK"] += 1
            if F & 0x20: bwd_flags["URG"] += 1; flags["URG"] += 1
            if F & 0x80: bwd_flags["CWR"] += 1; flags["CWR"] += 1

    # 4. Header Segments
    # fwd_header_len = sum([len(p['IP']) - len(p['IP'].payload) for p in fwd_pkts if p.haslayer('IP')])
    # bwd_header_len = sum([len(p['IP']) - len(p['IP'].payload) for p in bwd_pkts if p.haslayer('IP')])

    # 5. Build Complete Feature Set
    feat = {
        "flow_start_epoch": all_times[0],
        "Source IP": src_ip, "Source Port": src_port, "Destination IP": dst_ip, "Destination Port": dst_port, "Protocol": proto,
        "Flow Duration": duration_ms,
        "Total Fwd Packets": len(fwd_pkts), "Total Backward Packets": len(bwd_pkts),
        "Total Length of Fwd Packets": sum(fwd_lens), "Total Length of Bwd Packets": sum(bwd_lens),
        "Fwd Packet Length Max": max(fwd_lens) if fwd_lens else 0, "Fwd Packet Length Min": min(fwd_lens) if fwd_lens else 0,
        "Fwd Packet Length Mean": np.mean(fwd_lens) if fwd_lens else 0, "Fwd Packet Length Std": np.std(fwd_lens) if fwd_lens else 0,
        "Bwd Packet Length Max": max(bwd_lens) if bwd_lens else 0, "Bwd Packet Length Min": min(bwd_lens) if bwd_lens else 0,
        "Bwd Packet Length Mean": np.mean(bwd_lens) if bwd_lens else 0, "Bwd Packet Length Std": np.std(bwd_lens) if bwd_lens else 0,
        "Flow Bytes/s": (sum(all_lens) / duration) if duration > 0 else 0,
        "Flow Packets/s": (len(all_lens) / duration) if duration > 0 else 0,
        "Flow IAT Mean": np.mean(flow_iats), "Flow IAT Std": np.std(flow_iats), "Flow IAT Max": max(flow_iats), "Flow IAT Min": min(flow_iats),
        "Fwd IAT Total": sum(fwd_iats) if len(fwd_iats) > 0 else 0,
        "Fwd IAT Mean": np.mean(fwd_iats), "Fwd IAT Std": np.std(fwd_iats), "Fwd IAT Max": max(fwd_iats), "Fwd IAT Min": min(fwd_iats),
        "Bwd IAT Mean": np.mean(bwd_iats), "Bwd IAT Std": np.std(bwd_iats), "Bwd IAT Max": max(bwd_iats), "Bwd IAT Min": min(bwd_iats),
        "Bwd IAT Total": sum(bwd_iats) if len(bwd_iats) > 0 else 0,
        "Fwd PSH Flags": fwd_flags["PSH"], "Bwd PSH Flags": bwd_flags["PSH"],
        "Fwd URG Flags": fwd_flags["URG"], "Bwd URG Flags": bwd_flags["URG"],
        "Fwd Header Length": fwd_header_len, "Bwd Header Length": bwd_header_len,
        "Fwd Packets/s": (len(fwd_pkts) / duration) if duration > 0 else 0, "Bwd Packets/s": (len(bwd_pkts) / duration) if duration > 0 else 0,
        "Min Packet Length": min(all_lens) if all_lens else 0, "Max Packet Length": max(all_lens) if all_lens else 0,
        "Packet Length Mean": np.mean(all_lens) if all_lens else 0, "Packet Length Std": np.std(all_lens) if all_lens else 0, "Packet Length Variance": np.var(all_lens) if all_lens else 0,
        "FIN Flag Count": flags["FIN"], "SYN Flag Count": flags["SYN"], "RST Flag Count": flags["RST"], "PSH Flag Count": flags["PSH"],
        "ACK Flag Count": flags["ACK"], "URG Flag Count": flags["URG"], "CWR Flag Count": flags["CWR"], "CWE Flag Count": flags["CWR"], "ECE Flag Count": flags["ECE"],
        "Down/Up Ratio": (len(bwd_pkts) / len(fwd_pkts)) if len(fwd_pkts) > 0 else 0,
        "Average Packet Size": (sum(all_lens) / len(all_lens)) if all_lens else 0,
        "Avg Fwd Segment Size": np.mean(fwd_lens) if fwd_lens else 0, "Avg Bwd Segment Size": np.mean(bwd_lens) if bwd_lens else 0,
        "Fwd Header Length.1": fwd_header_len,
        "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0, # Placeholders for bulk metrics
        "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": len(fwd_pkts), "Subflow Fwd Bytes": sum(fwd_lens),
        "Subflow Bwd Packets": len(bwd_pkts), "Subflow Bwd Bytes": sum(bwd_lens),
        "Init_Win_bytes_forward": win_bytes_fwd, "Init_Win_bytes_backward": win_bytes_bwd,
        "act_data_pkt_fwd": sum(1 for p in fwd_pkts if payload_len(p) > 0),
        "min_seg_size_forward": min((p['TCP'].dataofs * 4 for p in fwd_pkts if p.haslayer('TCP')), default=0),
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, # Inactivity profiles require multi-burst captures
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0
    }
    computed_flows.append(feat)

if computed_flows:
    df = pd.DataFrame(computed_flows)

    log = pd.read_csv("logs/attack_log.csv")
    print("flows :", df["flow_start_epoch"].min(), "->", df["flow_start_epoch"].max())
    print("log   :", log["start_epoch"].min(), "->", log["end_epoch"].max())
    print(df["Destination Port"].value_counts().head(10))

    t0, t1 = df["flow_start_epoch"].min(), df["flow_start_epoch"].max()
    covered = log[(log.end_epoch >= t0 - 2) & (log.start_epoch <= t1 + 2)]
    print(covered[["attack_type", "start_epoch", "end_epoch", "target_port"]])

    df["Label"] = label_flows(df, "logs/attack_log.csv")
    df = df.drop(columns=["flow_start_epoch"])

    df.to_csv(output_csv, index=False)
    print(f"Success. Constructed {len(df)} entries matching the full CIC-IDS 2017 schema.")
    print(f"File stored safely at: {os.path.abspath(output_csv)}")
