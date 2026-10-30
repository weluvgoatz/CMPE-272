import os
import numpy as np
import pandas as pd
from scapy.all import rdpcap

# avoids permission denied error
input_pcap = 'captures/benign_traffic.pcap'
output_csv = 'flows_output.csv' # saves directly to current project folder

def get_flow_key(pkt):
    if not pkt.haslayer('IP'):
        return None
    src_ip = pkt['IP'].src
    dst_ip = pkt['IP'].dst
    proto = pkt['IP'].proto
    if pkt.haslayer('TCP'):
        src_port = pkt['TCP'].sport
        dst_port = pkt['TCP'].dport
    elif pkt.haslayer('UDP'):
        src_port = pkt['UDP'].sport
        dst_port = pkt['UDP'].dport
    else:
        src_port, dst_port = 0, 0
        
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, dst_ip, src_port, dst_port, proto), "fwd"
    else:
        return (dst_ip, src_ip, dst_port, src_port, proto), "bwd"

print("Loading PCAP file...")
try:
    packets = rdpcap(input_pcap)
    print(f"Loaded {len(packets)} packets. Mapping full CIC-IDS 2017 feature matrix...")
except Exception as e:
    print(f"Error: {e}")
    exit(1)

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

computed_flows = []

for key, data in raw_flows.items():
    src_ip, dst_ip, src_port, dst_port, proto = key
    fwd_pkts, bwd_pkts = data["fwd"], data["bwd"]
    all_times = sorted(data["all_times"])
    
    # 1. Packet Counts & Lengths
    fwd_lens = [len(p) for p in fwd_pkts]
    bwd_lens = [len(p) for p in bwd_pkts]
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
            win_bytes_fwd = p['TCP'].window
            if F & 0x01: fwd_flags["FIN"] += 1; flags["FIN"] += 1
            if F & 0x02: fwd_flags["SYN"] += 1; flags["SYN"] += 1
            if F & 0x04: fwd_flags["RST"] += 1; flags["RST"] += 1
            if F & 0x08: fwd_flags["PSH"] += 1; flags["PSH"] += 1
            if F & 0x10: fwd_flags["ACK"] += 1; flags["ACK"] += 1
            if F & 0x20: fwd_flags["URG"] += 1; flags["URG"] += 1
            if len(p['TCP'].payload) > 0: fwd_act_data_pkts += 1

    for p in bwd_pkts:
        if p.haslayer('TCP'):
            F = p['TCP'].flags
            win_bytes_bwd = p['TCP'].window
            if F & 0x01: bwd_flags["FIN"] += 1; flags["FIN"] += 1
            if F & 0x02: bwd_flags["SYN"] += 1; flags["SYN"] += 1
            if F & 0x04: bwd_flags["RST"] += 1; flags["RST"] += 1
            if F & 0x08: bwd_flags["PSH"] += 1; flags["PSH"] += 1
            if F & 0x10: bwd_flags["ACK"] += 1; flags["ACK"] += 1
            if F & 0x20: bwd_flags["URG"] += 1; flags["URG"] += 1

    # 4. Header Segments
    fwd_header_len = sum([len(p['IP']) - len(p['IP'].payload) for p in fwd_pkts if p.haslayer('IP')])
    bwd_header_len = sum([len(p['IP']) - len(p['IP'].payload) for p in bwd_pkts if p.haslayer('IP')])

    # 5. Build Complete Feature Set
    feat = {
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
        "Fwd IAT Mean": np.mean(fwd_iats), "Fwd IAT Std": np.std(fwd_iats), "Fwd IAT Max": max(fwd_iats), "Fwd IAT Min": min(fwd_iats),
        "Bwd IAT Mean": np.mean(bwd_iats), "Bwd IAT Std": np.std(bwd_iats), "Bwd IAT Max": max(bwd_iats), "Bwd IAT Min": min(bwd_iats),
        "Fwd PSH Flags": fwd_flags["PSH"], "Bwd PSH Flags": bwd_flags["PSH"],
        "Fwd URG Flags": fwd_flags["URG"], "Bwd URG Flags": bwd_flags["URG"],
        "Fwd Header Length": fwd_header_len, "Bwd Header Length": bwd_header_len,
        "Fwd Packets/s": (len(fwd_pkts) / duration) if duration > 0 else 0, "Bwd Packets/s": (len(bwd_pkts) / duration) if duration > 0 else 0,
        "Min Packet Length": min(all_lens) if all_lens else 0, "Max Packet Length": max(all_lens) if all_lens else 0,
        "Packet Length Mean": np.mean(all_lens) if all_lens else 0, "Packet Length Std": np.std(all_lens) if all_lens else 0, "Packet Length Variance": np.var(all_lens) if all_lens else 0,
        "FIN Flag Count": flags["FIN"], "SYN Flag Count": flags["SYN"], "RST Flag Count": flags["RST"], "PSH Flag Count": flags["PSH"],
        "ACK Flag Count": flags["ACK"], "URG Flag Count": flags["URG"], "CWR Flag Count": flags["CWR"], "ECE Flag Count": flags["ECE"],
        "Down/Up Ratio": (len(bwd_pkts) / len(fwd_pkts)) if len(fwd_pkts) > 0 else 0,
        "Average Packet Size": (sum(all_lens) / len(all_lens)) if all_lens else 0,
        "Avg Fwd Segment Size": np.mean(fwd_lens) if fwd_lens else 0, "Avg Bwd Segment Size": np.mean(bwd_lens) if bwd_lens else 0,
        "Fwd Header Length.1": fwd_header_len,
        "Fwd Avg Bytes/Bulk": 0, "Fwd Avg Packets/Bulk": 0, "Fwd Avg Bulk Rate": 0, # Placeholders for bulk metrics
        "Bwd Avg Bytes/Bulk": 0, "Bwd Avg Packets/Bulk": 0, "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": len(fwd_pkts), "Subflow Fwd Bytes": sum(fwd_lens),
        "Subflow Bwd Packets": len(bwd_pkts), "Subflow Bwd Bytes": sum(bwd_lens),
        "Init_Win_bytes_forward": win_bytes_fwd, "Init_Win_bytes_backward": win_bytes_bwd,
        "act_data_pkt_fwd": fwd_act_data_pkts,
        "min_seg_size_forward": min([len(p) for p in fwd_pkts]) if fwd_pkts else 0,
        "Active Mean": 0, "Active Std": 0, "Active Max": 0, "Active Min": 0, # Inactivity profiles require multi-burst captures
        "Idle Mean": 0, "Idle Std": 0, "Idle Max": 0, "Idle Min": 0,

        "Label": "BENIGN"
    }
    computed_flows.append(feat)

if computed_flows:
    df = pd.DataFrame(computed_flows)
    df.to_csv(output_csv, index=False)
    print(f"Success. Constructed {len(df)} entries matching the full CIC-IDS 2017 schema.")
    print(f"File stored safely at: {os.path.abspath(output_csv)}")
