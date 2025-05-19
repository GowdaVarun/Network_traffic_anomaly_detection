import pyshark
import pandas as pd
import os
from collections import deque
import time
import logging
# from anomaly_generator import generate_anomaly_packets
from sklearn.preprocessing import LabelEncoder
import joblib
import ipaddress

logging.basicConfig(level=logging.INFO)

BATCH_SIZE = 100
packet_window = deque(maxlen=BATCH_SIZE)
EXPORT_FILE = "captured_packets.csv"
ANOMALY_INJECT_INTERVAL = 10  # seconds

def ip_to_int(ip):
    try:
        return int(''.join([f"{int(i):03}" for i in ip.split('.')]))
    except:
        return 0

def extract_features(packet):
    try:
        return {
            "timestamp": getattr(packet, 'sniff_time', pd.Timestamp.utcnow()),
            "src_ip": packet.ip.src if hasattr(packet, 'ip') else "0.0.0.0",
            "dst_ip": packet.ip.dst if hasattr(packet, 'ip') else "0.0.0.0",
            "src_port": int(packet[packet.transport_layer].srcport) if hasattr(packet, 'transport_layer') and hasattr(packet[packet.transport_layer], 'srcport') else 0,
            "dst_port": int(packet[packet.transport_layer].dstport) if hasattr(packet, 'transport_layer') and hasattr(packet[packet.transport_layer], 'dstport') else 0,
            "protocol": packet.transport_layer if hasattr(packet, 'transport_layer') else "UNKNOWN",
            "flags": getattr(packet.tcp, 'flags', '') if hasattr(packet, 'tcp') else '',
            "length": int(packet.length) if hasattr(packet, 'length') else 0,
            "ttl": int(packet.ip.ttl) if hasattr(packet, 'ip') and hasattr(packet.ip, 'ttl') else 0,
            "window_size": int(packet.tcp.window_size) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size') else 0,
            "label": "good"
        }
    except Exception as e:
        logging.warning(f"Feature Extraction Failed: {e}")
        return None

def export_to_csv(packets, filename=EXPORT_FILE):
    df = pd.DataFrame(packets)
    df.to_csv(filename, mode='a', header=not os.path.exists(filename), index=False)
    logging.info(f"Exported {len(packets)} packets to {filename}")

def start_capture(interface="wlp1s0", duration=300):
    cap = pyshark.LiveCapture(interface=interface)
    print("Real-time Packet Monitoring Started...")
    start_time = time.time()
    last_injection = time.time()
    # Clear the captured_packets.csv file if it exists
    if os.path.exists(EXPORT_FILE):
        with open(EXPORT_FILE, 'w') as f:
            pass
        logging.info(f"Cleared the contents of {EXPORT_FILE}")
    try:
        for packet in cap.sniff_continuously():
            current_time = time.time()

            if current_time - start_time > duration:
                break

            # Real packet capture
            features = extract_features(packet)
            if features:
                packet_window.append(features)

            # # Periodic anomaly injection
            # if current_time - last_injection > ANOMALY_INJECT_INTERVAL:
            #     anomaly_packets = generate_anomaly_packets(count=10)
            #     export_to_csv(anomaly_packets)
            #     last_injection = current_time
            #     logging.info("🔴 Injected anomaly packets")

            # Export window when full
            if len(packet_window) == BATCH_SIZE:
                export_to_csv(list(packet_window))
                packet_window.clear()

    except KeyboardInterrupt:
        print("Monitoring Interrupted.")
    finally:
        cap.close()
        print("Monitoring Ended.")
        create_cleaned_csv()
# this should be working before EL
#VARUN AND SUMADHVA'S PART 

#UPDATED LOGIC HERE .....->>>>

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import KMeans
import numpy as np

def create_cleaned_csv(raw_csv_path="captured_packets.csv", clean_csv_path="cleaned_packets.csv"):
    if not os.path.exists(raw_csv_path):
        raise FileNotFoundError(f"Raw CSV file {raw_csv_path} not found!")

    logging.info(f"Processing raw packet data from {raw_csv_path}")
    
    try:
        df_raw = pd.read_csv(raw_csv_path, header=0)
    except Exception as e:
        raise ValueError(f"Failed to read raw CSV: {e}")

    logging.info(f"Loaded raw data with {len(df_raw)} rows")

    required_columns = [
        'timestamp', 'src_ip', 'dst_ip',
        'src_port', 'dst_port', 'protocol',
        'flags', 'length', 'ttl', 'window_size', 'label'
    ]
    if list(df_raw.columns) != required_columns:
        df_raw.columns = required_columns  # fallback if no header in file

    df_clean = pd.DataFrame()
    df_clean['timestamp'] = df_raw['timestamp']
    
    def ip_to_int_safe(ip):
        try:
            return int(ipaddress.IPv4Address(str(ip)))
        except Exception as e:
            logging.warning(f"Bad IP: {ip} ({e})")
            return 0

    df_clean['src_ip'] = df_raw['src_ip'].apply(ip_to_int_safe)
    df_clean['dst_ip'] = df_raw['dst_ip'].apply(ip_to_int_safe)
    df_clean['src_port'] = pd.to_numeric(df_raw['src_port'], errors='coerce').fillna(0).astype(int)
    df_clean['dst_port'] = pd.to_numeric(df_raw['dst_port'], errors='coerce').fillna(0).astype(int)

    protocol_encoder = LabelEncoder()
    df_clean['protocol'] = protocol_encoder.fit_transform(df_raw['protocol'].astype(str))
    joblib.dump(protocol_encoder, 'protocol_encoder.joblib')

    df_clean['flags'] = df_raw['flags'].apply(
        lambda x: int(str(x), 16) if str(x).startswith('0x') else x
    )
    df_clean['flags'] = pd.to_numeric(df_clean['flags'], errors='coerce').fillna(0).astype(int)

    df_clean['length'] = pd.to_numeric(df_raw['length'], errors='coerce').fillna(0).astype(int)
    df_clean['ttl'] = pd.to_numeric(df_raw['ttl'], errors='coerce').fillna(0).astype(int)
    df_clean['window_size'] = pd.to_numeric(df_raw['window_size'], errors='coerce').fillna(0).astype(int)

    df_clean['label'] = df_raw['label'].astype(str).str.lower().map({"good": 0, "bad": 1})
    df_clean = df_clean.dropna(subset=['label'])

    zero_ip = ip_to_int_safe("0.0.0.0")
    df_clean = df_clean[~((df_clean['src_ip'] == zero_ip) & (df_clean['label'] == 0))]
    df_clean = df_clean[~((df_clean['dst_ip'] == zero_ip) & (df_clean['label'] == 0))]


    df_clean = df_clean.dropna()

    if df_clean.empty:
        logging.warning("No valid rows after cleaning. CSV will not be saved.")
        return

    # ========== UNSUPERVISED ANOMALY DETECTION ==========
    df_features = df_clean.drop(columns=["timestamp", "label"])
    models = {
        "IsolationForest": IsolationForest(contamination=0.1, random_state=42),
        "OneClassSVM": OneClassSVM(nu=0.1, kernel="rbf"),
        "LOF": LocalOutlierFactor(n_neighbors=20, contamination=0.1),
        "KMeans": KMeans(n_clusters=2, random_state=42)
    }

    unsupervised_preds = pd.DataFrame(index=df_features.index)

    for name, model in models.items():
        try:
            if name == "LOF":
                preds = model.fit_predict(df_features)
            else:
                preds = model.fit(df_features).predict(df_features)

            if name in ["IsolationForest", "OneClassSVM", "LOF"]:
                preds = np.where(preds == -1, 1, 0)
            elif name == "KMeans":
                counts = np.bincount(preds)
                anomaly_cluster = np.argmin(counts)
                preds = np.where(preds == anomaly_cluster, 1, 0)

            unsupervised_preds[name] = preds
        except Exception as e:
            logging.warning(f"{name} failed: {e}")

    # Voting: If 2 or more models agree it's an anomaly
    df_clean["possible_anomaly"] = np.where(unsupervised_preds.sum(axis=1) >= 2, "yes", "no")
    # ========== END UNSUPERVISED ==========
    
    try:
        df_clean.to_csv(clean_csv_path, index=False)
        logging.info(f"Saved cleaned data with anomaly results to {clean_csv_path}, rows: {len(df_clean)}")
    except Exception as e:
        logging.error(f"Failed to write cleaned CSV: {e}")
        raise



if __name__ == "__main__":
    start_capture()