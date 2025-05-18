import pyshark
import pandas as pd
import os
from collections import deque
import time
import logging
from anomaly_generator import generate_anomaly_packets

logging.basicConfig(level=logging.INFO)

BATCH_SIZE = 100
packet_window = deque(maxlen=BATCH_SIZE)
EXPORT_FILE = "captured_packets.csv"
ANOMALY_INJECT_INTERVAL = 5  # seconds

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

    try:
        for packet in cap.sniff_continuously():
            current_time = time.time()

            if current_time - start_time > duration:
                break

            # Real packet capture
            features = extract_features(packet)
            if features:
                packet_window.append(features)

            # Periodic anomaly injection
            if current_time - last_injection > ANOMALY_INJECT_INTERVAL:
                anomaly_packets = generate_anomaly_packets(count=10)
                export_to_csv(anomaly_packets)
                last_injection = current_time
                logging.info("🔴 Injected anomaly packets")

            # Export window when full
            if len(packet_window) == BATCH_SIZE:
                export_to_csv(list(packet_window))
                packet_window.clear()

    except KeyboardInterrupt:
        print("Monitoring Interrupted.")
    finally:
        cap.close()
        print("Monitoring Ended.")

if __name__ == "__main__":
    start_capture()