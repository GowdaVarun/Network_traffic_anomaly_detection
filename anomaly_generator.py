import random
import datetime

def generate_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_anomaly_packets(count=10):
    anomalies = []

    for _ in range(count):
        anomalies.append({
            "timestamp": datetime.datetime.utcnow(),
            "src_ip": generate_ip(),
            "dst_ip": generate_ip(),
            "src_port": random.choice([0, 1, 22, 23, 3389, 8080, 31337]),  # suspicious
            "dst_port": random.choice([0, 1, 22, 23, 80, 443, 8080]),
            "protocol": random.choice(["TCP", "UDP", "ICMP", "UNKNOWN"]),
            "flags": random.choice(["0x002", "0x000", "0xFFF"]),  # SYN, null, strange
            "length": random.choice([0, 20, 65535]),
            "ttl": random.choice([1, 2, 255]),  # too low or max
            "window_size": random.choice([0, 1, 65535]),
            "label": "bad"
        })

    return anomalies