"""Small bidirectional flow accumulator used by live packet capture.

Only directly measured features are provided. It is not a CICFlowMeter clone;
models requiring other features must not silently treat them as measured values.
"""
from dataclasses import dataclass
from statistics import mean, stdev, variance


@dataclass(frozen=True, eq=False)
class FlowKey:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def _identity(self):
        endpoints = sorted(((self.src_ip, self.src_port), (self.dst_ip, self.dst_port)))
        return self.protocol, tuple(endpoints)

    def __hash__(self):
        return hash(self._identity())

    def __eq__(self, other):
        return isinstance(other, FlowKey) and self._identity() == other._identity()


def _stats(values):
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return max(values), min(values), mean(values), stdev(values) if len(values) > 1 else 0.0


class NetworkFlow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol, timestamp):
        self.src_ip, self.dst_ip = src_ip, dst_ip
        self.src_port, self.dst_port, self.protocol = src_port, dst_port, protocol
        self.start_time = self.end_time = timestamp
        self.fwd_packets, self.bwd_packets = [], []

    def add_packet(self, src_ip, packet_size, timestamp, header_length, tcp_flags, window_size, src_port=None):
        packet = (float(timestamp), int(packet_size), int(header_length), dict(tcp_flags), int(window_size))
        (self.fwd_packets if (src_ip == self.src_ip and (src_port is None or src_port == self.src_port)) else self.bwd_packets).append(packet)
        self.start_time = min(self.start_time, timestamp)
        self.end_time = max(self.end_time, timestamp)

    def get_features(self):
        forward, backward = self.fwd_packets, self.bwd_packets
        packets = sorted(forward + backward, key=lambda p: p[0])
        duration = max(0.0, (self.end_time - self.start_time) * 1_000_000)
        result = {
            'Destination Port': self.dst_port,
            'Protocol': self.protocol,
            'Flow Duration': duration,
            'Total Fwd Packets': len(forward),
            'Total Backward Packets': len(backward),
            'Total Length of Fwd Packets': sum(p[1] for p in forward),
            'Total Length of Bwd Packets': sum(p[1] for p in backward),
            'Flow Bytes/s': sum(p[1] for p in packets) * 1_000_000 / duration if duration else 0.0,
            'Flow Packets/s': len(packets) * 1_000_000 / duration if duration else 0.0,
            'Fwd Header Length': sum(p[2] for p in forward),
            'Bwd Header Length': sum(p[2] for p in backward),
            'Fwd Packets/s': len(forward) * 1_000_000 / duration if duration else 0.0,
            'Bwd Packets/s': len(backward) * 1_000_000 / duration if duration else 0.0,
        }
        for prefix, rows in [('Fwd Packet Length', forward), ('Bwd Packet Length', backward), ('Packet Length', packets)]:
            vals = [p[1] for p in rows]
            for suffix, value in zip(('Max', 'Min', 'Mean', 'Std'), _stats(vals)):
                result[f'{prefix} {suffix}'] = value
            if prefix == 'Packet Length':
                result['Packet Length Variance'] = variance(vals) if len(vals) > 1 else 0.0
        for prefix, rows in [('Flow IAT', packets), ('Fwd IAT', forward), ('Bwd IAT', backward)]:
            times = sorted(p[0] for p in rows)
            diffs = [(b - a) * 1_000_000 for a, b in zip(times, times[1:])]
            for suffix, value in zip(('Max', 'Min', 'Mean', 'Std'), _stats(diffs)):
                result[f'{prefix} {suffix}'] = value
            if prefix != 'Flow IAT':
                result[f'{prefix} Total'] = sum(diffs)
        for flag in ('FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'CWR', 'ECE'):
            result[f'{flag} Flag Count'] = sum(bool(p[3].get(flag)) for p in packets)
        return result
