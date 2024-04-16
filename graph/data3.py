from scapy.all import sniff, TCP, IP
import time
import math
import socket
import statistics
import pandas as pd
import numpy as np

def get_wifi_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        print("Error:", e)
        return None

source_ip = get_wifi_ip_address()

dur = 30

ip_stats_map = {}
packet_timestamps = []
idle_times = []
tot_packet_len = 0
packet_len_arr = []
packet_mean = 0
packet_min = 1e9
packet_max = 0
packet_std = 0
min_idle_time = 1e9
idle_std = 0
flow_bytes_sec = 0
fwd_arr = []
tot_fwd_packet = 0
packet_count=0

def packet_callback(packet):
    global tot_packet_len, packet_len_arr, packet_mean, packet_min, packet_max, packet_std, packet_timestamps, idle_times, min_idle_time
    global idle_std, flow_bytes_sec, fwd_arr, tot_fwd_packet,packet_count

    packet_len = len(packet)
    tot_packet_len += packet_len
    packet_count+=1

    packet_timestamps.append(packet.time)
    if len(packet_timestamps) > 2:
        idle_times = [packet_timestamps[i] - packet_timestamps[i - 1] for i in range(0, len(packet_timestamps))]
        min_idle_time = min(idle_times)
        idle_std = statistics.stdev(idle_times)
    else:
        idle_std = 0

    flow_bytes_sec = tot_packet_len / dur

    packet_info = {
        "timestamp": packet.time,
        "length": packet_len,
    }

    avg_packet_size=tot_packet_len/packet_count

    if IP in packet and packet[IP].src == source_ip:
        dest_ip = packet[IP].dst

        if dest_ip in ip_stats_map:
            ip_stats_map[dest_ip]["max_length"] = max(ip_stats_map[dest_ip]["max_length"], packet_len)
            ip_stats_map[dest_ip]["min_length"] = min(ip_stats_map[dest_ip]["min_length"], packet_len)
            ip_stats_map[dest_ip]["packet_lengths"].append(packet_len)

            num_segments = ip_stats_map[dest_ip]["num_segments"] + 1
            ip_stats_map[dest_ip]["num_segments"] = num_segments

            total_segments_size = ip_stats_map[dest_ip]["total_segments_size"] + packet_len
            ip_stats_map[dest_ip]["total_segments_size"] = total_segments_size

            avg_fwd_segment_size = total_segments_size / num_segments
            ip_stats_map[dest_ip]["avg_fwd_segment_size"] = avg_fwd_segment_size

            total_forwarded_length = ip_stats_map[dest_ip].get("forward_packet_length_tot", 0) + packet_len
            ip_stats_map[dest_ip]["forward_packet_length_tot"] = total_forwarded_length

            fwd_sum_squared_diff = sum((length - avg_fwd_segment_size) ** 2 for length in ip_stats_map[dest_ip]["packet_lengths"])
            fwd_variance = fwd_sum_squared_diff / num_segments
            fwd_std_deviation = math.sqrt(fwd_variance)
            ip_stats_map[dest_ip]["forward_packet_length_std"] = fwd_std_deviation

            ip_stats_map[dest_ip]["packet_length_std"] = fwd_std_deviation

            ip_stats_map[dest_ip]["packet_length_variance"]=fwd_variance
            ip_stats_map[dest_ip]["fwd_packets_per_sec"] = num_segments / dur

            ip_stats_map[dest_ip]["packet_length_mean"] = total_segments_size / num_segments

            ip_stats_map[dest_ip]["idle_min"] = min_idle_time
            ip_stats_map[dest_ip]["idle_std"] = idle_std

            ip_stats_map[dest_ip]["flow_bytes_per_sec"] = flow_bytes_sec

            ip_stats_map[dest_ip]["down_up_ratio"] = ip_stats_map[dest_ip]["count_bwd_packet"] / num_segments
            ip_stats_map[dest_ip]["average_packet_size"]=avg_packet_size
            
            ip_stats_map[dest_ip]["flow_packets_per_sec"]=packet_count/dur
            ip_stats_map[dest_ip]["packets_fwd"].append(packet_info)

            ip_stats_map[dest_ip]["packet_fwd_per_sec"].append({"timestamp": packet.time, "fwd_packets_per_sec": ip_stats_map[dest_ip]["fwd_packets_per_sec"]})
           

        else:
            ip_stats_map[dest_ip] = {
                "Destination port": packet[TCP].dport if TCP in packet else 0,
                "max_length": packet_len,
                "min_length": packet_len,
                "packet_lengths": [packet_len],

                "backward_packet_length_mean": 0,
                "min_backward_length": 1e9,
                "max_backward_length":0,
                "backward_packet_length_tot": 0,
                "backward_packet_length_std": 0,
                "count_bwd_packet": 0,
                "backward_packet_per_sec":0,
                "avg_bwd_segment_size":0,

                "avg_fwd_segment_size": packet_len,
                "forward_packet_length_tot": packet_len,
                "forward_packet_length_std": 0,
                "fwd_packets_per_sec": packet_len / dur,

                "num_segments": 1,
                "total_segments_size": packet_len,

                "packet_length_mean": packet_len,
                "down_up_ratio": 0,
                "packet_length_std": 0,
                "packet_length_variance":0,
                "packets_fwd": [packet_info],
                "packets_bwd": [],
                "idle_min": packet.time,
                "idle_std": 0,
                "average_packet_size": avg_packet_size,
                "flow_bytes_per_sec": packet_len / dur,
                "flow_packets_per_sec": packet_count/dur,
                "packet_fwd_per_sec": [{"timestamp": packet.time, "fwd_packets_per_sec": 1/dur }],
               
            }

    if IP in packet and packet[IP].dst == source_ip:
        src_ip = packet[IP].src
        packet_length = len(packet)

        if src_ip in ip_stats_map:
            ip_stats_map[src_ip]["min_backward_length"] = min(ip_stats_map[src_ip]["min_backward_length"], packet_length)
            ip_stats_map[src_ip]["max_backward_length"] = max(ip_stats_map[src_ip]["max_backward_length"], len(packet))
            count_bwd_pck = ip_stats_map[src_ip]["count_bwd_packet"] + 1
            ip_stats_map[src_ip]["count_bwd_packet"] = count_bwd_pck

            total_backward_length = ip_stats_map[src_ip]["backward_packet_length_tot"] + packet_length
            ip_stats_map[src_ip]["backward_packet_length_tot"] = total_backward_length

            ip_stats_map[src_ip]["backward_packet_length_mean"] = total_backward_length / count_bwd_pck

            sum_squared_diff = sum((length - total_backward_length / count_bwd_pck) ** 2 for length in ip_stats_map[src_ip]["packet_lengths"])
            variance = sum_squared_diff / count_bwd_pck
            std_deviation = math.sqrt(variance)
            ip_stats_map[src_ip]["backward_packet_length_std"] = std_deviation
            
            ip_stats_map[src_ip]["backward_packet_per_sec"] = count_bwd_pck / dur

            avg_bwd_segment_size = total_backward_length / count_bwd_pck
            ip_stats_map[src_ip]["avg_bwd_segment_size"] = avg_bwd_segment_size

            ip_stats_map[src_ip]["packets_bwd"].append(packet_info)

# Start sniffing on the default interface, capturing packets indefinitely
sniff(prn=packet_callback, timeout=dur, iface='Ethernet')

if '1.2.3.4' in ip_stats_map:
    ip_stats_map.pop('1.2.3.4')

ip=[]
for key, value in ip_stats_map.items():
    ip.append(key)



def get_max_packet_lengths(ip_stats_map):
    max_packet_lengths = {}
    for ip, stats in ip_stats_map.items():
        max_length = stats.get("max_length", 0)
        if max_length > 0:
            max_packet_lengths.setdefault("Max packet length", []).append(max_length)
    return max_packet_lengths

def get_bwd_max_packet_lengths(ip_stats_map):
    bwd_max_packet_lengths = {}
    for ip, stats in ip_stats_map.items():
        max_backward_lengt = stats.get("max_backward_length", 0)
        if max_backward_lengt >= 0:
            bwd_max_packet_lengths.setdefault("max_backward_length", []).append(max_backward_lengt)
    return bwd_max_packet_lengths

def get_avg_fwd_segment_size(ip_stats_map):
    avg_fwd_segment_sizes = {}
    for ip, stats in ip_stats_map.items():
        avg_fwd_segment_size = stats.get("avg_fwd_segment_size")
        if avg_fwd_segment_size is not None:
            avg_fwd_segment_sizes.setdefault("avg fwd segment size", []).append(avg_fwd_segment_size)
    return avg_fwd_segment_sizes

def get_avg_bwd_segment_size(ip_stats_map):
    avg_bwd_segment_sizes = {}
    for ip, stats in ip_stats_map.items():
        avg_bwd_segment_size = stats.get("avg_bwd_segment_size")
        if avg_bwd_segment_size is not None:
            avg_bwd_segment_sizes.setdefault("avg_bwd_segment_size", []).append(avg_bwd_segment_size)
    return avg_bwd_segment_sizes


def get_bwd_packet_length_min(ip_stats_map):
    bwd_packet_length_min_dict = {}
    for ip, stats in ip_stats_map.items():
        bwd_packet_length_min = stats.get("min_backward_length")
        if bwd_packet_length_min:
            bwd_packet_length_min_dict.setdefault("min_backward_length", []).append(bwd_packet_length_min)
    return bwd_packet_length_min_dict

def get_packet_length_mean(ip_stats_map):
    packet_length_means = {}
    for ip, stats in ip_stats_map.items():
        packet_length_mean = stats.get("packet_length_mean")
        if packet_length_mean is not None:
            packet_length_means.setdefault("packet_length_mean",[]).append(packet_length_mean)
    return packet_length_means

def get_packet_length_std(ip_stats_map):
    packet_length_std_dict = {}
    for ip, stats in ip_stats_map.items():
        packet_length_std = stats.get("packet_length_std")
        if packet_length_std is not None:
            packet_length_std_dict.setdefault("packet_length_std",[]).append(packet_length_std)
    return packet_length_std_dict

def get_total_length_fwd_packets(ip_stats_map):
    total_length_fwd_packet_dict = {}
    for ip, stats in ip_stats_map.items():
        total_length_fwd_packet = stats.get("forward_packet_length_tot")
        if total_length_fwd_packet is not None:
            total_length_fwd_packet_dict.setdefault("total_length_fwd_packet",[]).append(total_length_fwd_packet)
    return total_length_fwd_packet_dict

def get_total_length_bwd_packets(ip_stats_map):
    total_length_bwd_packet_dict = {}
    for ip, stats in ip_stats_map.items():
        total_length_bwd_packet = stats.get("backward_packet_length_tot")
        if total_length_bwd_packet is not None:
            total_length_bwd_packet_dict.setdefault("total_length_bwd_packet",[]).append(total_length_bwd_packet)
    return total_length_bwd_packet_dict

def get_bwd_packet_length_std(ip_stats_map):
    bwd_packet_length_std_dict = {}
    for ip, stats in ip_stats_map.items():
        bwd_packet_length_std = stats.get("backward_packet_length_std")
        if bwd_packet_length_std is not None:
            bwd_packet_length_std_dict.setdefault("bwd_packet_length_std",[]).append(bwd_packet_length_std)
    return bwd_packet_length_std_dict

def get_fwd_packet_length_std(ip_stats_map):
    fwd_packet_length_std_dict = {}
    for ip, stats in ip_stats_map.items():
        fwd_packet_length_std = stats.get("forward_packet_length_std")
        if fwd_packet_length_std is not None:
            fwd_packet_length_std_dict.setdefault("fwd_packet_length_std",[]).append(fwd_packet_length_std)
    return fwd_packet_length_std_dict

def get_fwd_packets_per_sec(ip_stats_map):
    fwd_packets_per_sec_dict = {}
    for ip, stats in ip_stats_map.items():
        fwd_packets_per_sec = stats.get("fwd_packets_per_sec")
        if fwd_packets_per_sec is not None:
            fwd_packets_per_sec_dict.setdefault("fwd_packets_per_sec",[]).append(fwd_packets_per_sec)
    return fwd_packets_per_sec_dict

def get_flow_bytes_per_sec(ip_stats_map):
    flow_bytes_per_sec_dict = {}
    for ip, stats in ip_stats_map.items():
        flow_bytes_per_sec = stats.get("flow_bytes_per_sec")
        if flow_bytes_per_sec is not None:
            flow_bytes_per_sec_dict.setdefault("flow_bytes_per_sec",[]).append(flow_bytes_per_sec)
    return flow_bytes_per_sec_dict

def get_bwd_packet_per_sec(ip_stats_map):
    bwd_packet_per_sec_dict={}
    for ip, stats in ip_stats_map.items():
        bwd_packet_per_sec= stats.get("backward_packet_per_sec")
        if bwd_packet_per_sec is not None:
           bwd_packet_per_sec_dict.setdefault("bwd_packet_per_sec",[]).append(bwd_packet_per_sec) 
    return bwd_packet_per_sec_dict

def get_dest_port(ip_stats_map):
    dest_port_dict = {}
    for ip, stats in ip_stats_map.items():
        dest_port = stats.get("Destination port")  # Use .get() method to avoid KeyError
        if dest_port is not None:
           dest_port_dict.setdefault("dest_port", []).append(dest_port)
    return dest_port_dict

def get_avg_packet_size(ip_stats_map):
    avg_packet_size_dict = {}
    for ip, stats in ip_stats_map.items():
        avg_packet_size = stats.get("average_packet_size")
        if avg_packet_size is not None:
            avg_packet_size_dict.setdefault("avg_packet_size", []).append(avg_packet_size) 
    return avg_packet_size_dict

def get_packet_length_variance(ip_stats_map):
    packet_length_variance_dict = {}
    for ip, stats in ip_stats_map.items():
        packet_length_variance = stats.get("packet_length_variance")
        if packet_length_variance is not None:
            packet_length_variance_dict.setdefault("packet_length_variance", []).append(packet_length_variance) 
    return packet_length_variance_dict


def get_flow_packets_per_sec(ip_stats_map):
    flow_packets_per_sec_dict = {}
    for ip, stats in ip_stats_map.items():
        flow_packets_per_sec = stats.get("flow_packets_per_sec")
        if flow_packets_per_sec is not None:
            flow_packets_per_sec_dict.setdefault("flow_packets_per_sec", []).append(flow_packets_per_sec) 
    return flow_packets_per_sec_dict

avg_bwd_segment_size=get_avg_bwd_segment_size(ip_stats_map).get('avg_bwd_segment_size', [])
bwd_packet_per_sec=get_bwd_packet_per_sec(ip_stats_map).get('bwd_packet_per_sec', [])
dest_port=get_dest_port(ip_stats_map).get('dest_port', [])
Max_packet_length=get_max_packet_lengths(ip_stats_map).get('Max packet length',[])
max_backward_length=get_bwd_max_packet_lengths(ip_stats_map).get('max_backward_length',[])
packet_length_std=get_packet_length_std(ip_stats_map).get('packet_length_std',[])
packet_length_mean=get_packet_length_mean(ip_stats_map).get('packet_length_mean',[])
avg_packet_size=get_avg_packet_size(ip_stats_map).get('avg_packet_size',[])
packet_length_variance=get_packet_length_variance(ip_stats_map).get('packet_length_variance',[])
bwd_packet_length_std=get_bwd_packet_length_std(ip_stats_map).get('bwd_packet_length_std',[])
total_length_fwd_packet=get_total_length_fwd_packets(ip_stats_map).get('total_length_fwd_packet',[])
flow_bytes_per_sec=get_flow_bytes_per_sec(ip_stats_map).get('flow_bytes_per_sec',[])
avg_fwd_segment_size=get_avg_fwd_segment_size(ip_stats_map).get('avg fwd segment size',[])
total_length_bwd_packet=get_total_length_bwd_packets(ip_stats_map).get('total_length_bwd_packet',[])
flow_packets_per_sec=get_flow_packets_per_sec(ip_stats_map).get('flow_packets_per_sec',[])

# print(len(avg_bwd_segment_size))
# print(len(bwd_packet_per_sec))
# print(len(dest_port))
# print(len(Max_packet_length))
# print(len(max_backward_length))
# print(len(packet_length_std))
# print(len(packet_length_mean))
# print(len(avg_packet_size))
# print(len(packet_length_variance))
# print(len(bwd_packet_length_std))
# print(len(total_length_fwd_packet))
# print(len(flow_bytes_per_sec))
# print(len(total_length_bwd_packet))
# print(len(flow_packets_per_sec))

dict={
    ' Avg Bwd Segment Size':avg_bwd_segment_size,
    ' Bwd Packets/s': bwd_packet_per_sec,
    ' Destination Port': dest_port,
    ' Max Packet Length': Max_packet_length,
    ' Bwd Packet Length Max':max_backward_length ,
    ' Packet Length Std':packet_length_std ,
    ' Packet Length Mean': packet_length_mean,
    ' Average Packet Size':avg_packet_size,
    ' Packet Length Variance':packet_length_variance ,
    ' Bwd Packet Length Std':bwd_packet_length_std ,
    ' Total Length of Fwd Packets':total_length_fwd_packet ,
    ' Flow Bytes/s':flow_bytes_per_sec,
    ' Avg Fwd Segment Size':avg_fwd_segment_size ,
    ' Total Length of Bwd Packets': total_length_bwd_packet,
    ' Flow Packets/s':flow_packets_per_sec,
}

df=pd.DataFrame(dict)
#print(df)