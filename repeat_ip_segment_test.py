# -*- coding: utf-8 -*-
import time
from intervaltree import IntervalTree
import ipaddress
from tqdm import tqdm

file_path = 'shunt_rule/rules/openwrt_ipv4.txt'

with open(file_path, 'r') as file:
    ip_segments = file.read().splitlines()

# 创建IP段对象列表
ip_networks = [ipaddress.ip_network(ip) for ip in ip_segments]

# 创建区间树
interval_tree = IntervalTree()

time1 = time.time()
# 将IP段作为区间添加到树中
print('Adding IP segments to interval tree...')
for ip in tqdm(ip_networks):
    start = int(ip.network_address)
    end = int(ip.broadcast_address)
    # 检查区间是否为空（即起始和结束地址是否相同）
    if start != end:
        interval_tree[start:end] = ip

# 查找重叠的IP段
print('Finding overlapping IP segments...')
overlapping_intervals = set()
for interval in tqdm(interval_tree):
    overlaps = interval_tree.overlap(interval.begin, interval.end)
    for overlap in overlaps:
        if overlap != interval:
            sorted_pair = tuple(sorted([str(interval.data), str(overlap.data)]))
            overlapping_intervals.add(sorted_pair)

# 转换为列表并排序
overlapping_ip_segments = list(overlapping_intervals)
overlapping_ip_segments.sort()
time2 = time.time()
print("重复IP段: ", overlapping_ip_segments)
print("总共用时: ", time2 - time1)
