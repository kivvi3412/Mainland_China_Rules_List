# -*- coding: utf-8 -*-
import pandas as pd
import ipaddress

# 下载网址: https://lite.ip2location.com/china-ip-address-ranges?lang=en_US
# 加载CSV文件
file_path = 'ip-cidr-storage/IP2LOCATION-LITE-DB1.CSV'  # 替换为您的文件路径
ip_data = pd.read_csv(file_path, header=None)

# 筛选出中国的IP地址范围
china_ip_data = ip_data[ip_data[2] == 'CN'].copy()


# 转换函数：将数字格式的IP地址范围转换为CIDR格式
def convert_to_cidr(ip_from, ip_to):
    start_ip = ipaddress.ip_address(ip_from)
    end_ip = ipaddress.ip_address(ip_to)
    return [str(cidr) for cidr in ipaddress.summarize_address_range(start_ip, end_ip)]


# 应用转换
china_ip_data.loc[:, 'CIDR'] = china_ip_data.apply(lambda row: convert_to_cidr(row[0], row[1]), axis=1)

# 格式化输出并写入文件
formatted_cidr_list = ["IP-CIDR," + cidr for sublist in china_ip_data['CIDR'] for cidr in sublist]
output_file_path = 'ip-cidr-storage/ip-cidr.txt'  # 替换为您的输出文件路径
with open(output_file_path, 'w') as file:
    for cidr in formatted_cidr_list:
        file.write(cidr + '\n')
