import ipaddress
import os
import re
import time
import requests
import dns.resolver


class rule_operator(object):
    def __init__(self):
        self.history_file_ipv4 = "shunt_rule/history/ipv4_latest.txt"
        self.history_file_ipv6 = "shunt_rule/history/ipv6_latest.txt"
        self.ipv4_list = []
        self.ipv6_list = []
        self.read_history()

    def read_history(self) -> (list, list):
        with open(self.history_file_ipv4, 'r') as f:
            self.ipv4_list = f.read().split("\n")
        with open(self.history_file_ipv6, 'r') as f:
            self.ipv6_list = f.read().split("\n")
        return self.ipv4_list, self.ipv6_list

    def write_history(self, ipv4_list, ipv6_list):
        ipv4_list = list(set(ipv4_list))
        ipv6_list = list(set(ipv6_list))
        ipv4_list.sort()
        ipv6_list.sort()
        ipv4_list_text = "\n".join(ipv4_list)
        ipv6_list_text = "\n".join(ipv6_list)
        # 原来的文件更新名字为 时间+ipv4/ipv6
        os.rename(self.history_file_ipv4,
                  "shunt_rule/history/" + time.strftime("%Y%m%d%H%M%S", time.localtime()) + "_ipv4.txt")
        os.rename(self.history_file_ipv6,
                  "shunt_rule/history/" + time.strftime("%Y%m%d%H%M%S", time.localtime()) + "_ipv6.txt")
        with open(self.history_file_ipv4, 'w') as f:  # 写入新的文件
            f.writelines(ipv4_list_text)
        with open(self.history_file_ipv6, 'w') as f:
            f.writelines(ipv6_list_text)

    # 检测ip是否在ip段中
    def detect_ip_in_net(self, ip: str) -> list:
        try:  # 检测是ipv4还是ipv6
            ipv4_ip = re.findall(r"\d+\.\d+\.\d+\.\d+", ip)
            ipv6_ip = re.findall(
                r"(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$)",
                ip)
            if ipv4_ip:
                ipv4_ip = ipaddress.IPv4Address(ip)
                for ipv4_list_net in self.ipv4_list:
                    ipv4_net = ipaddress.IPv4Network(ipv4_list_net)
                    if ipv4_net.__contains__(ipv4_ip):
                        return [ipv4_list_net]
                return []
            elif ipv6_ip:
                ipv6_ip = ipaddress.IPv6Address(ip)
                for ipv6_list_net in self.ipv6_list:
                    ipv6_net = ipaddress.IPv6Network(ipv6_list_net)
                    if ipv6_net.__contains__(ipv6_ip):
                        return [ipv6_list_net]
                return []
            else:
                return []
        except Exception as e:
            print(e)
            return []

    def add_ip_net(self, ip_net_list: list) -> list:
        try:
            for ip_net in ip_net_list:
                ipv4_net = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", ip_net)
                ipv6_net = re.findall(
                    r"(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*/\d{1,2})",
                    ip_net)
                if ipv4_net:
                    self.ipv4_list.append(ipv4_net[0])
                elif ipv6_net:
                    self.ipv6_list.append(ipv6_net[0][0])
            self.write_history(self.ipv4_list, self.ipv6_list)
            return ip_net_list
        except Exception as e:
            print(e)
            return []

    def del_ip_net(self, ip_list: list) -> list:
        try:
            for ip in ip_list:
                ipv4_ip = re.findall(r"\d+\.\d+\.\d+\.\d+", ip)
                ipv6_ip = re.findall(
                    r"(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$)",
                    ip)
                if ipv4_ip:
                    ipv4_net = self.detect_ip_in_net(ip)
                    if ipv4_net:
                        [self.ipv4_list.remove(i) for i in ipv4_net]
                elif ipv6_ip:
                    ipv6_net = self.detect_ip_in_net(ip)
                    if ipv6_net:
                        [self.ipv6_list.remove(i) for i in ipv6_net]
            self.write_history(self.ipv4_list, self.ipv6_list)
            return ip_list
        except Exception as e:
            print(e)
            return []


class ip_info_searcher(object):
    @staticmethod
    def get_ipv4_info_from_url(ipv4_ip_list: list) -> list:
        ipv4_network_info_list = []
        try:
            for ipv4_ip in ipv4_ip_list:
                url = 'https://ip.bczs.net/' + ipv4_ip
                response = requests.get(url).text
                need_add_ip_segment_def = re.findall(
                    r'((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)) - ((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))',
                    response)
                if not need_add_ip_segment_def:
                    need_add_ip_segment_def = re.findall(
                        r'((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))-((25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|[1-9])\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))',
                        response)

                country = re.findall(r"所属国家/地区：<code>(.*?)</code>", response)
                area_name = re.findall(r"区域名称：<code>(.*?)</code>", response)
                ip_net_name = re.findall(r"<br>IP段名称：(.*?)<br>", response)
                router_info = re.findall(r"路由信息：<code>(.*?)</code>", response)

                start_ip_obj = ipaddress.IPv4Address(need_add_ip_segment_def[0][0])
                end_ip_obj = ipaddress.IPv4Address(need_add_ip_segment_def[0][5])
                ip_range_obj = ipaddress.summarize_address_range(start_ip_obj, end_ip_obj)
                ip_address_range = [str(i) for i in ip_range_obj][0]

                ipv4_network_info = {
                    "ip": ipv4_ip,
                    "country": None if not country else country[0],
                    "area_name": None if not area_name else area_name[0],
                    "ip_net_name": None if not ip_net_name else ip_net_name[0],
                    "router_info": None if not router_info else router_info[0],
                    "ip_address_range": ip_address_range
                }
                ipv4_network_info_list.append(ipv4_network_info)

            return ipv4_network_info_list

        except Exception as e:
            print(e)
            return []

    @staticmethod
    def query_dns(domain: str, q_type: str) -> list:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['119.29.29.29', "223.5.5.5", "2402:4e00::"]  # 支持多服务器，设置dns服务器地址
            answer_obj = resolver.resolve(domain, q_type)

            return [str(ip) for ip in answer_obj]
        except Exception as e:
            print('Network is unreachable ' + str(e))
            return []


class rule_file_generator(object):
    def __init__(self):
        self.ipv4_list, self.ipv6_list = rule_operator().read_history()
        self.ipv4_list_text = "\n".join(self.ipv4_list)
        self.ipv6_list_text = "\n".join(self.ipv6_list)
        self.openwrt_ipv4_file = "shunt_rule/rules/openwrt_ipv4.txt"
        self.openwrt_ipv6_file = "shunt_rule/rules/openwrt_ipv6.txt"
        self.shadowrocket_mix_file = "shunt_rule/rules/shadowrocket_mix.conf"
        self.surge_mix_file = "shunt_rule/rules/surge_mix.txt"

    def generate_all(self):
        self.openwrt_rule_generator()
        self.shadowrocket_rule_generator()
        self.surge_rule_generator()

    def openwrt_rule_generator(self):
        with open(self.openwrt_ipv4_file, "w") as f:
            f.write(self.ipv4_list_text)
        with open(self.openwrt_ipv6_file, "w") as f:
            f.write(self.ipv6_list_text)

    def shadowrocket_rule_generator(self):
        file_head = '''[General]\nbypass-system = true\nskip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local, captive.apple.com\ntun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32\ndns-server = system\nipv6 = true\nprefer-ipv6 = false\ndns-fallback-system = false\ndns-direct-system = false\nicmp-auto-reply = true\nalways-reject-url-rewrite = false\nprivate-ip-answer = true\ndns-direct-fallback-proxy = true\n\n[Rule]\n'''
        file_tail = '''FINAL,PROXY\n\n[Host]\nlocalhost = 127.0.0.1\n\n[URL Rewrite]\n^https?://(www.)?g.cn https://www.google.com 302\n^https?://(www.)?google.cn https://www.google.com 302\n'''
        shadowrocket_ipv4_rule = '\n'.join("IP-CIDR," + i + ',DIRECT' for i in self.ipv4_list)
        shadowrocket_ipv6_rule = '\n'.join("IP-CIDR6," + i + ',DIRECT' for i in self.ipv6_list)
        with open(self.shadowrocket_mix_file, "w") as f:
            f.write(file_head + shadowrocket_ipv4_rule + "\n" + shadowrocket_ipv6_rule + "\n" + file_tail)

    def surge_rule_generator(self):
        surge_ipv4_rule = '\n'.join("IP-CIDR," + i + ',DIRECT' for i in self.ipv4_list)
        surge_ipv6_rule = '\n'.join("IP-CIDR6," + i + ',DIRECT' for i in self.ipv6_list)
        with open(self.surge_mix_file, "w") as f:
            f.write(surge_ipv4_rule + "\n" + surge_ipv6_rule)


class Menu(object):
    def __init__(self):
        self.menu = {
            "1": "查询测试添加IP或域名",
            "2": "手动添加网段到规则",
            "3": "删除规则中的IP或域名",
            "4": "生成规则文件",
            "5": "退出程序"
        }
        self.ipv4_list, self.ipv6_list = rule_operator().read_history()  # 读取历史记录
        self.rule_operator = rule_operator()  # 规则操作类
        self.ip_info_searcher = ip_info_searcher()  # IP信息查询类
        self.rule_file_generator = rule_file_generator()  # 规则文件生成类

    def menu_display(self):
        while True:
            print()
            for k, v in self.menu.items():
                print("\t", k, v)
            print()
            choice = input("-> ")
            if choice == "1":
                self.menu_1()
            elif choice == "2":
                self.menu_2()
            elif choice == "3":
                self.menu_3()
            elif choice == "4":
                self.menu_4()
            elif choice == "5":
                break
            else:
                print("输入错误，请重新输入")
            input("Press Enter to continue...")

    def menu_1(self):
        domain_or_ip = input("请输入IP或域名\n-> ")
        ip_info = self.domain_or_ip_to_info(domain_or_ip)
        self.print_domain_or_ip_info(ip_info)
        if any([i["rule"] for i in ip_info]):
            print("以上IP在规则中, 无需添加")
        else:
            if input("是否添加? (y/n)\n-> ").lower() == "y":
                if input("添加router_info or ip_address_range? (r/i)\n-> ").lower() == "r":
                    self.rule_operator.add_ip_net([i["router_info"] for i in ip_info if i["router_info"]])
                else:
                    self.rule_operator.add_ip_net([i["ip_address_range"] for i in ip_info if i["ip_address_range"]])
                print("添加成功")
            else:
                print("取消添加")

    def menu_2(self):
        ip_net = input("请输入IP网段, 例如:192.168.1.1/24\n-> ")
        if self.rule_operator.add_ip_net([ip_net]):
            print("添加成功")
        else:
            print("添加失败")

    def menu_3(self):
        domain_or_ip = input("请输入IP或域名\n-> ")
        ip_info = self.domain_or_ip_to_info(domain_or_ip)
        self.print_domain_or_ip_info(ip_info)
        if any([i["rule"] for i in ip_info]):
            if input("是否删除? (y/n)\n-> ").lower() == "y":
                if self.rule_operator.del_ip_net([i["ip"] for i in ip_info if i["rule"]]):
                    print("删除成功")
                else:
                    print("删除失败")
            else:
                print("取消删除")
        else:
            print("以上IP不在规则中, 无需删除")

    def menu_4(self):
        self.rule_file_generator.generate_all()
        print("生成成功")

    def domain_or_ip_to_info(self, domain_or_ip: str) -> list:
        ip_list = []
        try:
            ipaddress.ip_address(domain_or_ip)
            ip_list.append(domain_or_ip)
        except ValueError:
            ip_list = self.ip_info_searcher.query_dns(domain_or_ip, "A")
        ip_info = self.ip_info_searcher.get_ipv4_info_from_url(ip_list)
        for ip_info_dict in ip_info:  # 检查是否在规则中
            ip_detect_result = self.rule_operator.detect_ip_in_net(ip_info_dict["ip"])
            if ip_detect_result:
                ip_info_dict["rule"] = ip_detect_result[0]
            else:
                ip_info_dict["rule"] = None
        return ip_info

    @staticmethod
    def print_domain_or_ip_info(ip_info: list):
        for ip_info_dict in ip_info:
            info = ""
            for k, v in ip_info_dict.items():
                info += "\t" + k.ljust(20) + str(v) + "\n"
            print(info)


if __name__ == '__main__':
    Menu().menu_display()
