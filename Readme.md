>为解决使用绕过中国大陆列表规则访问时，某些国内应用依旧显示为代理IP  
>此程序可以自定义添加IP段，根据域名自动转化为IP段，然后添加到规则中  
>最后生成规则文件，供使用 shunt_rule/rules 目录下  
>
-  IPv6 自定义不能自动添加，但可以自动生成配置文件
- 添加了AppleMap的域名请求conf, 解决了在中国大陆模式下无法使用AppleMap的问题

| 设备            | Link                                                                                                              |
|---------------|-------------------------------------------------------------------------------------------------------------------|
| OpenWrt IPv4  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/openwrt_ipv4.txt      |
| OpenWrt IPv6  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/openwrt_ipv6.txt      |
| OpenWrt Apple | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/apple.china.conf      |
| Shadowrocket  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/shadowrocket_mix.conf |
| Surge         | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/surge_mix.txt         |