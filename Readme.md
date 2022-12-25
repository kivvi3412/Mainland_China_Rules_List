> 为解决使用绕过中国大陆列表规则访问时，某些国内应用依旧显示为代理IP  
> 此程序可以自定义添加IP段，根据域名自动转化为IP段，然后添加到规则中  
> 最后生成规则文件，供使用 shunt_rule/rules 目录下
>

- IPv6 自定义不能自动添加，但可以自动生成配置文件
- AppleMap Domains 直连解决大陆模式下无法使用AppleMap的问题

   ```text
  # Solve AppleMap in mainland China cannot be used
   cdn.apple-mapkit.com
   configuration.ls.apple.com
   gs-loc.apple.com
   gsp-ssl.ls.apple.com
   gsp64-ssl.ls.apple.com
   gspe1-ssl.ls.apple.com
   gspe12-ssl.ls.apple.com
   gspe19-ssl.ls.apple.com
   gspe21-ssl.ls.apple.com
   gspe35-ssl.ls.apple.com
   gspe76-ssl.ls.apple.com
   i-resv.meituan.com
   m.hotmail.com
   mesu.apple.com
   p218-mailws.icloud.com.cn
   ```

| 设备            | Link                                                                                                              |
|---------------|-------------------------------------------------------------------------------------------------------------------|
| OpenWrt IPv4  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/openwrt_ipv4.txt      |
| OpenWrt IPv6  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/openwrt_ipv6.txt      |
| OpenWrt Apple | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/apple.china.conf      |
| Shadowrocket  | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/shadowrocket_mix.conf |
| Surge         | https://raw.githubusercontent.com/kivvi3412/Mainland_China_Rules_List/main/shunt_rule/rules/surge_mix.txt         |