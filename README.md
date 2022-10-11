# libspb
通用SPA协议报，支持发送或监听TCP/UDP类型的SPA客户端以及服务器。提供了对接IAM回调接口。内嵌iptables+ipset。实现开放端口访问权限。
目前SPA服务器需部署在拥有ipset/iptables的环境中。
目前SPA报文加密方式支持raw/aes128/aes192/aes256/sm2/sm3/sm4。
