# EasyCA
golang语言实现的简易CA

# Usage
```
Usage: easyCA [-hI] [-new] [-ecc] [-CN commonName] [-d days]

Options:
  -CN string
    	CommonName，证书绑定域名, 与-c命令搭配使用
  -I	初始化项目，新建CA证书
  -d int
    	证书有效期, 与-c命令搭配使用 (default 365)
  -ecc
    	是否创建ECC类型的证书, 与-c命令搭配使用
  -f pkcs1
    	私钥文件格式，支持pkcs1和`pkcs8` (default "pkcs1")
  -h	Show this Help
  -new
    	签发证书

Example:
   easyCA -I                          初始化项目
   easyCA -new -CN foo.jdcloud.local  创建CommonName为foo.jdcloud.local的服务器端证书


```
