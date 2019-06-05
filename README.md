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
  -p	签发证书的私钥文件是否需要密码保护

Example:
   easyCA -I -d 3650                  初始化项目
   easyCA -new -CN foo.jdcloud.local  创建CommonName为foo.jdcloud.local的服务器端证书

```

# Example
```
[root❄anhk:easyCA]☭ ./easyCA -new -CN www.test.com -ecc -f pkcs8 -p
Enter Key Passphrase for ./pki/private/ca.key:
Enter New Key Passphrase:
Re-Enter New Key Passphrase:
创建私钥文件: ./pki/issued/www.test.com-20190430175936-4v5wr8xc.key
创建证书文件: ./pki/issued/www.test.com-20190430175936-4v5wr8xc.crt
[root❄anhk:easyCA]☭

```

# 更新CA证书到操作系统【来自互联网】

## Ubuntu
### 添加证书
```
sudo cp ./pki/ca.crt /usr/local/share/ca-certificates/my-ca.crt
sudo update-ca-certificates
```
### 移除证书
```
sudo rm -fr /usr/local/share/ca-certificates/my-ca.crt
sudo update-ca-certificates --fresh
```

## CentOS
### 添加证书
```
sudo cp ./pki/ca.crt /etc/pki/ca-trust/source/anchors
sudo update-ca-trust 
```
### 移除证书
```
```
