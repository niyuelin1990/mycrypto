mycrypto
====

##简介
搜罗各种加密算法
 
##电子邮件传输算法
 Base64

##摘要算法
 MD2，MD5；SHA-256，SHA-348，SHA-512；HMAC；RipeMD系列，Tiger，Whirpoll，GOST3411以及 HmacRipeMD系列
 HMAC包括HmacMD2，HmacMD5，HmacMD4；HmacSHA1，HmacSHA256，HmacSHA384，HmacSHA512，
 CRC

##对称加密
 DES、3DES、AES、IDEA， PBE
 目前AES加密未被破解，为有效算法

##非对称加密
 RSA、ElGamal、椭圆曲线系列算法，DH算法
 DH算法：需要在%JRE_HOME%\lib\security 替换local_policy.jar和US_export_policy.jar

##数字签名
 RSA，DSA，ECDSA
 DAS和ECDSA源自离散对数问题。RSA应用最广泛,ECDSA更安全

##数字证书
 数字证书最常用非对称算法是RSA算法，签名算法SHA1withRSA，消息摘要SHA1
 X509标准
 PKCS（Public-Key Cryptography Standards）由RSA指定的一系列标准

##国密系列
 国产密码算法（国密算法）是指国家密码局认定的国产商用密码算法，
 在金融领域目前主要使用公开的SM2、SM3、SM4三类算法，分别是非对称算法、哈希算法和对称算法。