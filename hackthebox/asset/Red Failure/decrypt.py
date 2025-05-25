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
        print("Usage: python3 decrypt_9tVI0.py <input_file> <output_file>")
        print("Example: python3 decrypt_9tVI0.py 9tVI0.bin decrypted.bin")
        sys.exit(1)
    
    password = "z64&Rx27Z$B%73up"
    
    if not decrypt_9tVI0(sys.argv[1], sys.argv[2], password):
        print("[!] Please check:")
        print("1. Does File input exist")
        print("2. Is password correct")