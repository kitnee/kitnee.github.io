---
title: "TTV CTF — Forensics Writeups"
description: "Tổng hợp 3 writeup TTV CTF: Wolfenstein, Paper Airplane, \"disk\"ombobulate."
pubDate: 2026-03-08
lang: vi
category: writeup
ctf: "TTV CTF"
tags:
  - "Writeup"
  - "Forensics"
  - "TTV"
  - "DFIR"
---

## Wolfenstein

### 1. Analysis
* **Given:** a pcapng file named `Register` and a mini dump crash file named `Register.DMP`
* **Description:** Agent Hitler đang trong quá trình điều tra một vụ án. Trong quá trình thực hiện nhiệm vụ, chiếc máy cá nhân của đặc vụ này đã bị xâm nhập. Bạn có thể giúp điều tra không.

* **Hints:**   
    * No hints are given

### 2. Investigation
#### THE FIRST PART
Started with the `Register.pcapng`, after a few scrolls, I found some HTTP traffics (only stream 3), looked like base64 but maybe it was xored or something else.

The server is `NimPlant C2 Server` (first time heard it btw - I did 1 chall about C2 before but it was `Havoc`), so I did some investigation and directed to `https://github.com/chvancooten/NimPlant`.

Of course I aint read all that so here something abt `NimPlant`: Essentially, NimPlant is a lightweight, first-stage C2 (Command & Control) framework. Attackers use it as an initial foothold to establish a connection between the victim's machine and their server.

I also found a `nimplant.py` , there's a function called `get_xor_key`:
```python
def get_xor_key(force_new=False):
    """Get the XOR key for pre-crypto operations."""
    if os.path.isfile(".xorkey") and not force_new:
        file = open(".xorkey", "r", encoding="utf-8")
        xor_key = int(file.read())
    else:
        print("Generating unique XOR key for pre-crypto operations...")
        print(
            "NOTE: Make sure the '.xorkey' file matches if you run the server elsewhere!"
        )
        xor_key = random.randint(0, 2147483647)
        with open(".xorkey", "w", encoding="utf-8") as file:
            file.write(str(xor_key))

    return xor_key
```
this will get a random number from 0 to 2147483647 for `pre-crypto operations`, however I didnt find any crypto functions on the `server`, so I tried to find it on the `client`. And there is one func named `crypto.nim`:
```python

import nimcrypto, base64, random
from strutils import strip

# Calculate the XOR of a string with a certain key
# This function is explicitly intended for use for pre-key exchange crypto operations (decoding key)
proc xorString*(s: string, key: int): string {.noinline.} =
    var k = key
    result = s
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
        k = k +% 1

# XOR a string to a sequence of raw bytes
# This function is explicitly intended for use with the embedded config file (for evasion)
proc xorStringToByteSeq*(str: string, key: int): seq[byte] {.noinline.} =
    let length = str.len
    var k = key
    result = newSeq[byte](length)

    # Bitwise copy since we can't use 'copyMem' since it will be called at compile-time
    for i in 0 ..< result.len:
        result[i] = str[i].byte

    # Do the XOR
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = uint8(result[i]) xor uint8((k shr f) and 0xFF)
        k = k +% 1

# XOR a raw byte sequence back to a string
proc xorByteSeqToString*(input: seq[byte], key: int): string {.noinline.} =
    let length = input.len
    var k = key

    # Since this proc is used at runtime, we can use 'copyMem'
    result = newString(length)
    copyMem(result[0].unsafeAddr, input[0].unsafeAddr, length)

    # Do the XOR and convert back to character
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
        k = k +% 1

# Get a random string
proc rndStr(len : int) : string =
    randomize()
    for _ in 0..(len-1):
        add(result, char(rand(int('A') .. int('z'))))

# Converts a string to the corresponding byte sequence.
# https://github.com/nim-lang/Nim/issues/14810
func convertToByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

# Converts a byte sequence to the corresponding string.
func convertToString(bytes: openArray[byte]): string {.inline.} =
    let length = bytes.len
    if length > 0:
        result = newString(length)
        copyMem(result[0].unsafeAddr, bytes[0].unsafeAddr, length)

# Decrypt a blob of encrypted data with the given key
proc decryptData*(blob: string, key: string): string =
    let 
        blobBytes = convertToByteSeq(decode(blob))
        iv = blobBytes[0 .. 15]
    var
        enc = newSeq[byte](blobBytes.len)
        dec = newSeq[byte](blobBytes.len)   
        keyBytes = convertToByteSeq(key)
        dctx: CTR[aes128]

    enc = blobBytes[16 .. ^1]
    dctx.init(keyBytes, iv)
    dctx.decrypt(enc, dec)
    dctx.clear()
    result = convertToString(dec).strip(leading=false, chars={'\0'})

# Encrypt a input string with the given key
proc encryptData*(data: string, key: string): string =
    let 
        dataBytes : seq[byte] = convertToByteSeq(data)
    var
        iv: string = rndStr(16)
        enc = newSeq[byte](len(dataBytes))
        dec = newSeq[byte](len(dataBytes))   
    dec = dataBytes
    var dctx: CTR[aes128]
    dctx.init(key, iv)
    dctx.encrypt(dec, enc)
    dctx.clear()
    result = encode(convertToByteSeq(iv) & enc)
```
NimPlant will use a random 32-bit xorkey to decrypt to real crypto method: `AES 128 CTR-mode`:
1. IV Generation: First up, the malware generates a random 16-byte string using the rndStr(16) function to act as the Initialization Vector (IV).
2. Encryption: Next, it takes the AES key (which was securely exchanged earlier thanks to the pre-crypto XOR layer) and pairs it with the IV to encrypt the raw JSON command.
3. Packaging & Base64 Encoding: Finally, it slaps the 16-byte IV right in front of the resulting Ciphertext, and encodes the entire data blob into Base64 to ensure safe transport over the network.

The final structure of the payload transmitted over HTTP looks like this: `Base64(IV[16 bytes] + AES_Ciphertext)`

So basically if I got the xorkey I will able to decrypt the AES key and then use that key to decrypt all the traffic. 

But I didnt find it. So I tried something new with `Register.DMP` file, I used a tools called `Detect it Easy` to investigate and extract all artifacts from the memory dump.

After that, I got some `.exe` file and some `.png` file, however I noticed two file heavier than the others, with the `.png` file I open it and got the first part of the flag:

![](/images/posts/ttv-ctf-wolfenstein/Register.DMP.02627f58_0006fe5f.png)

`BKSEC{h1tl3r_0nce_s4id_`

with the `.exe` one, I named `malice.exe`, uploaded the file to VirusTotal to analyze, the result is this file was written by `NimPlant`like the traffic I mentioned. 

I wasted so many times scroll through the logic of `NimPlant` to find whether the xorkey or the aeskey laid in the DMP file since that my only hope. So I literally decided to clone the `NimPlant` to my local machine and recreate the challenge. 

#### THE SECOND PART
After did some set up, I turned on `WireShark` to start capturing packets, then I ran:
```bash
python3 nimplant.py server
```
As soon as I turned on the server, I noticed a `.xorkey` file created in the folder, click on the `.exe` I compile with `python3 nimplant.py compile exe`, then I ran 2 commands: `shell whoami` and `screenshot`, I dump the `NimPlant.exe` in `Task Manager`, stop capturing packets and got the whole challenge recreated.

Then I noticed the `.xorkey` created as soon as the server run, definitely the author dont give me the file, so I focused entirely on the AESKEY which I sure gonna be in the .DMP file, I write a small script to get the AESKEY from my `k` captured and `.xorkey`:
```python
import base64

def calculate_aes_key(k_base64: str, xor_key: int) -> bytes:
    try:
        k_bytes = base64.b64decode(k_base64)
    except Exception as e:
        return None

    result = bytearray(k_bytes)
    k = xor_key

    for i in range(len(result)):
        for f in [0, 8, 16, 24]:
            key_byte = (k >> f) & 0xFF
            result[i] = result[i] ^ key_byte
        
        k = (k + 1) & 0xFFFFFFFF

    return bytes(result)

if __name__ == "__main__":
    k_from_pcap = "trXqvp3vqqatq7iqtbujlA==" 
    extracted_xor_key = 2022903838 

    aes_key = calculate_aes_key(k_from_pcap, extracted_xor_key)

    if aes_key:
        print(f"{aes_key}")
```
Got my AES_KEY which is `SQ1dD7uxpwkxdktB`, then I try grep this string in file `NimPlant.DMP` to confirm my suspicion.

```bash
strings `NimPlant.DMP` | grep "SQ1dD7uxpwkxdktB"
```

As I thought, the string is there.

![](/images/posts/ttv-ctf-wolfenstein/Screenshot_2026-03-07_233151.png)

So I got the logic: the AES_KEY is a 16-bytes base64 string is in the `Register.DMP` near the `listenerTaskPath` , I turned back to the chal, using

```bash
strings Register.DMP | grep '^.\{16\}$'
```

![](/images/posts/ttv-ctf-wolfenstein/Screenshot_2026-03-07_225630.png)

Of course I found the string: `Te9B2zIS74kYn1fj`

**Decode:** After got the string, I wrote a python script to decoded the traffic
```python
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import base64

    # The AES key
    AES_KEY_BYTES = b'Te9B2zIS74kYn1fj' 
    
    # The ciphertext
    CIPHERTEXT_B64 = "TE8sYGBAc3BTZ3VhLFlHaCEe71IiOn+MC4yr9zz+rH8pukSTqp/5LBTj+2qAbMWMXa9MuBA7GgKlSuhP8NNjaTTW3VRkOnrP0EWt5XyJ/G8UnXkfznreiURrlQTY4ClHXeRg6v+MA7EoLkCo4WuL/qPJ0Ewcj9YA1vwIXyCwEOf6IeEMBXca5xNX+ZuoZkjHXbcbBi8rdJxyJQ=="
    def decrypt_aes_ctr(ciphertext_b64, key_bytes):
        data = base64.b64decode(ciphertext_b64)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    decrypted_text_2 = decrypt_aes_ctr(CIPHERTEXT_B64, AES_KEY_BYTES)
    print(f"Result: {decrypted_text_2.decode('utf-8')}")

except Exception as e:
    print(f"Error: {e}")
```

After some decryption, I noticed an upload command before a gzip file was sent:
```bash
{"guid": "1jOOMBeZ", "command": "upload", "args": ["99c72e04845c4c85a2a1e124cdd079e3", "backdoor.exe", "C:\\Users\\Public\\backdoor.exe"]}
```

However the gzip encryption is quite different from the others so I wrote another python script to decode the `.exe`:
```python
import base64
import zlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

def decrypt_nimplant_upload(b64_blob: str, aes_key: bytes):
    try:
        raw_data = base64.b64decode(b64_blob)
    except Exception as e:
        print(f"Base64 Decoded Error: {e}")
        return None

    iv = raw_data[:16]
    ciphertext = raw_data[16:]

    iv_int = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv_int)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
    
    decrypted_bytes = cipher.decrypt(ciphertext)
    decrypted_bytes = decrypted_bytes.rstrip(b'\x00')

    try:
        plaintext = decrypted_bytes.decode('utf-8')
        print(plaintext)
        return plaintext
    except UnicodeDecodeError:
        try:
            # Decompressed
            decompressed_data = zlib.decompress(decrypted_bytes, wbits=zlib.MAX_WBITS | 32)            

            output_filename = "backdoor.exx"
            with open(output_filename, "wb") as f:
                f.write(decompressed_data)
            print(f"Saved: {output_filename}")
            
            return decompressed_data
        except zlib.error as ze:
            print(f"Error")
            return decrypted_bytes

if __name__ == "__main__":
    # Key
    AES_KEY_BYTES = b'Te9B2zIS74kYn1fj' 
    CIPHERTEXT_B64 = "ZG9Abz1EfmgpYF1gOFI3VXTOyJo2FJ8RI8UztG8t4tezYW+lTHRpGv93zb06EWBybrc+TKKsyqTuczPl+1oAeUXXeVOfkqyRPyDamM0Xi6JE0juS2lJV0BdZ761FLVhSd/m4vdCZVLLaXNwWYKaTWWb/0disXMIkkQzAGPnvCqZInnMC7j8CYsEqCdlq6AhlBZZikoRnTz950TWtfSFjgfVoNIhrGSLFMOCGQjA+motqddZhDwT+s4qkgukqONVaBFrL1l7V/ZUfkKjGMKckdnSLAVOHG+HZ+XY2nHCxzLkee8sRY74qyGkzTXil3bp+b2T0Em+Im6s2+00rWlOMr3r3t5p16q41drd88yCk/px93PRusVUtpk3jxU61sCLDmnwMNiqlmDmyuUG5kPFVNg8k/QUMsT4EaxIgwmj7p03Hrg70qa2dIvG4eOLgISMMZbUk8k6gvY+dL8bV5wrbWU1mJNq7KiX01apj6TLs8ax7AOLZQPea8YCzoAoCU+RbLOAcL0O/z9Rt0XRAhzCwo0UlhEkDk1H5Oq/...5ifciOkIZUb6"
    decrypt_upload(CIPHERTEXT_B64, AES_KEY_BYTES)
```
Then, I got the `backdoor.exe` file, to use `IDA Free` to decompile the file to readable pseudocode:
1. The `start` func call `sub_140001190`
2. The `sub_140001190` call `sub_140001698` which is `main`
3. In the `sub_140001698` I noticed this branch:
```c
if ( strcmp(v4, "--help") )
    {
      v7 = strcmp(v4, "0xDEADBEEF");
      if ( v7 )
      {
        sub_1400015E3("[!] Unknown command: %s\n", v4);
        puts("[*] Run with --help for usage.");
      }
      else
      {
        v8 = "PzM0BQxqNjEFPzM0BQhpMzkyBT8zNAUcLzIoaSh7Jw==";
        do
        {
          v28 = sub_1400015B6((unsigned int)*v8);
          v29 = sub_1400015B6((unsigned int)v8[1]);
          v30 = v8[2];
          if ( v30 == 61 )
            v26 = 0;
          else
            v26 = sub_1400015B6((unsigned int)v30);
          v31 = v8[3];
          if ( v31 == 61 )
            v27 = 0;
          else
            v27 = sub_1400015B6((unsigned int)v31);
          if ( (v29 | v28) < 0 )
            break;
          v32 = v7 + 1;
          *((_BYTE *)&v34 + v7) = (v29 >> 4) | (4 * v28);
          if ( v30 != 61 )
          {
            *((_BYTE *)&v34 + v32) = (v26 >> 2) | (16 * v29);
            v32 = v7 + 2;
          }
          if ( v31 == 61 )
          {
            v7 = v32;
          }
          else
          {
            v7 = v32 + 1;
            *((_BYTE *)&v34 + v32) = v27 | ((_BYTE)v26 << 6);
          }
          v8 += 4;
        }
        while ( v8 != "" );
        *((_BYTE *)&v34 + v7) = 0;
        for ( j = 0; v7 > (int)j; ++j )
          *((_BYTE *)&v34 + j) ^= 0x5Au;
        sub_1400015E3("[+] FLAG: %s\n", (const char *)&v34);
      }
      return 0;
    }
```

To sum up the code:
1. You are provided with an executable file. Running it normally or with random/incorrect arguments will result in an error.
2. To retrieve the flag, you must open a Terminal and execute the binary with the exact magic argument:
```bash
./backdoor.exe 0xDEADBEEF
```
3. Once executed with the correct argument, the program automatically triggers a decoding routine (Base64 Decode followed by a single-byte XOR with the key 0x5A) and prints out the result as [+] FLAG: ... .
   

`ein_V0lk_ein_R3ich_ein_Fuhr3r!}`


### 3. Solution
1. **Result:** The flag is `BKSEC{h1tl3r_0nce_s4id_ein_V0lk_ein_R3ich_ein_Fuhr3r!}`

---

## Paper Airplane

### Paper Airplane
### 1. Analysis
* **Given:** an url to Microsoft-look-alike `https://dboard.bksec.vn/1
* **Description:** Just a paper airplane.

* **Hints:**   
    * No hints are given

### 2. Investigation
#### The website phase
![](/images/posts/ttv-ctf-paper-airplane/Screenshot_2026-03-08_062551.png)

At first, I thought that this is a web chal since this is the first time I did a forensics chal in website.
Looked at the **Source**, I saw a suspicious file named `(index)`:
```html

    <!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8"/>
        <meta name="viewport" content="width=device-width,initial-scale=1"/>
        <title>Sign in to your account</title>
        <style>
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0
            }

            body {
                background: #f2f2f2;
                font-family: 'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center
            }

        ...
            function _0x3672() {
                var _0x6e65cc = ['mhvIm0PU', 'C3bSAxq', 'y2HHDf9Pza', 'ExnXwMC', 'zgfYAW', 'vMvOyLC', 'yMz5zgy', 'yxbWBhK', 'vujbqMC', 'BK1rEuC', 'x2DH', 'CMfUzg9T', 'mZuZnZK5mKjXse9yqq', 'rgzZqMy', 'CfDwtNO', 'E30Uy29UC3rYDq', 'r1Lczfq', 'D29pu2i', 'Bg9N', 'BMn0Aw9UkcKG', 'vuLqthC', 'BM93', 'Cfz0DMK', 'AMHiBuq', 'AMfgsM4', 'whr1Awm', 'z2LUlM1Py3jVCW', 'DMfSDwu', 'BMTOy1C', 'zxHJzxb0Aw9U', 'Aw5MBW', 'tKv4ywq', 'AgzKCha', 'tereEum', 'qNLjza', 'C2KTza', 'CKDVvLC', 'Ce1SwLi', 'rMnJuNa', 'ufP0tK4', 'sw1Wsge', 'm3WYFdf8nhWW', 'vueTmdaWmdaWlq', 'ugXLyxnLigvUDa', 'sw9KwhG', 'sNDMyvm', 'CMzQBNu', 'qMvtz0O', 'AffWwNa', 'u0HkDfy', 'Dg9tDhjPBMC', 'Dw91D3q', 'C3n3B3jKlG', 'te5Hsva', 'rhL4Dfi', 'shDmrLG', 'rfPxquu', 'qvvcvMi', 'pgi+w1bHCgvYqq', 'svf2rvu', 'CMv0DxjUicHMDq', 'z0zkBve', 'C3rYAw5NAwz5', 'sxzUwg8', 'z1rwy1K', 'wuXfqNi', 'nJyYm0HYu0XmDG', 't0XRuhu', 'yJ4k', 'zwXgq0q', 'C2nYAxb0', 'y29VA2LL', 'C2KTzq', 'C2KTyG', 'Fdr8mhWXma', 'yJ4G', 'DLz5AhC', 'AKHwD0i', 'vKP5DwG', 'B0DktMi', 'B3vXugG', 'qMPruhK', 'CfvxBKO', 'zLLwrxm', 'uNbvAg4', 'zxHTuhi', 'EKf2rK0', 'nda4mtmWrKLcuMrs', 'wNvQsxa', 'z2v0rwXLBwvUDa', 'Afnqy0G', 'BxbSCwS', 'rhfIDvC', 'u25qCwS', 'CM4GDgHPCYiPka', 'BgLKigvTywLSia', 'wMrgwgO', 'AxjWBgfUzv08lW', 'C2zKEfe', 'u3rsEvG', 'wuzktKi', 'ExrPy3m', 'uufNqNG', 'DNrXA04', 'vvnvDfO', 'y29UC3rYDwn0BW', 'Dgv4DenVBNrLBG', 'vwrUqNe', 'C2KTCa', 'wg95uuu', 'ALrPq20', 'AgfPrLm', 'BhjPzwC', 'Bg9JywXtDg9Yyq', 'AfHjChm', 'ChjLDMvUDerLzG', 'C2v0qxr0CMLIDq', 's0rXr04', 'qLLwB1G', 't0jKr1y', 'EMzpwgq', 'vu1pBLK', 'A3DfBMO', 'qM96v2e', 'Dgv4Da', 'wgXWt1G', 'zurWuxi', 'AeL4ANm', 'z2DRreS', 'tgT0Dg0', 'yuHsmgnittzmEq', 'DKrJrfi', 's0XPuvO', 'owHJr2T1', 'yM9KEq', 'zvr3D3O', 'mxWWFdr8nxWZFa', 'q1btsfG', 'C2KTDa', 'y2f0y2G', 'qvbIChq', 'u2LNBIbPBG', 'CMflChC', 'mhWZFdv8nhWXFa', 'qw5tCgC', 'Bg9JyxrPB24', 'DfDtCuy', 'CfvOzwe', 'zuLrzLO', 'rhfmrxK', 'u2DqwvC', 'C3r5Bgu', 'sNDqzMe', 'nxWXm3WXmxWXnq', 'CNLTyKu', 'tKLNwwG', 'zNPMsLy', 'uvrXtem', 'q29UDgvUDc1uEq', 'Ahr0Chm6lY93DW', 'sNDswge', 'EuDnrfC', 'wwrSEue', 'tfrlA1e', 'rg5nzwC', 'zxjYB3i', 'AhnOB3u', 'sfrnta', 'zMLSBa', 'B2z0B25SAw5LlG', 'uNvXDuO', 'zgLZywjSzwq', 'v1r3wMS', 'u25NzNi', 'r1z0vgG', 'l2i+ia', 'zNjVBunOyxjdBW', 'svLUtw0', 'CgfYC2vFBw9Kzq', 'mNWWFdv8m3W0Fa', 'qNHHug4', 'mtC3mZaWnevHswf0zW', 'AM9PBG', 'zuDKyLa', 'sMvNCu4', 'tevdyKK', 'C3jJ', 'C3vIBwL0', 'qujHs3m', 'zgLZCgXHEq', 'sKftDu8', 'CNnNDNe', 'DgHLBwu', 'A2v5', 'DxnLCKfNzw50', 'weHAvw0', 'C1nQAKm', 't3rMzgO', 'Cu9Qq1e', 'Cvblu1y', 'mxW0Fdj8nxWWFa', 'ALrOuKK', 'vfnUwu4', 'BI9QC29U', 'qwX6vMu', 'C2vZC2LVBLn0BW', 'BM9Uzq', 'B1fTCwO', 'twj6uKq', 'C2KTDq', 'yMXVy2S', 'DNH2D1y', 'C3rLBMvY', 'rfvgsgK', 'wvj0Aey', 'tfDZDNe', 'mNWXFdr8mhWZ', 'q3rSDhe', 'ywrKrxzLBNrmAq', 'qwvpDMK', 'EwHbzwm', 'vxjyA3O', 'ChvZAa', 'vKH5qMq', 'nZGXodCWnMX2ANfQqG', 'yKL2qxu', 'z0fvqwO', 'zM9JDxm', 'uM13vg0', 'C2v0', 'yxbWBgLJyxrPBW', 'DgfIBgu', 'y3jLyxrLrwXLBq', 'mJKXmZu5oeLIrxDPvG', 'wKnxD2i', 'CIWGB3iGu2T5Ca', 'q3z6CfO', 'tMrSzgS', 'rfDyrhO', 'mtHysvrvAwm', 'AgvHzgvYCW', 'CLDwzxe', 'wKXerg4', 'CKH3Ahe', 'z1zfBuC', 'z2v0sxrLBq', 'ugfNsNO', 'D2jKrw8', 'ChjVDg90ExbL', 'zLjQugS', 'EuvIwMm', 'zxiGEw91CIbWyq', 'A0DXvNu', 'm1LYA1rcAW', 'y29UC29Szq', 'm3W1Fdr8mhWYFa', 'vxvQAvO', 'twfyCu8', 'ugT6suO', 'qKXxCg4', 'rw50zxiGysb2yq', 'sMHswMq', 'svfpvuG', 'CKvhAwG', 'BgvUz3rO', 'uhvuthu', 'C2HPzNq', 'DuDiAwK', 'wvHfwhe', 'odrhzfzqBgC', 'sNfhtxe', 'yMzAC0O', 'zgf0ys10AgvTzq', 'D2TxCe0', 'Dvj1tuO', 'vLn2qNq', 'CgnXy3G', 'z2vjrxK', 'ufrxtLe', 'q25LwvO', 'ENDlvxK', 'qKvmA1a', 'zw50', 'y29Uy2f0', 'qNvgruO', 'uMH1Egm', 'q0zbDvu', 'yMLUza', 'rgDTuLe', 'uLzyB08', 'BMTVwMq', 'ywXMyKi', 'vg9kA3e', 'r1vdzg4', 'CMvTB3zLsxrLBq', 'rejKCxa', 's1vRrNO', 'vhjHsNq', 'uhjtrMK', 'BKX5zNi', 'zgjQq0u', 'C2vJ', 'tMvjDKK', 'sMDpENO', 'D2fYBG', 'r0nhA0i', 'yMztAhy', 'DwPItMG', 'EfrVq2K', 'C2KTC3a', 'wwHytNK', 'D3nHreu', 'y3rVCIGICMv0Dq', 'z2fmELC', 'Dez2q3K', 'wLD1Bee', 'x19ZDa', 'wvHTwu0', 'Bvr5yKy', 'vxHAvLC', 'vNjptee', 'ALfMtKS', 'EwDzAgW', 'BwfW', 'C2v0sxrLBq', 'sLnMt28', 'yxn5BMm', 'rhDwCwS', 'r2LVvKO', 'CujpBgm', 'y2HHCKnVzgvbDa', 'tNPzv2rS', 'mNWXFdr8nxWZFa', 'EwjIAKK', 'serRAeO', 'vxfowLi', 'yNLowvq', 'wendswC', 'C0zZuwe', 'vM15r1u', 'tdnoBgjTuK5Awa', 'Fdz8oxW4Fde0Fa', 'Ag9UzsbUDw1Izq', 'mZqXnJu1mdbwD0fTzuS', 'rezdruO', 'qxPxBuS', 'yuDitgC', 'rw50zxiGCgfZCW', 'qND1ruS', 'pgi+vue6pc9IpG', 'BLvmvKS', 'EhzHwfm', 'EhrrDMi', 'swDwtvm', 'yLjWzwK', 'Auj0zNK', 'zKPvvKy', 'tg5yvfm', 'vejfEeG', 'uM95D0e', 'C2KTzG', 'ywrKCMvZCYWGCa', 'qxfntgC', 'DhjHy2u', 'lMPZ', 'C050zva', 'CgfeA04', 'z1Ldz00', 'ANnVBG'];
                _0x3672 = function() {
                    return _0x6e65cc;
                }
                ;
                return _0x3672();
            }
        </script>
        <script defer src="https://static.cloudflareinsights.com/beacon.min.js/v8c78df7c7c0f484497ecbca7046644da1771523124516" integrity="sha512-8DS7rgIrAmghBFwoOTujcf6D9rXvH8xm8JQ1Ja01h9QX8EzXldiszufYa4IFfKdLUKTTrnSFXLDkUEOTrZQ8Qg==" data-cf-beacon='{"version":"2024.11.0","token":"da058bb71e544ef0859a788e8d4bcd3c","r":1,"server_timing":{"name":{"cfCacheStatus":true,"cfEdge":true,"cfExtPri":true,"cfL4":true,"cfOrigin":true,"cfSpeedBrain":true},"location_startswith":null}}' crossorigin="anonymous"></script>
    </body>
</html>
```

After some investigations and searchings, I found that this web related to a malware campaign stealing usernames and passwords. I uncovered a leaked `Telegram Bot Token` embedded within the site's components in strings such as `dGVsZWdyYW` which base64 -d will becomes `telegra`.

I tried to copy the file to my computer to test, since I know if i sent a submit, in the **network** tab, it will have a request look like this `https://api.telegram.org/bot<BOT_TOKEN>/sendMessage`, however when i tested, the console log declare fault.

So I try a new way:
1. Turn on a new tab, type `about:blank` in the address
2. I paste this script in the `console`:
```java
// 1. Decoded Array
var _0x6e65cc = ['mhvIm0PU', 'C3bSAxq', 'y2HHDf9Pza', 'ExnXwMC', 'zgfYAW', 'vMvOyLC', 'yMz5zgy', 'yxbWBhK', 'vujbqMC', 'BK1rEuC', 'x2DH', 'CMfUzg9T', 'mZuZnZK5mKjXse9yqq', 'rgzZqMy', 'CfDwtNO', 'E30Uy29UC3rYDq', 'r1Lczfq', 'D29pu2i', 'Bg9N', 'BMn0Aw9UkcKG', 'vuLqthC', 'BM93', 'Cfz0DMK', 'AMHiBuq', 'AMfgsM4', 'whr1Awm', 'z2LUlM1Py3jVCW', 'DMfSDwu', 'BMTOy1C', 'zxHJzxb0Aw9U', 'Aw5MBW', 'tKv4ywq', 'AgzKCha', 'tereEum', 'qNLjza', 'C2KTza', 'CKDVvLC', 'Ce1SwLi', 'rMnJuNa', 'ufP0tK4', 'sw1Wsge', 'm3WYFdf8nhWW', 'vueTmdaWmdaWlq', 'ugXLyxnLigvUDa', 'sw9KwhG', 'sNDMyvm', 'CMzQBNu', 'qMvtz0O', 'AffWwNa', 'u0HkDfy', 'Dg9tDhjPBMC', 'Dw91D3q', 'C3n3B3jKlG', 'te5Hsva', 'rhL4Dfi', 'shDmrLG', 'rfPxquu', 'qvvcvMi', 'pgi+w1bHCgvYqq', 'svf2rvu', 'CMv0DxjUicHMDq', 'z0zkBve', 'C3rYAw5NAwz5', 'sxzUwg8', 'z1rwy1K', 'wuXfqNi', 'nJyYm0HYu0XmDG', 't0XRuhu', 'yJ4k', 'zwXgq0q', 'C2nYAxb0', 'y29VA2LL', 'C2KTzq', 'C2KTyG', 'Fdr8mhWXma', 'yJ4G', 'DLz5AhC', 'AKHwD0i', 'vKP5DwG', 'B0DktMi', 'B3vXugG', 'qMPruhK', 'CfvxBKO', 'zLLwrxm', 'uNbvAg4', 'zxHTuhi', 'EKf2rK0', 'nda4mtmWrKLcuMrs', 'wNvQsxa', 'z2v0rwXLBwvUDa', 'Afnqy0G', 'BxbSCwS', 'rhfIDvC', 'u25qCwS', 'CM4GDgHPCYiPka', 'BgLKigvTywLSia', 'wMrgwgO', 'AxjWBgfUzv08lW', 'C2zKEfe', 'u3rsEvG', 'wuzktKi', 'ExrPy3m', 'uufNqNG', 'DNrXA04', 'vvnvDfO', 'y29UC3rYDwn0BW', 'Dgv4DenVBNrLBG', 'vwrUqNe', 'C2KTCa', 'wg95uuu', 'ALrPq20', 'AgfPrLm', 'BhjPzwC', 'Bg9JywXtDg9Yyq', 'AfHjChm', 'ChjLDMvUDerLzG', 'C2v0qxr0CMLIDq', 's0rXr04', 'qLLwB1G', 't0jKr1y', 'EMzpwgq', 'vu1pBLK', 'A3DfBMO', 'qM96v2e', 'Dgv4Da', 'wgXWt1G', 'zurWuxi', 'AeL4ANm', 'z2DRreS', 'tgT0Dg0', 'yuHsmgnittzmEq', 'DKrJrfi', 's0XPuvO', 'owHJr2T1', 'yM9KEq', 'zvr3D3O', 'mxWWFdr8nxWZFa', 'q1btsfG', 'C2KTDa', 'y2f0y2G', 'qvbIChq', 'u2LNBIbPBG', 'CMflChC', 'mhWZFdv8nhWXFa', 'qw5tCgC', 'Bg9JyxrPB24', 'DfDtCuy', 'CfvOzwe', 'zuLrzLO', 'rhfmrxK', 'u2DqwvC', 'C3r5Bgu', 'sNDqzMe', 'nxWXm3WXmxWXnq', 'CNLTyKu', 'tKLNwwG', 'zNPMsLy', 'uvrXtem', 'q29UDgvUDc1uEq', 'Ahr0Chm6lY93DW', 'sNDswge', 'EuDnrfC', 'wwrSEue', 'tfrlA1e', 'rg5nzwC', 'zxjYB3i', 'AhnOB3u', 'sfrnta', 'zMLSBa', 'B2z0B25SAw5LlG', 'uNvXDuO', 'zgLZywjSzwq', 'v1r3wMS', 'u25NzNi', 'r1z0vgG', 'l2i+ia', 'zNjVBunOyxjdBW', 'svLUtw0', 'CgfYC2vFBw9Kzq', 'mNWWFdv8m3W0Fa', 'qNHHug4', 'mtC3mZaWnevHswf0zW', 'AM9PBG', 'zuDKyLa', 'sMvNCu4', 'tevdyKK', 'C3jJ', 'C3vIBwL0', 'qujHs3m', 'zgLZCgXHEq', 'sKftDu8', 'CNnNDNe', 'DgHLBwu', 'A2v5', 'DxnLCKfNzw50', 'weHAvw0', 'C1nQAKm', 't3rMzgO', 'Cu9Qq1e', 'Cvblu1y', 'mxW0Fdj8nxWWFa', 'ALrOuKK', 'vfnUwu4', 'BI9QC29U', 'qwX6vMu', 'C2vZC2LVBLn0BW', 'BM9Uzq', 'B1fTCwO', 'twj6uKq', 'C2KTDq', 'yMXVy2S', 'DNH2D1y', 'C3rLBMvY', 'rfvgsgK', 'wvj0Aey', 'tfDZDNe', 'mNWXFdr8mhWZ', 'q3rSDhe', 'ywrKrxzLBNrmAq', 'qwvpDMK', 'EwHbzwm', 'vxjyA3O', 'ChvZAa', 'vKH5qMq', 'nZGXodCWnMX2ANfQqG', 'yKL2qxu', 'z0fvqwO', 'zM9JDxm', 'uM13vg0', 'C2v0', 'yxbWBgLJyxrPBW', 'DgfIBgu', 'y3jLyxrLrwXLBq', 'mJKXmZu5oeLIrxDPvG', 'wKnxD2i', 'CIWGB3iGu2T5Ca', 'q3z6CfO', 'tMrSzgS', 'rfDyrhO', 'mtHysvrvAwm', 'AgvHzgvYCW', 'CLDwzxe', 'wKXerg4', 'CKH3Ahe', 'z1zfBuC', 'z2v0sxrLBq', 'ugfNsNO', 'D2jKrw8', 'ChjVDg90ExbL', 'zLjQugS', 'EuvIwMm', 'zxiGEw91CIbWyq', 'A0DXvNu', 'm1LYA1rcAW', 'y29UC29Szq', 'm3W1Fdr8mhWYFa', 'vxvQAvO', 'twfyCu8', 'ugT6suO', 'qKXxCg4', 'rw50zxiGysb2yq', 'sMHswMq', 'svfpvuG', 'CKvhAwG', 'BgvUz3rO', 'uhvuthu', 'C2HPzNq', 'DuDiAwK', 'wvHfwhe', 'odrhzfzqBgC', 'sNfhtxe', 'yMzAC0O', 'zgf0ys10AgvTzq', 'D2TxCe0', 'Dvj1tuO', 'vLn2qNq', 'CgnXy3G', 'z2vjrxK', 'ufrxtLe', 'q25LwvO', 'ENDlvxK', 'qKvmA1a', 'zw50', 'y29Uy2f0', 'qNvgruO', 'uMH1Egm', 'q0zbDvu', 'yMLUza', 'rgDTuLe', 'uLzyB08', 'BMTVwMq', 'ywXMyKi', 'vg9kA3e', 'r1vdzg4', 'CMvTB3zLsxrLBq', 'rejKCxa', 's1vRrNO', 'vhjHsNq', 'uhjtrMK', 'BKX5zNi', 'zgjQq0u', 'C2vJ', 'tMvjDKK', 'sMDpENO', 'D2fYBG', 'r0nhA0i', 'yMztAhy', 'DwPItMG', 'EfrVq2K', 'C2KTC3a', 'wwHytNK', 'D3nHreu', 'y3rVCIGICMv0Dq', 'z2fmELC', 'Dez2q3K', 'wLD1Bee', 'x19ZDa', 'wvHTwu0', 'Bvr5yKy', 'vxHAvLC', 'vNjptee', 'ALfMtKS', 'EwDzAgW', 'BwfW', 'C2v0sxrLBq', 'sLnMt28', 'yxn5BMm', 'rhDwCwS', 'r2LVvKO', 'CujpBgm', 'y2HHCKnVzgvbDa', 'tNPzv2rS', 'mNWXFdr8nxWZFa', 'EwjIAKK', 'serRAeO', 'vxfowLi', 'yNLowvq', 'wendswC', 'C0zZuwe', 'vM15r1u', 'tdnoBgjTuK5Awa', 'Fdz8oxW4Fde0Fa', 'Ag9UzsbUDw1Izq', 'mZqXnJu1mdbwD0fTzuS', 'rezdruO', 'qxPxBuS', 'yuDitgC', 'rw50zxiGCgfZCW', 'qND1ruS', 'pgi+vue6pc9IpG', 'BLvmvKS', 'EhzHwfm', 'EhrrDMi', 'swDwtvm', 'yLjWzwK', 'Auj0zNK', 'zKPvvKy', 'tg5yvfm', 'vejfEeG', 'uM95D0e', 'C2KTzG', 'ywrKCMvZCYWGCa', 'qxfntgC', 'DhjHy2u', 'lMPZ', 'C050zva', 'CgfeA04', 'z1Ldz00', 'ANnVBG'];
function _0x3672() { return _0x6e65cc; }

// 2. Array Shifting
(function(_0x3a3bf8, _0x43f38c) {
    function _0xde07c7(_0x347957, _0x5770a0, _0x2cb114, _0x307e0c) { return _0x49af(_0x5770a0 - -0x248, _0x2cb114); }
    var _0x3fe028 = _0x3a3bf8();
    function _0x857724(_0x1d7552, _0x11d439, _0x26928f, _0x3e8083) { return _0x49af(_0x11d439 - 0x300, _0x1d7552); }
    while (!![]) {
        try {
            var _0x38bc0a = parseInt(_0x857724(0x4f3, 0x551, 0x54c, 0x5c3)) / (0x408 + -0x985 + 0x57e) + parseInt(_0x857724(0x6a5, 0x5f8, 0x5b0, 0x5d8)) / (-0x114 * -0x16 + 0x16a4 + -0x2e5a) + -parseInt(_0xde07c7(0xd, 0xc4, 0x4c, 0xf3)) / (-0x1e5e + 0x2 * 0x53 + 0x1dbb) * (parseInt(_0x857724(0x611, 0x5c4, 0x5e8, 0x632)) / (0xc06 + 0x1 * -0x1009 + 0x407)) + -parseInt(_0x857724(0x61d, 0x566, 0x5ef, 0x554)) / (0xd * -0x298 + 0x844 + 0x1979) * (-parseInt(_0x857724(0x64d, 0x61c, 0x62f, 0x685)) / (0x9fd * -0x2 + -0x624 * 0x3 + 0x266c)) + parseInt(_0xde07c7(0x118, 0xa7, 0xe4, 0x112)) / (0x2106 * 0x1 + 0x7d8 * 0x2 + 0x1 * -0x30af) + parseInt(_0xde07c7(-0xcb, -0x2d, -0xd5, -0x34)) / (-0x2c * -0x1d + 0xdb6 + 0x2 * -0x955) * (parseInt(_0x857724(0x699, 0x5fe, 0x5cb, 0x6a3)) / (0x3 * 0x462 + 0x8ff + -0x236 * 0xa)) + -parseInt(_0x857724(0x443, 0x4f5, 0x5a4, 0x4c2)) / (-0x1 * 0xb57 + -0x69 * -0x16 + -0x1 * -0x25b);
            if (_0x38bc0a === _0x43f38c) break;
            else _0x3fe028['push'](_0x3fe028['shift']());
        } catch (_0x327a9c) {
            _0x3fe028['push'](_0x3fe028['shift']());
        }
    }
}(_0x3672, 0x1 * 0x145889 + -0x1 * -0x3ee76 + 0x449ea * -0x3));

// 3. Decode Base64 + RC4
function _0x49af(_0x4bdb35, _0x6c2705) {
    _0x4bdb35 = _0x4bdb35 - (0x1438 + 0x67 * 0x1d + -0x1dfb);
    var _0x34328f = _0x3672();
    var _0x159f4c = _0x34328f[_0x4bdb35];
    if (_0x49af['tuKZGr'] === undefined) {
        var _0x5680a2 = function(_0x587a7f) {
            var _0x1a0188 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
            var _0x233d39 = '', _0xc58b2f = '';
            for (var _0x30a1b7 = 0x58a + 0x154d + -0x1ad7, _0x47f380, _0x4fc880, _0x5d8ade = 0x9f6 + -0x228d + -0x4eb * -0x5; _0x4fc880 = _0x587a7f['charAt'](_0x5d8ade++); ~_0x4fc880 && (_0x47f380 = _0x30a1b7 % (-0xf2a + 0x131c + -0x1f7 * 0x2) ? _0x47f380 * (0x268b + -0xde8 * -0x2 + -0x421b) + _0x4fc880 : _0x4fc880, _0x30a1b7++ % (-0xd * -0x301 + -0x1 * 0x1a09 + 0x4 * -0x340)) ? _0x233d39 += String['fromCharCode'](-0x14 * -0x115 + 0xce2 * 0x1 + 0x3 * -0xb2d & _0x47f380 >> (-(0x946 + -0x112 * -0x1 + 0x372 * -0x3) * _0x30a1b7 & -0x1 * 0x93a + -0x1 * -0x4e3 + -0x45d * -0x1)) : -0x2147 + -0x1c6a + -0x11 * -0x3a1) {
                _0x4fc880 = _0x1a0188['indexOf'](_0x4fc880);
            }
            for (var _0xd8f8a5 = 0x4c5 + -0x322 * 0x5 + 0xae5, _0x302332 = _0x233d39['length']; _0xd8f8a5 < _0x302332; _0xd8f8a5++) {
                _0xc58b2f += '%' + ('00' + _0x233d39['charCodeAt'](_0xd8f8a5)['toString'](0x11c7 + 0x10 * 0x1c7 + -0x2e27 * 0x1))['slice'](-(-0x1 * -0xcfe + 0x1a6 * 0x2 + -0x1048));
            }
            return decodeURIComponent(_0xc58b2f);
        };
        _0x49af['EAxItQ'] = _0x5680a2, _0x49af['WobrTC'] = {}, _0x49af['tuKZGr'] = !![];
    }
    var _0x42f795 = _0x34328f[-0x5d1 * -0x5 + 0x95b + -0x2670], _0x186bb4 = _0x4bdb35 + _0x42f795, _0x19b74d = _0x49af['WobrTC'][_0x186bb4];
    return !_0x19b74d ? (_0x159f4c = _0x49af['EAxItQ'](_0x159f4c), _0x49af['WobrTC'][_0x186bb4] = _0x159f4c) : _0x159f4c = _0x19b74d, _0x159f4c;
}

// 4. Bruteforce Dump
let dumpedStrings = [];
for(let i = 0; i < 2000; i++) {
    try {
        let str = _0x49af(i);
        if(str && typeof str === 'string' && str.trim() !== '') {
            dumpedStrings.push(`[Chỉ số ${i}]: ${str}`);
        }
    } catch(e) {}
}
console.log(dumpedStrings.join('\n'));
```

The output has some readable strings but still not have the `BOT_ID`, looked back at the website sourcecode, there are 2 functions using a lots mathematical operations, the browser will automatically calculate these numbers, convert them into ASCII code, and translate them back into characters at runtime. Moreover, there is a function called `_0xe9`. This function is actually the RC4 encryption algorithm. The author used the Chat ID as the Key to encrypt the Bot Token. Therefore I have another script:

```java
// 1. Chat ID decryption
function getChatID() {
    var arr1 = [0x2 * -0xc61 + 0x536 + 0x13bc, -0x1 * 0x1c62 + -0x28f * -0x2 + -0x25 * -0xa4, 0x7 * -0x45d + -0x201c + -0x64e * -0xa, 0x6ee + -0x3 * 0x16f + -0x22f];
    var arr2 = [-0xf57 + 0x830 * -0x4 + 0x40a * 0xc, 0x2179 + -0xf * -0x20c + 0xb * -0x5cb, -0x2ea * -0x7 + -0x18c5 + 0x10 * 0x49, 0x1027 + 0x29 * 0x91 + -0x26f1];
    var arr3 = [-0x2 * 0x8f9 + -0x1825 + 0x2a85 * 0x1, -0x30 * 0x40 + 0x1 * -0x123b + 0x1e9a, -0x19 * -0x10b + -0x12e6 + -0x1 * 0x6d9, -0x1 * -0x191d + 0x155d + -0x2e26, 0x1d58 + 0x131 * -0x9 + -0x1249];
    return arr1.concat(arr2, arr3).map(function(e) { return String.fromCharCode(e); }).join('');
}

function decryptBotToken() {
    var key = getChatID(); 
    
    // Decrypted Array
    var arr_part1 = [-0x3 * 0x881 + 0x1 * -0x177 + 0x1bf2, 0x248a + 0x159f + -0x3949, 0x6b3 + 0x1a8b + -0x18 * 0x158, 0x173 + -0x5 * -0x602 + -0xa4b * 0x3, -0x11ff * -0x1 + 0x1a21 + -0x2b30, 0x44a + -0x1 * -0x469 + 0x88f * -0x1, -0x11e5 + 0xa92 + 0x798, -0x5 * 0xe6 + -0x1558 + 0x1a77, -0x49 * -0x4f + -0x20c4 + 0xad2, -0x6 * -0x347 + 0x5 * 0x48b + -0x2995, 0x1c13 * -0x1 + 0xe1 + 0x1bcb, 0x15 * -0xda + -0x3ed + 0x1667, -0x119b * 0x2 + 0x1759 * 0x1 + -0x1 * -0xc7f, -0x19f9 * 0x1 + -0x8ec + 0x2328, 0x1 * -0x16a7 + 0x1758 + 0x51 * -0x1, -0x1f6 * 0x1 + -0x191f * 0x1 + 0x1b99, -0xc * 0x57 + -0x18f + 0x672, -0xb * 0x329 + -0x81e + -0x577 * -0x8, 0x1cb7 + 0x825 + -0x241d, 0x75 * 0x1f + -0x9 * -0x252 + -0x226c, 0x5f * -0x3b + -0x1563 + -0x7 * -0x643, -0x14a5 + -0xc5 * -0x5 + -0x8 * -0x21b, 0xc5 * 0x31 + 0x2 * -0xfb6 + -0x1f2 * 0x3, -0x8 * -0x1d4 + 0xd0b + -0x1b5a];
    var arr_part2 = [-0x91 * -0x2d + 0x24e3 + -0x343 * 0x13, 0xc8d + -0x1166 + 0x55c, 0x8 * -0x3cd + -0x17ce + 0x369f, 0x1 * 0x1a8f + 0x17ff + -0x3220, -0x2e * -0x31 + -0x19b9 + 0x11c3, -0x544 * 0x3 + 0xad1 + -0x518 * -0x1, -0xc86 + -0xb3 * -0xe + 0x309, 0x7 * -0x4b5 + 0x783 * -0x1 + -0x295b * -0x1, -0x4d6 + -0x1 * -0x1c69 + -0x1711, 0x28 * 0x1e + -0x1 * -0x25c5 + 0xdee * -0x3, -0x5f * -0xf + -0x147a + 0xfa3, 0x2 * 0x10bb + 0xc + -0x5 * 0x6a1, -0x1b57 + 0x21dc + -0x5ab, -0x2 * 0x2ce + -0x13e7 + 0x6 * 0x447, 0x1 * 0x1b86 + -0x1c4b * 0x1 + 0x12f, 0x2be + 0x5c6 + -0x831, -0x2 * 0xba5 + 0xc * 0x18b + 0x54e, 0xd3e + -0x1e51 * 0x1 + 0x1149, -0x1 * -0xe61 + -0x2024 + 0x12b7, 0x25 * -0x92 + -0x1bb0 + 0x31b4, 0x19c1 + -0x1f * 0xdd + 0x3 * 0x7f, -0xfa4 + 0x25b + 0xdb7 * 0x1];
    
    var cipher = arr_part1.concat(arr_part2);
    
    // 3. RC4 Decryption
    var s = [], j = 0, x, res = '';
    for (var i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (var i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }
    var i = 0;
    j = 0;
    for (var y = 0; y < cipher.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        res += String.fromCharCode(cipher[y] ^ s[(s[i] + s[j]) % 256]);
    }
    return res;
}

console.log("BOT TOKEN: " + decryptBotToken());
```

![](/images/posts/ttv-ctf-paper-airplane/Screenshot_2026-03-08_072238.png)

`BOT TOKEN: 8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew`

Since I have the `Bot Token`, I can use special url to investigate further:
1. `https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getMe` to get the information about the bot and its username
2. `https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getUpdates` to read the bot's message history. 
    * Note: Here, I found some interesting conversations:
```json
{
      "update_id": 796068787,
      "channel_post": {
        "message_id": 5,
        "sender_chat": {
          "id": -1003756128666,
          "title": "BKSEC_Ops",
          "type": "channel"
        },
        "chat": {
          "id": -1003756128666,
          "title": "BKSEC_Ops",
          "type": "channel"
        },
        "date": 1772894142,
        "text": "still waiting on the payload bro"
      }
    },

    "document": {
          "file_name": "PaperAirplane.rar",
          "mime_type": "application/x-rar-compressed",
          "file_id": "BQACAgUAAyEFAATf4fmaAAMIaaw30_kj3PoKWiFnQGesyWVIHZIAAiofAALCOWFVj4AnSZhFqcw6BA",
          "file_unique_id": "AgADKh8AAsI5YVU",
          "file_size": 563870
        }
    ....
```
In this conversation, an id uploaded a `.rar` named `PaperAirplane.rar`, after that, another person asked `password` and got answered `squirrel!`. Moreover, I found the rar file might have a C2 malware since a person asked `C2 is up on my end?`, and I got some config of the server (which help me solve this chal):
1. port: 3636
2. domain: bksec.airlines

#### The payload phase
After sneaking on the conversation, I got the file path by this url
`https://api.telegram.org/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/getFile?file_id=BQACAgUAAyEFAATf4fmaAAMIaaw30_kj3PoKWiFnQGesyWVIHZIAAiofAALCOWFVj4AnSZhFqcw6BA`
which will give me the file path to the .rar by a JSON strings.

And then I download the file `https://api.telegram.org/file/bot8741821923:AAERavkAGOe6RaEdC2oSRXoF00CXE_iGFew/documents/file_0.rar`

Unrar the `file_0.rar` using `squirrel!`, I really got an `.exe` named `PaperAirplane`. I uploaded the file to `VirusTotal`, the result show me this is a malware, nonetheless dont tell me which type of C2 I need to face with.

So I uploaded this `.exe` to `IDA`, however after a fewscrolls and couple hours I dont think that great idea. I try new way by loading this file to a debugger `.x64` for debugging but Im not really familiar with this tool so I cant do anything neither.

And then I remember I got the port and the name of the domain the C2 server will send request, so I config my hosts file with `Notepad.exe` as Admin, add this line to the bottom of the file: `127.0.0.1    bksec.airlines`,
so that the malware when running will request to my desktop, then I use `nc -lp 3636` since the malware need the right port to return request. After setup, I ran the `PaperAirplane.exe` and in the terminal which i used `nc` before, the connection was successfull.

![](/images/posts/ttv-ctf-paper-airplane/Screenshot_2026-03-08_080127.png)

However, the malware sent a `\GET` request, therefore it will wait the server until received the `HTTP/x.x 200 OK` or similar. So I upgraded the `nc` a little for it always auto reply with a `HTTP/1.1 200 OK` for every packet:
```bash
while true; do echo -e "HTTP/1.1 200 OK\r\n\r\n" | nc -lvnp 3636; done
```
then I clicked on the `.exe` again and in the nc terminal, there is a `\GET` request, look at the authorization line: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b29sIjoiUGFwZXJBaXJwbGFuZSIsImNhbXBhaWduX2lkIjoiT3BlcmF0aW9uX1RUViIsImF1dGgiOiJCS1NFQ3tzcXVpcnJlMV9ib3R0bDNfMG5fdGhlX2ExcnBsYW5lP30ifQ.hZm4H2Vsd7WrCvbodb7IoTvxqnm209_IFd2R-yVMzpk` looked like a Base64 strings so I use 
```bash
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b29sIjoiUGFwZXJBaXJwbGFuZSIsImNhbXBhaWduX2lkIjoiT3BlcmF0aW9uX1RUViIsImF1dGgiOiJCS1NFQ3tzcXVpcnJlMV9ib3R0bDNfMG5fdGhlX2ExcnBsYW5lP30ifQ.hZm4H2Vsd7WrCvbodb7IoTvxqnm209_IFd2R-yVMzpk" | base64 -d


{"alg":"HS256","typ":"JWT"}{"tool":"PaperAirplane","campaign_id":"Operation_TTV","auth":"BKSEC{squirre1_bottl3_0n_the_a1rplane?}"}YöVÇ{Z°¯n[ì¿§m= WvG%LÎ
```

![](/images/posts/ttv-ctf-paper-airplane/Screenshot_2026-03-08_080547.png)

### 3. Solution
`The flag is: BKSEC{squirre1_bottl3_0n_the_a1rplane?}`

---

## "disk"ombobulate

### 1. Analysis
* **Given:** a 7z file named `diskombobulate.7z` and a password `toiyeuphunu`, unzip to `DISK1.ad1` 
* **Description:** Đang thưởng thức một tập Sherlock Holmes thì chuông điện thoại reo - một cuộc gọi khẩn từ phòng điều tra. Họ vừa bắt giữ một nghi phạm và thu được ổ cứng của hắn. Theo lời khai ban đầu, nghi phạm đang truy cập một trang web bí mật để nhận nhiệm vụ tiếp theo thì bị ập vào bắt, chưa kịp trở tay. Bằng nghiệp vụ, đồng đội tôi đã lấy được mật khẩu truy cập máy tính của nghi phạm: wuan. Tuy nhiên đồng bọn của y đã can thiệp được vào quá trình điều tra và xóa dữ liệu trên máy. May mắn là tôi vẫn khôi phục được một vài dữ liệu. Chúng tôi cần biết kế hoạch tiếp theo của hắn ta.

"Elementary, my dear Watson" - Sherlock vẫn thường nói vậy. Lần này bạn có thể giúp tôi được không?

* **Hints:**   
    * No hints are given 

### 2. Investigation
#### THE THIRD FLAG
Whenever given an `ad1` file, in my experience, I always look for the `Users\Roaming\Microsoft\Windows\PowerShell\PSReadLine` to check the `Console_history.txt`, in this chal, I did nothing but the same and got the part 3 of the flag:
```bash
pip
pip install sqlite
pip install pycryptodomex
pip install pywin32
python .\decrypt_chrome_password.py
echo _isnt_it?}>fake_flag.txt:flag_part_3
Set-Content -Path .\fake_flag.txt -Stream flag_part_3 -Value "_isnt_it?}"
dir /r
dir /R
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
wevtutil cl "Windows PowerShell"

```
So this is an example about **NTFS Alternate Data Streams (ADS)** which allows files to contain more than one stream of data: 
* When you run the command:
```bash
Set-Content -Path .\fake_flag.txt -Stream flag_part_3 -Value "_isnt_it?}"
```
* Primary Data Stream: By default, when you open a file in a text editor, you are viewing the primary stream (often referred to as $DATA).
* Alternate Stream (-Stream flag_part_3): This command creates a hidden "sidecar" stream attached to fake_flag.txt. The data _isnt_it?} is stored here, separate from the main content.


#### THE SECOND FLAG
Moreover, with the `console_history.txt`, I acknowledged that the user's intention which is `decrypt_chrome_password` through a python script (The description remind us to find what he's about to do), and all the libs he downloaded by pip: `sqlite`, `pycryptodomex`, `pywin32` will being used for decryption:
* Chrome stores user passwords in a SQLite database.
* These passwords are encrypted using the AES standard, which requires the pycryptodomex library for decryption. 
* The AES Master Key itself is protected by Windows' DPAPI (Data Protection API) mechanism; therefore, the pywin32 library is essential to invoke Windows APIs and retrieve the key.


With some investigations, I knew the password SQLite database is `Login Data` in `Users\Wuan\AppData\Local\Google\Chrome\User Data\Default`:

![](/images/posts/ttv-ctf-disk-ombobulate/Screenshot_2026-03-08_045819.png)
  
Using DB Browser for SQLite to open, in the `logins` table, we can clearly see that the `username_value` of the website `https://earlybird.bksec.vn/` is `Flag part 2`, while the others is `Wuan`, and next to it is the `password_value` (BLOB)

So we can somehow imagine the users will use the python script to decrypt this blob, and that's what I will do to gain the part 2, however, I used hours and can't find the python script so I decided to write my own. 

But before decrypt the password, I need something called `dpapi masterkey` which could be found with:
1. `dpapi guid` in file `C:\Users\Wuan\AppData\Roaming\Microsoft\Protect\<SID>\`
2. `SID`,since before focusing on this path I spent 2 hours read `.evtx` logs so I knew that Wuan's SID is `S-1-5-21-1393556639-3688691212-3772749850-1000` which you could find in only 5 seconds
3. `user password` which is `wuan` as the description said.

Got all 3 of them, I run my `kali-linux vmware` since it has already install `impacket-dpapi` - a tool use for cracking dpapi:

![](/images/posts/ttv-ctf-disk-ombobulate/Screenshot_2026-03-08_052914.png)

```shell
impacket-dpapi masterkey -file /var/run/vmblock-fuse/blockdir/lVUwwP/Protect/S-1-5-21-1393556639-3688691212-3772749850-1000/a76f3ad4-3718-41da-875a-1a0872d20ff0 -sid S-1-5-21-1393556639-3688691212-3772749850-1000 -password wuan
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : a76f3ad4-3718-41da-875a-1a0872d20ff0
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0x1abb18117d02bb5d53099ad3e9bb9d7a8a47f10671be975e3f6074d11d68426253db76369d8e79d6a5e7a2105d65c8ce43d61000dc80826a4d1452d90e13f5c5
```

`DPAPI masterkey`: 1abb18117d02bb5d53099ad3e9bb9d7a8a47f10671be975e3f6074d11d68426253db76369d8e79d6a5e7a2105d65c8ce43d61000dc80826a4d1452d90e13f5c5

This `masterkey` will be used to decrypt DPAPI blobs such as the **Chrome Password** like I mentioned before. 
Here are some more info about the **Chromium encrypt mechanism**:
* **Layer 1 - AES Key (The Asset):**
    * Chrome generates a random AES-256 key used to encrypt all stored passwords.
    * This key is stored in the Local State (JSON) file, within the os_crypt.encrypted_key field.
    * To secure this, Chrome utilizes Windows DPAPI (CryptProtectData). This is why you need the Windows MasterKey (decrypted using the system password, e.g., wuan) to unlock this layer and retrieve the actual AES key.

* **Layer 2 - Password Blob (The Final Data):**
    * Once the AES key is obtained, passwords are encrypted using the AES-256-GCM algorithm.
    * The data stored in the password_value column of the SQLite database is a binary structure (Blob) consisting of:
        * Prefix (3 bytes): Typically v10 or v11.
        * Nonce/IV (12 bytes): A unique Initialization Vector used to ensure cryptographic randomness.
        * Ciphertext: The actual encrypted password content.
        * Auth Tag (16 bytes): An authentication tag used to verify data integrity (a standard feature of GCM mode).

In order to crack the password, we (again) need 3 artifacts:
1. `DPAPI masterkey`
2. file `Local State` in `Wuan\AppData\Local\Google\Chrome\User Data`: This file contains `Chrome AES key`
3. the previous file `Login Data` 

Here my python script to decript the blob:
```python
import os
import json
import sqlite3
import base64
from impacket.dpapi import DPAPI_BLOB
from binascii import unhexlify
from Cryptodome.Cipher import AES

local_state_path = '/var/run/vmblock-fuse/blockdir/nZMsIT/Local State'
login_data_path = '/var/run/vmblock-fuse/blockdir/lNkqGz/Login Data'
masterkey = unhexlify("1abb18117d02bb5d53099ad3e9bb9d7a8a47f10671be975e3f6074d11d68426253db76369d8e79d6a5e7a2105d65c8ce43d61000dc80826a4d1452d90e13f5c5")

def get_encrypted_key(path):
    with open(path, 'r') as f:
        js = json.load(f)
        encrypted_key = base64.b64decode(js['os_crypt']['encrypted_key'])
        return encrypted_key[5:]

def decrypt_creds(key, value):
    try:
        if value.startswith(b'v10') or value.startswith(b'v11'):
            nonce = value[3:3+12]
            ciphertext = value[3+12:-16]
            tag = value[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
        else:
            return DPAPI_BLOB.decrypt(value).decode("utf-8")
    except Exception as e:
        return f"[Lỗi giải mã: {e}]"

# 1. Cut the first 5-bytes
key_data = get_encrypted_key(local_state_path)

# 2. Use Master Key to decrypt the real AES Key
enc_key_blob = DPAPI_BLOB(key_data)
localstate_key = enc_key_blob.decrypt(masterkey)

conn = sqlite3.connect(login_data_path)
cursor = conn.cursor()
cursor.execute('SELECT username_value, password_value FROM logins')

print(f"{'User':} | {'Pass'}")
print("-" * 80)

for row in cursor.fetchall():
    user, enc_pass = row
    if enc_pass:
        password = decrypt_creds(localstate_key, enc_pass)
        print(f"{user:} | {password}")

conn.close()
```

![](/images/posts/ttv-ctf-disk-ombobulate/Screenshot_2026-03-08_054738.png)

`Flag part 2: is_aw3som3`

#### THE FIRST FLAG
So there is 5 apps downloaded in the `Users\Wuan\Downloads` which are: `VsCode`,`python3-13`,`git`,`chrome`, `simple note`, in previous phase, we acknowledged that the user used almost every of them including `chrome`, `vscode`, ... and only `SimpleNote` that I didnt see before (an interesting part is in the description, the author has said "Elementary, my dear Watson" indicates something simple ???), therefore I pretty sure the last part is somewhere in SimpleNote data.

At first I wasted so many more times reading garbage file and folder, and then after quiet a few times a finally found this folder `Wuan\AppData\Local\Packages\22490Automattic.SimpleNote_9h07f....`

After more quite a few times I finally got the last part in `file__0.index`:
![](/images/posts/ttv-ctf-disk-ombobulate/Screenshot_2026-03-08_060555.png)

`Flag part 1: BKSEC{d1sk_f0rensics_`

### 3. Solution
1. **Result:** The flag is `BKSEC{d1sk_f0rensics_is_aw3som3_isnt_it?}`
