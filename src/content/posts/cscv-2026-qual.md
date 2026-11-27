---
title: "CSCV 2026 Qual — Forensics Writeups"
description: "Tổng hợp 2 writeup vòng loại CSCV 2026: From Update to Encrypt và Silent Room."
pubDate: 2026-10-12
lang: vi
category: writeup
draft: true
ctf: "CSCV 2026 Qual"
tags:
  - "Writeup"
  - "Forensics"
  - "CSCV2026"
  - "Qual"
---

## From Update to Encrypt

### Kịch bản thử thách
```text
Ring... tuttt... tuttt....
SOC: Moshi moshi, Is that you Vu?
VuVT: Holy moly, I've just running some kind of updates and now my device got encrypted.
SOC: Do not touch your keyboard. We'll come and investigate
Then a data sample was collected from the incident
Investigate to figure it out what happened and find the information to restore the final results.
```

Đề bài cung cấp một file `VuVT.7z`. Sau khi giải nén một lần, ta có các artifacts sau:

- `sysmon.evtx`: Sysmon log trên máy nạn nhân.
- `network.pcapng`: lưu lượng mạng tại thời điểm xảy ra sự cố.
- `mem.raw`: memory dump của máy nạn nhân.
- `Users/`: chứa các file được thu thập từ ổ đĩa của nạn nhân.

![](/images/posts/cscv-2026-from-update-to-encrypt/pic1.png)

### Phân tích bằng chứng
#### 1. Sysmon log
Phần mô tả challenge có nói rằng nạn nhân vừa chạy một bản cập nhật sau đó dữ liệu bị mã hóa, nên suy nghĩ đầu tiên là cần xác định file nào đã được tải và tiến trình nào đã mã hóa dữ liệu, và không gì tốt hơn `sysmon.evtx` ở điểm này:

> `Sysmon.evtx`: 

Mình mở file log này bằng công cụ `Event Viewer`, lọc ra các Event ID `1 -  Process Create`, `3 - Network Connection` và `11 - File Create`, và thấy 1 loạt các sự kiện khả nghi bắt đầu xảy ra từ `2026-08-25 04:34:17 UTC`:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic2.png)

Sau đó 7 giây, nạn nhân tải 1 file nén `.7z` vào thư mục `Users\bkav\Downloads\` của nạn nhân:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic3.png)

Từ `04:34:33` - `04:34:34`, nạn nhân sử dụng công cụ `7z` để thực hiện giải nén file này, tạo ra tổng cộng 6 binaries lần lượt là: `7z2409-x64.exe`, `explorer.exe`, `key.exe`, `system.exe`, `update.exe` và `updater.exe`:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic4.png)

Hai file `update.exe` và `updater.exe` có vẻ match với mô tả ở đề bài, `updater.exe` được chạy tại `04:34:57` còn `update.exe` được chạy sau đó vài giây lúc `04:35:05`. Tuy nhiên đáng chú ý hơn cả là sau khi chạy `update.exe`, có hàng loạt event ID 11 (tổng cộng là 7) file được tạo ra có đuôi `.enc` tại thư mục `C:\Users\Public\MetaData\Data\` và 1 event ID 3 thực hiện kết nối tới địa chỉ IP `192.168.56.1:8080`:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic5.png)

Có thể tóm tắt timeline mã hóa file như sau:

| UTC | Sự kiện |
|---|---|
| 04:34:17 | `browser_broker.exe` tạo file tạm `UpdateX7A91C.7z...partial` |
| 04:34:24 | Tải file nén chứa các binary từ URL `http://192.168.56.1:1337/UpdateX7A91C.7z` |
| 04:34:33 | `7zG.exe` giải nén archive vào `C:\Users\bkav\Downloads\UpdateX7A91C\` |
| 04:35:05 | Chạy `update.exe`|
| 04:35:06 | `update.exe` tạo bảy file `.enc` |
| 04:35:07 | `update.exe` tạo kết nối tới `192.168.56.1:8080` |

Từ đây mình khá chắc phải dịch ngược `update.exe` để tìm ra thuật toán mã hóa các file `.enc` để giải mã các file này.

#### 2. Reverse update.exe
Mở `VuVT\Users\bkav\Downloads\UpdateX7A91C\update.exe` trong IDA, hàm main cũng chính là hàm mã hóa chính của chương trình. Đầu tiên nó thực hiện lấy `ComputerName` và `ProcessID` của chính nó:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic6.png)

Tiếp theo nó gán 1 giá trị URL là `http://192.168.56.1:8080/api/check` trước khi đưa vào hàm thực hiện kết nối C2 là `sub_406500`:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic7.png)

Trong sub_406500, chương trình dùng `WinHttpOpen -> WinHttpConnect -> WinHttpOpenRequest` với request method là `GET`, sau đó gọi `WinHttpSendRequest` và `WinHttpReceiveResponse`. Dữ liệu đọc bằng `WinHttpReadData` được nối vào biến `Buf`. Quay lại main, `Buf` được truyền vào `sub_406940`:

![](/images/posts/cscv-2026-from-update-to-encrypt/pic8.png)

Hàm này tìm chuỗi có dạng `"campaign"` trong `Buf`, sau đó sử dụng `memchr` để tìm giá trị nằm giữa cặp dấu `""`:






#### 3. Pivot sang network capture
Lọc HTTP liên quan tới IP vừa tìm được:

```bash
tshark -r VuVT/network.pcapng -Y "http && ip.addr == 192.168.56.1" \
  -T fields -e frame.number -e ip.src -e ip.dst \
  -e http.request.method -e http.request.uri -e http.response.code -e http.file_data
```

Các frame đáng chú ý:

```text
183   GET  /
196   GET  /UpdateX7A91C.7z
2741  GET  /api/check
2743  HTTP/1.0 200 OK
```

![Wireshark với display filter http và ip.addr bằng 192.168.56.1, đánh dấu GET UpdateX7A91C.7z và GET api/check](/images/posts/cscv-2026-from-update-to-encrypt/pic4.png)

Follow TCP stream của request `/api/check`, server trả về:

```json
{"campaign":"X7A91C","status":"ok"}
```

![Wireshark Follow HTTP Stream hiển thị GET /api/check và JSON campaign X7A91C, status ok](/images/posts/cscv-2026-from-update-to-encrypt/pic5.png)

Như vậy `X7A91C` không chỉ là một phần tên archive; đây là campaign ID do server cấp. Giá trị này nhiều khả năng tham gia vào logic của malware, nên bước tiếp theo là reverse `update.exe`.

#### 4. Tìm process trong memory và recover nonce
Với Volatility, `pslist` xác nhận PID từ Sysmon vẫn tồn tại tại thời điểm lấy memory:

```bash
vol-rs -f VuVT/mem.raw windows.pslist.PsList
```

```text
PID   PPID  ImageFileName  CreateTime (UTC)             Wow64
2844  3164  update.exe     2026-08-25 04:35:05.000000   True
2004  2844  conhost.exe    2026-08-25 04:35:05.000000   False
```



Dump vùng nhớ của tiến trình:

```bash
vol-rs -f VuVT/mem.raw -o recovery/memdump windows.memmap.Memmap --pid 2844 --dump
```

Sau đó tính FNV-1a-64 trên basename viết thường, tìm hash dạng little-endian trong `pid.2844.dmp`, rồi xác thực record bằng checksum. Các record hợp lệ là:

| File | Offset trong process dump | Nonce |
|---|---:|---|
| `1337dakl.txt` | `0xE2D20` | `F13BA19B255AE4F590C25CFD` |
| `7z2409-x64.exe` | `0xE2D38` | `DF8F031F5E50E9B0EAEA27FF` |
| `flag.jpeg` | `0xE2D50` | `97595686149CF7A4AFE5CD6F` |
| `hi.txt` | `0xE2D68` | `24C696F9341FD8E7882B44F0` |
| `IMG_4287.jpeg` | `0xE2D80` | `5A3EA1093656DB3093D8DF16` |
| `IMG_4288.jpeg` | `0xE2D98` | `257C8A8FF3BF9CB6CDDDCE85` |
| `ptit.txt` | `0xE2DB0` | `ADEA20882FDE1B4D6E74F57C` |

Ví dụ record của `hi.txt` tại `0xE2D68`:

```text
DC CC 0E 51 A3 96 31 E4  24 C6 96 F9 34 1F D8 E7
88 2B 44 F0 F5 82 72 F0
```

Tách record này ra ta có:

```text
name hash = 0xE43196A3510ECCDC
nonce     = 24C696F9341FD8E7882B44F0
checksum  = 0xF07282F5
```



#### 5. Giải mã dữ liệu
Script `solve.py` tự động:

- Tạo khóa từ hostname, PID và campaign.
- Tính hash tên của từng file `.enc`.
- Tìm và kiểm tra record nonce trong process dump.
- Parse magic, GCM tag và ciphertext.
- Giải mã AES-256-GCM; tag hợp lệ cũng xác nhận key/nonce đúng.

Phần chính của script:

```python
import hashlib
import struct
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHECK_XOR = 0xA17C4E29

def fnv1a64(name):
    value = 0xCBF29CE484222325
    for byte in name.lower().encode("ascii"):
        value ^= byte
        value = (value * 0x100000001B3) & 0xffffffffffffffff
    return value

def recover_nonce(memory, filename):
    name_hash = fnv1a64(filename)
    needle = struct.pack("<Q", name_hash)
    expected = (name_hash & 0xffffffff) ^ CHECK_XOR
    start = 0
    while True:
        offset = memory.find(needle, start)
        if offset < 0:
            raise ValueError(f"nonce not found: {filename}")
        if struct.unpack_from("<I", memory, offset + 20)[0] == expected:
            return offset, memory[offset + 8:offset + 20]
        start = offset + 1

memory = Path("pid.2844.dmp").read_bytes()
enc_dir = Path(r"VuVT\Users\Public\MetaData\Data")
out_dir = Path(r"recovery\decrypted")
out_dir.mkdir(parents=True, exist_ok=True)

key_material = b"desktop-7nnknik|2844|X7A91C"
key = hashlib.sha256(key_material).digest()

for path in enc_dir.glob("*.enc"):
    name = path.name[:-4]
    offset, nonce = recover_nonce(memory, name)
    data = path.read_bytes()
    assert data[:8] == b"1337DaKL"
    tag, ciphertext = data[8:24], data[24:]
    plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
    (out_dir / name).write_bytes(plaintext)
    print(name, hex(offset), nonce.hex())
```

Chạy script:

```powershell
python -m pip install cryptography
python .\solve.py .\pid.2844.dmp `
  '.\VuVT\Users\Public\MetaData\Data' `
  '.\recovery\decrypted'
```

Kết quả mong đợi:

```text
key = 3c0249e672188f75d3f6a845d534ecfc1bdd2c7c681562393f636d24d4409830
1337dakl.txt: record=0xE2D20 nonce=f13ba19b255ae4f590c25cfd
7z2409-x64.exe: record=0xE2D38 nonce=df8f031f5e50e9b0eaea27ff
flag.jpeg: record=0xE2D50 nonce=97595686149cf7a4afe5cd6f
hi.txt: record=0xE2D68 nonce=24c696f9341fd8e7882b44f0
IMG_4287.jpeg: record=0xE2D80 nonce=5a3ea1093656db3093d8df16
IMG_4288.jpeg: record=0xE2D98 nonce=257c8a8ff3bf9cb6cdddce85
ptit.txt: record=0xE2DB0 nonce=adea20882fde1b4d6e74f57c
```



Tên `flag.jpeg` là một decoy; ảnh đó giải mã hợp lệ nhưng không chứa flag cuối. Kiểm tra toàn bộ kết quả khôi phục cho thấy flag thật nằm trong `hi.txt`:

```powershell
Get-Content .\recovery\decrypted\hi.txt
```

```text
CSCV2026{c0rr3l4t3_b3f0r3_d3crypt}
```

### Flag
```text
CSCV2026{c0rr3l4t3_b3f0r3_d3crypt}
```

---

## Silent Room

### Phân tích bằng chứng
Giải nén file 7z mà đề bài cho ta được lần lượt các file sau:
- `evidence_acquire.log`
- `evidence.E01`
- `evidence.E01.txt`
- `README.txt`
- `SHA256SUMS.txt`

![](/images/posts/cscv-2026-silent-room/pic1.png)

Tiến hành đọc nội dung file `README.txt`:

```bash
kittne@DESKTOP-C0H1UVN:/mnt/d/sv_it/htb/CSCV2026/for/SilentRoom_public$ cat README.txt
Silent Room

Category: Forensics
Difficulty: Medium

Scenario:
A 17-year-old girl named A left home for unclear reasons. After being unable to
contact her for a while, her family reported the case to the authorities. You
are given an image extracted from A's computer to look for traces that can
identify A's current location.

Goal:
Determine the most likely current room, hotel, and province/city.

Flag format:
CSCV2026{.*}

Example:
CSCV2026{th1s_i5_4_fl4g'+!-.@#$%?}

Provided file:
evidence.E01
```

Vậy file chúng ta cần điều tra chính là `evidence.E01` - một ổ đĩa được thu thập từ máy tính của người bị mất tích. Mình mở ổ đĩa này bằng công cụ `FTK Imager`:

![](/images/posts/cscv-2026-silent-room/pic2.png)

Đây là ổ đĩa `C:` của A, bên trong chỉ có 1 user duy nhất. Đầu tiên tại thư mục `Downloads`, ta thấy có 2 file bị xóa lần lượt là: `ticket_DN1842.png` và `booking_HSR_260820_preview.png` có vẻ là thông tin đặt phòng và phương tiện di chuyển của A. Ngoài ra còn có 1 file `notice_217.PDF` mang nội dung rất giống một thông báo giả mạo cơ quan chức năng yêu cầu A hợp tác điều tra, và 1 file `booking_BAB_403DN_receipt.html` lưu một vài thông tin đặt phòng chưa bị xóa:

![](/images/posts/cscv-2026-silent-room/pic3.png)

![](/images/posts/cscv-2026-silent-room/pic4.png)

Tất nhiên challenge không dễ đến thế và thông tin trên file html là giả. Trong `AppData\Local\Programs` và `AppData\Roaming`, ta thấy sự xuất hiện của một ứng dụng lạ có tên là `ChatApp`:

![](/images/posts/cscv-2026-silent-room/pic5.png)

Tại `AppData\Local\Programs\ChatApp\resources` có 1 file có tên `app.bundle.js`:

```js
const crypto = require('crypto');
const ChatAppCrypto = {
	kid: 'chatapp-web-v2',
	deriveKey: function (peer, caseId) {
		return crypto.createHash('sha256').update([
			this.kid,
			peer,
			caseId
		].join('|'), 'utf8').digest();
	},
	decryptBody: function (body, peer, caseId) {
		const m = JSON.parse(body);
		if (m.alg !== 'AES-256-CBC')
			throw new Error('unsupported');
		const d = crypto.createDecipheriv('aes-256-cbc', this.deriveKey(peer, caseId), Buffer.from(m.iv, 'base64'));
		return Buffer.concat([
			d.update(Buffer.from(m.ct, 'base64')),
			d.final()
		]).toString('utf8');
	}
};
module.exports = ChatAppCrypto;
```

Đây là logic giải mã tin nhắn của ứng dụng nhắn tin trên máy nạn nhân:
1. Nó parse dữ liệu tin nhắn (1 file JSON) với các trường chính được dùng là: `alg`, `iv`, `ct`.
2. Nó tìm trường `alg` và kiểm tra thuật toán mã hóa của tin nhắn có phải `AES-256-CBC` không, nếu không thì sẽ báo lỗi và thoát.
3. Nếu đúng thuật toán, nó tạo `key` bằng hàm `deriveKey`, trong đó nó tính hash là `SHA256` theo công thức: `kid|peer|caseID`, với `kid` được gắn cứng là `chatapp-web-v2`; còn `iv` sẽ được lấy từ trường `iv`.
4. Tiến hành giải mã ciphertext AES được base64 encode ở trường `ct`.

Vậy câu hỏi bây giờ là ta phải tìm `peer`, `caseID` để băm làm khóa cho AES ở đâu, bên cạnh đó là database lưu tin nhắn của ChatApp này. Câu trả lời của cả 2 câu hỏi có thể tìm được ở `AppData\Roaming\ChatApp\Local State` và `AppData\Roaming\ChatApp\msg_cache.db`:

![](/images/posts/cscv-2026-silent-room/pic6.png)

```json
{
  "profile": {
    "activePeer": "fi-operator-73",
    "caseId": "FI-217",
    "database": "msg_cache.db"
  },
  "install": {
    "resources": "C:\\Users\\A\\AppData\\Local\\Programs\\ChatApp\\resources\\app.bundle.js"
  }
}
```

File `Local State` thực chất là một tệp cấu hình `JSON` dùng để truyền các tham số còn lại để tính ra key của thuật toán AES: `peer` là `fi-operator-73` và `caseID` là `FI-217`, nó trỏ vào database là `msg_cache.db` và tiến hành giải mã bằng script mà chúng ta vừa phân tích ở trên. Vậy ta có thể tính được `key` của ứng dụng này:

```bash
kittne@DESKTOP-C0H1UVN:/mnt/d/sv_it/htb/CSCV2026/for/SilentRoom_public$ echo -n "chatapp-web-v2|fi-operator-73|FI-217" | sha256sum
5cc72b55a0ab3bec95a332c69bae29582ab59181e062d04ea94e9faca648d10d
```

Sau khi có AES key là `5cc72b55a0ab3bec95a332c69bae29582ab59181e062d04ea94e9faca648d10d`, mình mở `msg_cache.db` bằng `DBrowser for SQLite` để xem cấu tạo của 1 tin nhắn để tiến hành viết script giải mã. Database chỉ có 2 bảng là `conversations` và `messages`:

![](/images/posts/cscv-2026-silent-room/pic7.png)

![](/images/posts/cscv-2026-silent-room/pic8.png)

Có tổng cộng 15 tin nhắn, và cấu tạo của cột `body` giống hệt các trường trong file giải mã, vì vậy ta có thể dễ dàng viết 1 script để giải mã hàng loạt:

```python
import base64
import json
import sqlite3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

db_path = "[root]/Users/A/AppData/Roaming/ChatApp/msg_cache.db"
aes_key = bytes.fromhex("5cc72b55a0ab3bec95a332c69bae29582ab59181e062d04ea94e9faca648d10d")

def decrypt(iv_b64, ct_b64, key):
  iv = base64.b64decode(iv_b64)
  ct = base64.b64decode(ct_b64)

  cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
  decryptor = cipher.decryptor()
  padded_pt = decryptor.update(ct) + decryptor.finalize()
  unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
  pt = unpadder.update(padded_pt) + unpadder.finalize()

  return pt.decode("utf-8")



conn = sqlite3.connect(db_path)
cursor = conn.cursor()

query = "SELECT id, direction, body FROM messages;"
cursor.execute(query)
rows = cursor.fetchall()

for row_id, direction, body_str in rows:
  data = json.loads(body_str)
  iv = data.get("iv")
  ct = data.get("ct")

  plaintext = decrypt(iv, ct, aes_key)
  print(f"Message ID: {row_id}" + f" Direction: {direction}")
  print(plaintext)
  print(f"-" * 100)

conn.close()
```

```bash
kittne@DESKTOP-C0H1UVN:/mnt/d/sv_it/htb/CSCV2026/for/SilentRoom_public$ python3 solve.py
Message ID: 1 Direction: in
Em không được để lại lời nhắn. Nếu gia đình biết, hồ sơ sẽ chuyển sang mức khẩn cấp.
----------------------------------------------------------------------------------------------------
Message ID: 2 Direction: in
Họ tên, trường học, CCCD cũ và địa chỉ nhà của em đều nằm trong hồ sơ FI-217. Đừng thử thách hệ thống.
----------------------------------------------------------------------------------------------------
Message ID: 3 Direction: in
Nếu tắt camera, gọi cho bố mẹ, hoặc rời màn hình quá 30 giây, biên bản sẽ ghi là tự ý cản trở điều tra.
----------------------------------------------------------------------------------------------------
Message ID: 4 Direction: in
Em chỉ có một cách chứng minh trong sạch: làm đúng từng bước và giữ im lặng cho đến khi có lệnh mới.
----------------------------------------------------------------------------------------------------
Message ID: 5 Direction: in
Tài khoản của em đang bị đồng bộ với ví trung gian. Một thao tác sai sẽ khóa tài sản của cả gia đình.
----------------------------------------------------------------------------------------------------
Message ID: 6 Direction: in
Mở vé xe, xác nhận PNR rồi ghi nhớ. PNR là một phần khóa đối chiếu, không đọc cho ai.
----------------------------------------------------------------------------------------------------
Message ID: 7 Direction: in
Sau khi xem xong vé và booking, xóa file tải về. Không cần xóa trình duyệt.
----------------------------------------------------------------------------------------------------
Message ID: 8 Direction: in
Nếu có ai hỏi, nói em đang ra sân bay. Không đi theo điểm đỗ nếu chưa có lệnh mới.
----------------------------------------------------------------------------------------------------
Message ID: 9 Direction: in
Ảnh đặt phòng cũ chỉ là bản chụp tại thời điểm đó. Trạng thái trong hệ thống mới là lệnh hợp lệ.
----------------------------------------------------------------------------------------------------
Message ID: 10 Direction: out
Em run quá, em làm sai thì có bị bắt không?
----------------------------------------------------------------------------------------------------
Message ID: 11 Direction: in
Bình tĩnh và làm nhanh. Em đang được đánh dấu là hợp tác, đừng đổi trạng thái từ xác nhận sang khẩn cấp.
----------------------------------------------------------------------------------------------------
Message ID: 12 Direction: out
Em đã xóa vé và ảnh booking rồi.
----------------------------------------------------------------------------------------------------
Message ID: 13 Direction: in
Chỉ làm theo mã còn hiệu lực trong trang đặt phòng. Đừng tin ảnh chụp cũ nếu hệ thống đã cập nhật.
----------------------------------------------------------------------------------------------------
Message ID: 14 Direction: in
Ảnh chứng minh cuối đã khóa theo XOR bằng chuỗi đối chiếu. Nếu máy không mở được, tìm CyberChef và dùng key UTF-8.
----------------------------------------------------------------------------------------------------
Message ID: 15 Direction: in
Thứ tự chuỗi đối chiếu: Mã PNR vé xe|trạng thái đặt phòng bằng chữ|Số phòng|tên nơi ở viết liền|tỉnh thành viết liền.
----------------------------------------------------------------------------------------------------
```

Giờ chúng ta đã rõ đây là 1 vụ lừa đảo, kẻ tấn công đã lừa cô gái đến địa điểm chúng chỉ định nếu không sẽ vô hiệu hóa tài sản của gia đình (xD very realistic plot tho). Ở 2 tin nhắn cuối cùng kẻ tấn công cho chúng ta công thức của chuỗi để làm chuỗi XOR (`Mã PNR vé xe|trạng thái đặt phòng bằng chữ|Số phòng|tên nơi ở viết liền|tỉnh thành viết liền`) với một file nào đó được tải trên trình duyệt để tìm ra ảnh chứng minh cuối.

Sau khi kiểm tra thì chỉ có 1 trình duyệt trên máy của nạn nhân thôi, đó là `Chrome`, `Windows\Prefetch` cũng chỉ có  1 file của `Chrome` được tạo:

![](/images/posts/cscv-2026-silent-room/pic9.png)

Vậy ta biết qua `Chrome`, nạn nhân đã tải các file mà kẻ giả mạo yêu cầu về `Downloads\` và đã xóa chúng trên ổ đĩa, vậy liệu có cách nào tìm lại được các thông tin này không? Câu trả lời là có:

> * `AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data\`: Lưu các tài nguyên mà Chrome đã tải và cache trong quá trình truy cập website, chẳng hạn như hình ảnh, nội dung phản hồi API, JavaScript và các dữ liệu web khác. Vì cache là bản sao riêng, nội dung của một file đã bị xóa khỏi disk vẫn có thể còn tồn tại tại đây và được phục hồi để phân tích.

Tại `[root]\Users\A\AppData\Local\Google\Chrome\User\Data\Default\Cache\Cache_Data\`, ta có thể thấy các file `f_0000*` mang những thông tin rất thú vị:

1. Đầu tiên là `f_000020` lưu các tình trạng đặt phòng và id tương ứng của chúng:

```text
window.__STAYHUB_STATE__={1:'draft',2:'confirmed',4:'checked_in',7:'cancelled',9:'expired'};
```

2. Tiếp theo là file `f_000021` cho t biết lí do tại sao file html ban đầu ở thư mục `Downloads` không phải ảnh đặt phòng chúng ta đang tìm, do state hiện tại của nó là `7` tức cancelled:

```text
{
  "url": "https://stayhub.example/api/reservation/BAB-403DN",
  "reservation": "BAB-403DN",
  "state": 7,
  "previousState": 2,
  "updatedAt": "2026-08-20T06:58:09+07:00",
  "supersededBy": "HSR-260820-0401",
  "displayName": "Babarian Hotel",
  "room": "403",
  "cityCode": "DAD",
  "cacheSource": "reservation-sync"
}
```

3. `f_000033` là ảnh vé xe mà kẻ giả mạo gửi cho nạn nhân, cũng có vẻ chính là ảnh vé xe đã bị xóa ở thư mục `Downloads`, ta có thông tin quan trọng là `PNR: NSE1842` ở ảnh này. 

4. `f_000041` là thông tin khách sạn mới nhất và `f_000054` là ảnh xác nhận đặt của khách sạn đó:

```text
{
  "url": "https://stayhub.example/api/reservation/HSR-260820-0401",
  "reservation": "HSR-260820-0401",
  "state": 2,
  "lodgingRef": "R8QK-72M-19",
  "roomNumber": "401",
  "cityCode": "DAD",
  "checkinFrom": "2026-08-20T19:00:00+07:00",
  "geoHint": "16.071:108.229",
  "mapPinKey": "M-4412"
}
```

![](/images/posts/cscv-2026-silent-room/pic10.png)

Vậy ta đã có chuỗi đối chiếu được nhắc đến: `NSE1842|confirmed|401|HanaRiverSide|DaNang`.

5. `f_000089` chính là nội dung bị mã hóa, theo như thông tin được nhắc đến ở `f_000088`, vì vậy giờ ta có thể sử dụng `CyberChef` để tiến hành giải mã:

![](/images/posts/cscv-2026-silent-room/pic11.png)

Thêm recipe `Render Image` là sẽ thấy flag:

![](/images/posts/cscv-2026-silent-room/pic12.png)

### Flag
* Flag là: `CSCV2026{F04nd_h3r_4t_401_HanaRiverSide_DaNang_fm0923812}`.
