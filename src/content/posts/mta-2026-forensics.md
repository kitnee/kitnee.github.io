---
title: "MTA 2026 — Forensics & Threat Intelligence Writeups"
description: "Vài bài Forensics & Threat Intelligence đã giúp mình rinh chiếc Top 1 đầu tay tại MTA CTF 2026: DDoS và Hunt."
pubDate: 2026-08-15
lang: vi
category: writeup
ctf: "MTA 2026"
tags:
  - "Writeup"
  - "Forensics"
  - "MTA2026"
  - "ThreatIntelligence"
---

## Intro

Here are the challenges that helped me grab my very first CTF achievement: **Top 1 MTA CTF 2026**. A big round of applause for my mentors, teammates, and supporters as well for carrying me to glory.

## Hunt

### 1. Miêu tả bài

Trong quá trình Threat Hunting, chúng tôi phát hiện một địa chỉ C&C được kết nối bởi nhiều máy tính khác nhau trong tổ chức, có lưu lượng mạng đáng ngờ xuất hiện. Đồng thời, chúng tôi đã thu thập được một số tài liệu được cho là đã bị thu thập bởi mã độc có liên quan đến C&C này và bị mã độc lạm dụng. Bạn có thể tìm ra thông tin Username đã tạo tài liệu và hash SHA256 của tài liệu này được không? C&C: dalerocks.com

Format flag: MTA60{username_hash SHA256}

Hint: Have you found the list of IOCs yet?

### 2. Phân tích domain `dalerocks.com`

Điểm xuất phát là tên miền `dalerocks.com`. Khi tìm kiếm tên miền này trên Internet, ta tìm thấy báo cáo [Thông tin các mối đe dọa bảo mật tháng 05/2026 của NCS Group](https://ncsgroup.vn/thong-tin-cac-moi-de-doa-bao-mat-thang-05-2026/). Báo cáo mô tả một chiến dịch phát tán PlugX nhắm vào Việt Nam, sử dụng tệp `LNK`, `PowerShell` và kỹ thuật `DLL side-loading`. Ở cuối chuỗi lây nhiễm, mã độc kết nối tới C2 `dalerocks.com`.

Phần **4.2.1 – Chiến dịch phát tán mã độc PlugX nhắm mục tiêu vào Việt Nam** cung cấp danh sách IoC gồm tám mã băm SHA-256 và chính tên miền trên:

![](/images/posts/mta-2026-hunt/pic1.png)

Trong đó có 8 IOCs, sau khi thử qua thì đây là IoC cần dùng để phân tích:

![](/images/posts/mta-2026-hunt/pic10.png)

```text
504fbe8ad953e5ba270fe0e25fbb494c3360dde794451ae241b52aa9a62f80bb
```

Mẫu này có thể tra cứu trên [MalwareBazaar](https://bazaar.abuse.ch/sample/504fbe8ad953e5ba270fe0e25fbb494c3360dde794451ae241b52aa9a62f80bb/) với tên `Giấy mời.docx.zip`. Rất có thể đây chính là nhánh chứa tài liệu thật đã bị đánh cắp và được tái sử dụng làm mồi nhử.

![](/images/posts/mta-2026-hunt/pic2.png)

### 3. Phân tích `Giấy mời.docx.zip`

Sau khi tải mẫu về và kiểm tra lại mã băm, kết quả khớp với IoC:

```powershell
sha256sum 'Giấy mời.docx.zip'
504fbe8ad953e5ba270fe0e25fbb494c3360dde794451ae241b52aa9a62f80bb  Giấy mời.docx.zip
```

Ta unzip tệp zip này sẽ thu được 1 tệp zip khác:

```bash
7z x Giấy\ mời.docx.zip -pinfected
# thu được: 504fbe8ad953e5ba270fe0e25fbb494c3360dde794451ae241b52aa9a62f80bb.zip
```

File `.zip` mới này nặng tới 654KB, tuy nhiên nếu extract tệp ZIP mới này như bình thường thì chỉ hiển thị một tệp shortcut có nội dung rất nhỏ so với chính file này:

![](/images/posts/mta-2026-hunt/pic3.png)

```text
Giấy mời.docx.lnk
```

![](/images/posts/mta-2026-hunt/pic4.png)

Đây là shortcut Windows. Sử dụng `strings -el` để kiểm tra, ta thấy shortcut này chứa lệnh PowerShell với các thao tác chính sau:

1. Đọc lại chính tệp ZIP ban đầu.
2. Lấy `668160` byte dữ liệu kể từ offset `1090`.
3. Ghi phần dữ liệu này thành `%LocalAppData%\ifyfdaoj.qc`.
4. Dùng `tar.exe` giải nén tệp vừa tạo vào `%LocalAppData%`.
5. Khởi chạy `%LocalAppData%\DHJ0I9RK-42ZJ-5KYX-95QA-5C53J2XWRKGE\CNMNSST.exe`.

![](/images/posts/mta-2026-hunt/pic5.png)

Như vậy ta đã có payload TAR được nối ẩn phía sau dữ liệu ZIP. Sau khi tách và giải nén payload, thư mục thu được chứa bộ ba thành phần:

![](/images/posts/mta-2026-hunt/pic6.png)

| Tệp | Vai trò |
|---|---|
| `CNMNSST.exe` | Tệp thực thi hợp lệ, có chữ ký số của Canon |
| `CNCLID.dll` | DLL độc hại được nạp bằng kỹ thuật DLL side-loading |
| `Canon.dat` | Payload PlugX đã mã hóa và dữ liệu tài liệu mồi |

Khi `CNMNSST.exe` chạy, chương trình nạp `CNCLID.dll` từ cùng thư mục. DLL này tiếp tục đọc, giải mã và thực thi payload trong `Canon.dat`. Chuỗi này phù hợp với mô tả kỹ thuật trong báo cáo NCS.

Các mã băm liên quan trực tiếp tới nhánh `Giấy mời` là:

| Thành phần | SHA-256 |
|---|---|
| `Giấy mời.docx.zip` | `504fbe8ad953e5ba270fe0e25fbb494c3360dde794451ae241b52aa9a62f80bb` |
| `Giấy mời.docx.lnk` | `7ba9c652b8cad91cb764a641def3dd9c559cb035e154015d0eac1cf935c89759` |
| `CNCLID.dll` | `f93923341c3e4b43015a2a1ca0b21ec115035447f2398eaea1aff1377f6d9d5d` |
| `Canon.dat` | `1e05e5ec247641bfcfa51ea16d45a5330a8bcd2d4d5c8593be375c3e2acf9b82` |

### 4. Tách tài liệu mồi khỏi `Canon.dat`

Khi kiểm tra `Canon.dat`, ta có thể tìm thấy chữ ký đầu tệp ZIP `PK\x03\x04` tại offset `276574`. Khác với phần payload bị mã hóa, vùng dữ liệu này là một tệp ZIP đọc được trực tiếp. Bên cạnh đó nội dung trong file zip còn thể hiện các thuộc tính của 1 file `.docx` đó là `[Content_Types].xml`, `rels\.rels`,... Đây là dấu hiệu cho thấy một tài liệu Word đã được nối vào `Canon.dat`.

![](/images/posts/mta-2026-hunt/pic7.png)

Có thể tách phần overlay bằng lệnh sau:

```bash
dd if=Canon.dat of=decoy.docx bs=1M skip=276574 status=none
file decoy.docx
sha256sum decoy.docx
```

![](/images/posts/mta-2026-hunt/pic8.png)

Phần overlay có kích thước `18158` byte. Tệp thu được là một DOCX hợp lệ, chứa đầy đủ các thành phần như `[Content_Types].xml`, `word/document.xml` và `docProps/core.xml`. Mã băm của tài liệu là:

```text
0e1af119fcdf669dc18377ab346217b6b0d247c28d330a5a80f14aadc1d92225
```

Nội dung tài liệu là giấy mời của Viện Đào tạo và Phát triển nhân lực mời tham dự khai mạc. Nội dung có tính thực tế nên có vẻ đây là tài liệu bị thu thập rồi tái sử dụng làm mồi nhử, đúng với dữ kiện của đề bài.

### 5. Xác định username tạo tài liệu

Metadata của tài liệu nằm trong `docProps/core.xml`. Có thể đọc trực tiếp mà không cần mở tài liệu:

```bash
7z x decoy.docx
```

Các trường đáng chú ý:

```xml
<dc:creator>AutoBVT</dc:creator>
<cp:lastModifiedBy>HieuGLLite</cp:lastModifiedBy>
<dcterms:created>2026-04-14T07:03:00Z</dcterms:created>
<dcterms:modified>2026-04-14T07:13:00Z</dcterms:modified>
```

![](/images/posts/mta-2026-hunt/pic9.png)

### 6. Flag

Trường `lastModifiedBy` là trường đáp án chứ không phải trường creator. Ghép username của người tạo tài liệu với SHA-256 của chính tài liệu theo định dạng đề bài:

```text
username = HieuGLLite
SHA-256 = 0e1af119fcdf669dc18377ab346217b6b0d247c28d330a5a80f14aadc1d92225
```

Flag:

```text
MTA60{HieuGLLite_0e1af119fcdf669dc18377ab346217b6b0d247c28d330a5a80f14aadc1d92225}
```

---

## DDoS

### 1. Miêu tả bài

A bank's international payment application was hit by a DDoS attack. The investigation team extracted logs from that application to investigate the cause of the DDoS attack on the international payment gateway. Investigate how the attacker group carried out the DDoS attack on the bank's international payment gateway and find the attacker's IP address.

Format: MTA60{sha256(IP)}

### 2. Phân tích log

File log có dạng JSON theo từng dòng, trong đó các trường quan trọng gồm:

![](/images/posts/mta-2026-ddos/pic1.png)

- `timestamp`: thời điểm request.
- `clientip`: IP gửi request.
- `request`: phương thức và đường dẫn request.
- `status`: HTTP status.
- `user_agent`: User-Agent.
- `request_time`, `upstream_status`, `upstream_response_time`: thời gian xử lý và trạng thái backend.

Các request lỗi 404 tăng mạnh từ khoảng `2026-07-15T23:15:25+07:00`. Dòng đầu tiên dễ nhận thấy của cụm DDoS là:

![](/images/posts/mta-2026-ddos/pic2.png)

```text
timestamp: 2026-07-15T23:15:25+07:00
clientip: 188.165.59.127
status: 404
request: GET /payment/checkout?data?q=Okp4p18eFzgp HTTP/2.0
```

Khi thống kê các endpoint liên quan đến thanh toán, ta thấy có hai nhóm request bất thường:

```text
GET /payment/checkout?data?q=<random>
GET /payment/checkout?data=<token>
```

#### Nhóm 1:

Nhóm đầu tiên có số lượng rất lớn. Sau tham số `q` luôn là chuỗi ngẫu nhiên 12 ký tự, ví dụ:

![](/images/posts/mta-2026-ddos/pic3.png)

```text
/payment/checkout?data?q=Okp4p18eFzgp
/payment/checkout?data?q=3JGp5t8j59YJ
/payment/checkout?data?q=8MN6s64P4Upj
```

Đây là vector flood chính dùng để gây tải lên endpoint checkout. Tuy nhiên dễ thấy các IP gửi nhiều request trong nhóm này chỉ là các bot/proxy tham gia DDoS chứ không phải IP thật của attacker.

Khi nhờ AI phân tích, ta thu được hầu hết IP trong pha này gửi số request theo bội số của 64. Đây là dấu hiệu của công cụ DDoS chia việc thành các batch cố định qua danh sách proxy. Nhiều request còn bị chuyển qua cả hai upstream là `10.16.11.69:443` và `10.16.11.68:443`.

Một request sai định dạng vẫn có thể khiến ứng dụng thử nhiều backend trước khi trả lỗi, làm tăng chi phí xử lý phía ngân hàng. Sau khi xong giải và về nhà tìm hiểu thì mình biết đây là dấu hiệu của HTTP Layer-7 GET flood vào endpoint checkout.

#### Nhóm 2:

Nhóm thứ hai là replay một token thanh toán hợp lệ:

![](/images/posts/mta-2026-ddos/pic4.png)

```text
eyJpZCI6MTg2MjE1NjEyOSwiY29udHJvbCI6ImEyYzcyMzBlODViYzU4M2UwNWRkMzc4OTFmYWNhZmRiIn0=
```

Giải mã Base64:

```json
{"id":1862156129,"control":"a2c7230e85bc583e05dd37891facafdb"}
```

Như vậy attacker dùng hai chiến thuật:

```text
Pha 1: malformed-query flood qua proxy pool
Pha 2: valid-token flood qua proxy/Tor/VPS pool
```

### Workflow của phiên thanh toán bình thường

Sau một lúc quan sát, ta thấy được một phiên thanh toán bình thường thường có flow:

```text
GET /payment/checkout?data=<token>
        |
        v
Tải CSS, JavaScript, ảnh, favicon
        |
        v
POST /payment/checkout
        |
        v
/payment/status hoặc /payment/threeds
        |
        v
/payment/complete
```

![](/images/posts/mta-2026-ddos/pic5.png)

Thông thường, người dùng chỉ làm việc với một token tại một thời điểm, có chuỗi tải asset và các bước thanh toán tiếp theo. Không tự nhiên rảnh mà họ phát token qua Telegram, kích hoạt nhiều node kiểm tra hạ tầng, và quay lại token cũ đúng lúc hệ thống đang bị DDoS để kiểm tra lỗi.

Từ baseline này, tư duy là cần tìm IP có hành vi chuẩn bị khác biệt chứ không phải chỉ tìm IP gửi flood.

### Dấu vết operator

Khi kiểm tra các request trước thời điểm DDoS, ta thấy IP `42.114.215.243` có hành vi bất thường:

Tại `2026-07-15T21:48:46+07:00`, IP này truy cập hai checkout token khác nhau gần như cùng lúc:

![](/images/posts/mta-2026-ddos/pic6.png)

```text
728891:
timestamp: 2026-07-15T21:48:46+07:00
clientip: 42.114.215.243
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjEwNDU5OSwiY29udHJvbCI6IjE5Y2M1MjFhZjU4MjU0NzVlNGFlYjA2ODU4N2M5NjY1In0%3D HTTP/2.0
user_agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_2_1 like Mac OS X) ...

728892:
timestamp: 2026-07-15T21:48:46+07:00
clientip: 42.114.215.243
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjEwMzgyMywiY29udHJvbCI6IjUwZGE5NTg3ZmZlMjI5YjhjN2ZjNmJiMjgzMzQyODYwIn0%3D HTTP/2.0
user_agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_2_1 like Mac OS X) ...
```

Hai token này giải mã Base64 lần lượt là:

```json
{"id":1862104599,"control":"19cc521af5825475e4aeb068587c9665"}
{"id":1862103823,"control":"50da9587ffe229b8c7fc6bb283342860"}
```

Ngay sau đó, token `1862104599` xuất hiện từ TelegramBot:

![](/images/posts/mta-2026-ddos/pic7.png)

![](/images/posts/mta-2026-ddos/pic8.png)

```text
729051:
timestamp: 2026-07-15T21:48:53+07:00
clientip: 149.154.161.20
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjEwNDU5OSwiY29udHJvbCI6IjE5Y2M1MjFhZjU4MjU0NzVlNGFlYjA2ODU4N2M5NjY1In0%3D HTTP/1.1
user_agent: TelegramBot (like TwitterBot)
```

`149.154.161.20` là TelegramBot tạo preview cho đường link được gửi qua Telegram. Khoảng vài giây sau TelegramBot, token tiếp tục được mở bởi IP `5.18.87.231`:

```text
729189:
timestamp: 2026-07-15T21:48:58+07:00
clientip: 5.18.87.231
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjEwNDU5OSwiY29udHJvbCI6IjE5Y2M1MjFhZjU4MjU0NzVlNGFlYjA2ODU4N2M5NjY1In0%3D HTTP/2.0
```

IP này có thể là thiết bị thứ hai hoặc một thành viên khác trong nhóm, nhưng không phải IP đầu tiên của chuỗi recon. Sau đó cùng token này tiếp tục được truy cập từ nhiều node `CheckHost`:

```text
729484:
timestamp: 2026-07-15T21:49:07+07:00
clientip: 185.209.161.169
user_agent: CheckHost (https://check-host.net/)

729487:
timestamp: 2026-07-15T21:49:07+07:00
clientip: 179.43.148.195
user_agent: CheckHost (https://check-host.net/)

729492:
timestamp: 2026-07-15T21:49:07+07:00
clientip: 88.119.179.10
user_agent: CheckHost (https://check-host.net/)
```

![](/images/posts/mta-2026-ddos/pic9.png)

Điều này cho thấy link checkout được IP `42.114.215.243` mở trước, sau đó bị đưa ra Telegram và dịch vụ CheckHost để kiểm tra khả năng truy cập từ nhiều nơi. Đây là hành vi chuẩn bị và kiểm tra mục tiêu trước khi tấn công, không giống hành vi khách hàng bình thường.

Chuỗi recon có thể tóm tắt như sau:

```text
42.114.215.243
        | khoảng 7 giây
        v
TelegramBot
        | khoảng 5 giây
        v
5.18.87.231
        | khoảng 9 giây
        v
nhiều node CheckHost
```

Đến `22:04:36`, `42.114.215.243` tiếp tục mở thêm một token thanh toán mới:

![](/images/posts/mta-2026-ddos/pic10.png)

```text
749332:
timestamp: 2026-07-15T22:04:36+07:00
clientip: 42.114.215.243
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjExMDM3NywiY29udHJvbCI6IjlhMzg1NzljNWRkYWJkOTFhNjhhNTExZGU2NTJlNGQ4In0%3D HTTP/2.0

749355:
timestamp: 2026-07-15T22:04:38+07:00
clientip: 42.114.215.243
status: 200
request: GET /payment/checkout?data=eyJpZCI6MTg2MjExMDM3NywiY29udHJvbCI6IjlhMzg1NzljNWRkYWJkOTFhNjhhNTExZGU2NTJlNGQ4In0%3D HTTP/2.0
```

Request được lặp lại sau hai giây nhưng không có flow hoàn tất giao dịch. Điều này tiếp tục củng cố giả thuyết IP này đang kiểm tra endpoint thanh toán, không thực hiện giao dịch bình thường.

### Liên hệ với thời điểm DDoS

Trong thời gian DDoS đang diễn ra, token `1862103823` mà `42.114.215.243` từng mở trước đó lại xuất hiện.

![](/images/posts/mta-2026-ddos/pic11.png)

![](/images/posts/mta-2026-ddos/pic12.png)

```text
1737863:
timestamp: 2026-07-15T23:24:52+07:00
clientip: 37.110.114.174
status: 200
request: GET /payment/checkout?data=...1862103823...

1743167:
timestamp: 2026-07-15T23:24:59+07:00
clientip: 37.110.114.174
status: 499
request: GET /payment/checkout?data=...1862103823...

1746839:
timestamp: 2026-07-15T23:25:08+07:00
clientip: 42.114.215.243
status: 499
request: GET /payment/checkout?data=eyJpZCI6MTg2MjEwMzgyMywiY29udHJvbCI6IjUwZGE5NTg3ZmZlMjI5YjhjN2ZjNmJiMjgzMzQyODYwIn0%3D HTTP/2.0
upstream_status: 500, -
```

Dòng cuối rất quan trọng: chính IP `42.114.215.243` quay lại kiểm tra token cũ trong lúc hệ thống đã bị ảnh hưởng bởi DDoS. Request trả về `499` và backend có `upstream_status: 500, -`, phù hợp với trạng thái gateway đang lỗi.

IP này không kiểm tra token DDoS `1862156129` trực tiếp. Thay vào đó, nó dùng token cũ làm một control URL để xem cổng thanh toán còn hoạt động hay không. Kết quả `500` rồi timeout cho thấy cuộc tấn công đã ảnh hưởng đến backend. Hành vi này rất phù hợp với attacker kiểm tra hiệu quả của cuộc tấn công.

### Kết luận

Cuộc tấn công được thực hiện theo hướng:

1. Operator truy cập các link checkout hợp lệ để lấy/kiểm tra token.
2. Link checkout được đưa qua Telegram và CheckHost để kiểm tra khả năng truy cập từ nhiều vị trí.
3. Sau đó botnet/proxy flood endpoint:

```text
GET /payment/checkout?data?q=<random>
```

và replay các checkout token, gây lỗi `499`, `500`, `502`, `504` trên gateway.

Flow tổng quát:

```text
[42.114.215.243]
        |
        ├── Mở nhiều token thanh toán để recon
        ├── Gửi token thử qua Telegram
        |          └── TelegramBot tạo preview
        ├── Token được mở từ thiết bị/IP thứ hai
        ├── Kích hoạt CheckHost từ nhiều vị trí
        v
[Chuẩn bị proxy/Tor/VPS pool]
        |
        ├── Pha 1: malformed GET requests
        ├── Pha 2: GET requests replay token hợp lệ
        v
[Backend quá tải, xuất hiện 500/499/timeout]
        |
        v
[42.114.215.243]
Kiểm tra lại token cũ để xác nhận tác động
```

Các IP có lượng request lớn chỉ là bot/proxy trong DDoS. IP để lại dấu vết chuẩn bị và kiểm tra tấn công là:

```text
42.114.215.243
```

Ta tính được SHA-256 của chuỗi IP bằng lệnh sau:

```bash
printf '42.114.215.243' | sha256sum
# thu được: 5d8ff637aa91217932331185a75808fdc42762b0dd5173f25db0caca4383c403

```

### Flag

```text
MTA{5d8ff637aa91217932331185a75808fdc42762b0dd5173f25db0caca4383c403}
```
