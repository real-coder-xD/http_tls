# http_tls

Thư viện HTTP client hiệu năng cao viết bằng **Rust (PyO3 + Tokio + Reqwest + Rustls)** cho Python, tích hợp công nghệ giả lập chữ ký TLS (**JA3 / JA4**), **HTTP/2 Frames** và Browser Headers (Chrome, Safari, Firefox, Edge, Tor).

**Thay thế trực tiếp 100% cho cả `requests` và `curl_cffi`:**
```python
import http_tls as requests          # Thay thế hoàn toàn requests
from http_tls import requests        # Thay thế hoàn toàn curl_cffi.requests
```

---

## Mục lục
1. [Tính năng nổi bật](#1-tính-năng-nổi-bật)
2. [Cài đặt & Biên dịch](#2-cài-đặt--biên-dịch)
3. [Hướng dẫn sử dụng](#3-hướng-dẫn-sử-dụng)
   - [Chế độ 1: Thay thế trực tiếp `requests`](#chế-độ-1-thay-thế-trực-tiếp-thư-viện-requests)
   - [Chế độ 2: Thay thế trực tiếp `curl_cffi`](#chế-độ-2-thay-thế-trực-tiếp-curl_cffi)
   - [Chế độ 3: Cú pháp Native `http_tls`](#chế-độ-3-cú-pháp-native-http_tls)
4. [Lập trình Bất đồng bộ (AsyncSession)](#4-lập-trình-bất-đồng-bộ-asyncsession)
5. [Chi tiết đối tượng Response & Bắt lỗi](#5-chi-tiết-đối-tượng-response--bắt-lỗi)
6. [Danh sách Browser Presets (Cập nhật 15/11/2026)](#6-danh-sách-browser-presets-cập-nhật-15112026)
7. [Kiến trúc Dual-Engine](#7-kiến-trúc-dual-engine)
8. [Kinh nghiệm thực chiến vượt Cloudflare / Akamai WAF](#8-kinh-nghiệm-thực-chiến-vượt-cloudflare--akamai-waf)

---

## 1. Tính năng nổi bật

- **Chữ ký TLS Byte-Exact (JA4):** Tạo đúng 15 cipher suites, thứ tự extensions, elliptic curves và token GREASE chuẩn xác của Google Chrome (`t13d1517h2_...`).
- **HTTP/2 Pseudo-Headers Chuẩn:** Đảm bảo thứ tự pseudo-header `:method`, `:authority`, `:scheme`, `:path` (**`m,a,s,p`**), đồng bộ Akamai HTTP/2 Settings Frame và Window Update với trình duyệt thật.
- **Tương thích ngược 100%:** Hỗ trợ toàn bộ API của `requests` (`Session`, `codes`, `exceptions`, `raise_for_status()`, Case-Insensitive Headers) và `curl_cffi` (`BrowserType`, `impersonate`).
- **Tối ưu Concurrency & GIL:** Nhả Python Global Interpreter Lock (GIL) trong thời gian thực thi I/O mạng, giúp khai thác tối đa CPU đa nhân khi chạy đa luồng (`threading`) hoặc bất đồng bộ (`asyncio`).
- **Đóng gói CPython Stable ABI3:** Wheel build ra tương thích trực tiếp với tất cả các bản Python từ 3.8 đến 3.14+ mà không cần biên dịch lại.

---

## 2. Cài đặt & Biên dịch

### Cách 1: Cài đặt từ mã nguồn bằng Maturin

Yêu cầu máy đã cài Rust (`cargo`) và Python (>= 3.8):

```powershell
# Di chuyển vào thư mục dự án
cd D:\http_tls

# Cài đặt công cụ đóng gói Maturin
pip install maturin

# Biên dịch bản release và cài đặt thẳng vào môi trường Python
$env:PYO3_USE_ABI3_FORWARD_COMPATIBILITY = "1"
maturin build --release
python -m pip install --force-reinstall .\target\wheels\http_tls-0.2.0-cp38-abi3-win_amd64.whl
```

### Cách 2: Kiểm tra cài đặt thành công

```bash
python -c "import http_tls; print(http_tls.__version__); print(http_tls.supported_presets()[:5])"
```

---

## 3. Hướng dẫn sử dụng

### Chế độ 1: Thay thế trực tiếp thư viện `requests`

Giữ nguyên 100% codebase cũ, chỉ cần thay đổi dòng import đầu file:

```python
import http_tls as requests

# 1. GET đơn giản kèm query parameters
resp = requests.get(
    "https://httpbin.org/get",
    params={"page": 1, "query": "rust"},
    timeout=10.0
)
resp.raise_for_status()

# 2. Kiểm tra status code qua requests.codes chuẩn
if resp.status_code == requests.codes.ok:
    print("Request thành công!")

# 3. Headers không phân biệt hoa thường (Case-Insensitive)
print(resp.headers["content-type"])
print(resp.headers["Content-Type"])

# 4. POST gửi dữ liệu JSON hoặc Form
r_post = requests.post(
    "https://httpbin.org/post",
    json={"username": "user123", "role": "admin"},
    headers={"X-Custom-Client": "http_tls"}
)
print("Data trả về:", r_post.json()["json"])

# 5. Sử dụng Session để giữ Cookie & Connection Pool
with requests.Session() as s:
    # Cập nhật header chung cho toàn bộ session
    s.headers.update({"Authorization": "Bearer my_token_123"})
    
    # Request 1: Nhận cookie
    s.get("https://httpbin.org/cookies/set?session_id=abc999")
    
    # Request 2: Tự động gửi kèm cookie và header đã lưu
    r_check = s.get("https://httpbin.org/cookies")
    print("Session Cookies:", r_check.json()["cookies"])
```

---

### Chế độ 2: Thay thế trực tiếp `curl_cffi`

Nếu project đang sử dụng cú pháp `curl_cffi.requests` và `BrowserType`:

```python
from http_tls import requests
from http_tls import BrowserType

# Sử dụng BrowserType Enum hoặc string
resp = requests.get(
    "https://www.upwork.com",
    impersonate=BrowserType.chrome152,  # hoặc: impersonate="chrome152"
    verify=True,
    proxies={"all": "http://user:pass@proxy.example.com:8080"}
)
print("Status:", resp.status_code)
print("CF-Ray:", resp.headers.get("cf-ray"))

# Sử dụng Session với impersonate
with requests.Session(impersonate=BrowserType.chrome152) as session:
    res = session.get("https://discord.com")
    print("Discord Status:", res.status_code)
```

---

### Chế độ 3: Cú pháp Native `http_tls`

Dành cho các dự án mới muốn sử dụng API gọn gàng:

```python
import http_tls

# Tự động chọn preset mới nhất (Chrome 152)
resp = http_tls.get("https://httpbin.org/headers")
print(resp.json()["headers"]["User-Agent"])

# Chỉ định rõ preset khác
resp_safari = http_tls.get("https://httpbin.org/headers", impersonate="safari_27")
resp_firefox = http_tls.get("https://httpbin.org/headers", impersonate="firefox_155")
```

---

## 4. Lập trình Bất đồng bộ (AsyncSession)

Thư viện cung cấp `AsyncSession` chuẩn `asyncio` để crawler/scraper cào hàng nghìn URLs song song mà không block Event Loop:

```python
import asyncio
import http_tls

async def fetch_worker(session: http_tls.AsyncSession, index: int):
    url = f"https://httpbin.org/get?item={index}"
    try:
        resp = await session.get(url, timeout=10.0)
        return resp.status_code, resp.json()["args"]
    except Exception as e:
        return None, str(e)

async def main():
    # Khởi tạo AsyncSession giả lập Chrome 152
    async with http_tls.AsyncSession(impersonate="chrome_152") as session:
        # Bắn đồng loạt 20 requests song song
        tasks = [fetch_worker(session, i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        for status, data in results:
            print(f"Status: {status} | Args: {data}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 5. Chi tiết đối tượng Response & Bắt lỗi

### Các thuộc tính và phương thức của `Response`:

| Thuộc tính / Hàm | Kiểu dữ liệu | Mô tả |
| :--- | :---: | :--- |
| `resp.status_code` | `int` | Mã trạng thái HTTP (200, 301, 403, 404, 500, ...) |
| `resp.ok` | `bool` / callable | Trả về `True` nếu mã trạng thái từ 200 đến 399 |
| `resp.headers` | `CaseInsensitiveDict` | Headers trả về, không phân biệt hoa thường |
| `resp.text` | `str` | Nội dung văn bản phản hồi (tự động giải mã UTF-8) |
| `resp.content` | `bytes` | Dữ liệu nhị phân nguyên bản (dùng để lưu file, ảnh) |
| `resp.json(**kwargs)` | `dict` / `list` | Tự động parse JSON |
| `resp.cookies` | `dict` | Danh sách Cookie nhận được từ server |
| `resp.url` | `str` | URL cuối cùng sau khi hoàn tất redirect |
| `resp.elapsed` | `float` | Thời gian phản hồi tính bằng giây |
| `resp.raise_for_status()` | hàm | Bắn lỗi `HTTPError` nếu server trả về 4xx hoặc 5xx |

### Xử lý Ngoại lệ (Exceptions):

Mô hình bắt lỗi hoàn toàn tương thích với `requests.exceptions`:

```python
import http_tls as requests

try:
    resp = requests.get("https://httpbin.org/status/500", timeout=5.0)
    resp.raise_for_status()
except requests.exceptions.Timeout:
    print("Lỗi: Quá thời gian chờ phản hồi (Timeout)!")
except requests.exceptions.ConnectionError:
    print("Lỗi: Không thể kết nối tới máy chủ (DNS/Network down)!")
except requests.exceptions.HTTPError as err:
    print(f"Lỗi HTTP: {err.response.status_code} - {err}")
except requests.exceptions.RequestException as err:
    print("Lỗi tổng quát:", err)
```

---

## 6. Danh sách Browser Presets (Cập nhật 15/11/2026)

Thư viện hỗ trợ 35+ presets trình duyệt thực tế được cập nhật đến tháng 11/2026:

### Google Chrome (Mặc định: `chrome_152`)
- **`chrome_152`** *(Bản phát hành mới nhất - Windows 10/11 x64)*
- **`chrome_152_macos`** *(macOS)*
- **`chrome_151`**, **`chrome_151_macos`**
- **`chrome_150`**, **`chrome_146`**, **`chrome_145`**, **`chrome_142`**
- **`chrome_136`**, **`chrome_133`**
- **`chrome_131`**, **`chrome_131_android`**
- **`chrome_130`**, **`chrome_128`**, **`chrome_126`**, **`chrome_124`**

> **Dynamic Version Generator:** Bạn có thể truyền bất kỳ số phiên bản Chrome nào (ví dụ: `chrome_135`, `chrome_148`), engine sẽ tự động sinh token GREASE, User-Agent và Sec-CH-UA chuẩn xác.

### Microsoft Edge
- `edge_152`, `edge_142`, `edge_131`, `edge_128`, `edge_124`

### Safari (WebKit)
- `safari_27` (macOS 27.0), `safari_26`, `safari_18_4`, `safari_18`, `safari_17`

### Mozilla Firefox
- `firefox_155`, `firefox_154`, `firefox_153`, `firefox_147`, `firefox_144`, `firefox_135`, `firefox_133`, `firefox_130`

### Tor Browser
- `tor_14_5`

---

## 7. Kiến trúc Dual-Engine

Bạn có thể chủ động chuyển đổi động cơ xử lý qua tham số `engine`:

```python
import http_tls

# Chế độ 1: engine="impersonate" (Mặc định / Auto)
# Giả lập 100% byte-exact chữ ký TLS JA4 & HTTP/2 frames của Chrome.
# Dùng để vượt các WAF khó tính nhất: Cloudflare Bot Management, Akamai, DataDome.
with http_tls.Session(impersonate="chrome_152", engine="impersonate") as s:
    resp = s.get("https://www.upwork.com")

# Chế độ 2: engine="rust"
# Sử dụng 100% Rust Tokio + Rustls runtime.
# An toàn bộ nhớ tuyệt đối (RAII), độc lập hoàn toàn với runtime C, không sợ crash pointer.
with http_tls.Session(impersonate="chrome_152", engine="rust") as s:
    resp = s.get("https://httpbin.org/get")
```

---

## 8. Kinh nghiệm thực chiến vượt Cloudflare / Akamai WAF

### 1. Phân biệt 3 cấp độ phòng thủ của Cloudflare:

1. **Cấp độ 1 (CDN & Basic WAF):**
   - Chỉ kiểm tra User-Agent, Headers, IP rate-limit.
   - **`http_tls` vượt 100%** ngay cả ở chế độ mặc định.
2. **Cấp độ 2 (Cloudflare Bot Management / Super Bot Fight Mode):**
   - Soi xét chữ ký **JA4 TLS** (phải có 15 cipher suites + GREASE) và thứ tự **HTTP/2 pseudo-headers** (`:method`, `:authority`, `:scheme`, `:path`).
   - Nếu dùng `requests` thường sẽ bị trả về **HTTP 403**.
   - **`http_tls` (với `impersonate="chrome_152"`) vượt 100%** (Đã kiểm chứng trên Upwork, TradingView, Discord, GitLab).
3. **Cấp độ 3 (Cloudflare Turnstile - JavaScript "Just a moment..."):**
   - Trả về mã HTTP 403 kèm trang HTML bắt trình duyệt thực thi đoạn mã JavaScript giải đố (Proof-of-Work).
   - **Không có HTTP client nào tự chạy JS được.** Cần áp dụng 2 kỹ thuật dưới đây:

### 2. Kỹ thuật vượt Cấp độ 3:

#### Cách 1: Sử dụng Residential Proxy sạch (Tối ưu nhất)
Cloudflare chỉ kích hoạt trang giải đố JS nếu IP của bạn có điểm uy tín xấu (IP Data Center, VPN giá rẻ, IP bị spam). Khi kết hợp `http_tls` với một Residential Proxy sạch, Cloudflare sẽ bỏ qua trang challenge và trả thẳng **HTTP 200**:

```python
import http_tls as requests

resp = requests.get(
    "https://target-site.com",
    impersonate="chrome_152",
    proxies={"all": "http://user:pass@residential-proxy.net:9999"}
)
print("Bypass thành công:", resp.status_code)
```

#### Cách 2: Bắt cầu Cookie `cf_clearance`
Sử dụng một headless browser siêu nhẹ (như `nodriver` hoặc `playwright`) chạy nền 1 lần để vượt Turnstile lấy cookie `cf_clearance`, sau đó nạp cookie này vào `http_tls.Session`:

```python
import http_tls as requests

with requests.Session(
    impersonate="chrome_152",
    cookies={"cf_clearance": "TOKEN_LAY_DUOC_TU_BROWSER"}
) as session:
    resp = session.get("https://community.cloudflare.com")
    print("Vượt Challenge thành công:", resp.status_code) # 200 OK
```

---

## Giấy phép (License)

Dự án phát hành theo giấy phép **MIT License**.
