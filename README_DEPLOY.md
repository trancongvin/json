# Kiro Account Checker — Web UI

Web app check account Kiro: chọn **Microsoft** hoặc **IAM Identity Center**, dán danh sách
account, bấm nút, kết quả hiện dần. Có 4 chế độ:

| Chế độ | Nút | Làm gì |
|---|---|---|
| Check pass | ▶ Run | Xác nhận pass Right/Wrong/Error |
| Full check | ▶ Run + ô Full | pass → **power credit** (đã dùng/tổng/ngày reset) → **API keys** |
| Check keys | 🔑 Check keys | Cào list **API key `ksk_`** + ngày tạo trên portal |
| Delete keys | 🗑 Delete keys | **Xóa key chọn lọc** theo tên (hoặc xóa hết) |

Account bị ép đổi pass (Microsoft & IAM) → tool tự sinh pass mới ngẫu nhiên, hoàn tất
login, hiển thị pass mới ở cột **New Pass** (nhớ lưu). Backend tái dụng logic trong
`batch.py` + `kiro_helper.py` (không viết lại).

## File
- `web.py` — Flask app (auth + API + 1 worker thread giữ 1 browser Playwright).
- `templates/index.html`, `templates/login.html` — UI.
- `batch.py`, `kiro_helper.py`, `kiro_usage.py` — logic (check pass + credit + cào/xóa key).
- `requirements.txt`, `Dockerfile`, `render.yaml` — deploy.
- `.gitignore` — **loại sẵn** mọi file chứa secret (`accounts.csv`, `*.json` token, `out/`).
- `accounts.csv.example` — mẫu danh sách account (copy thành `accounts.csv` để dùng).

## Chạy LOCAL
```powershell
cd h:\Tải\json
$env:CHECKPASS_PASSWORD="mat-khau-cua-ban"
$env:COOKIES_SECURE="0"      # local la http -> tat Secure; cloud (https) bo dong nay
python web.py
```
Mở http://localhost:5000 → nhập mật khẩu → dùng.

> `CHECKPASS_PASSWORD` là **bắt buộc** (app từ chối chạy nếu thiếu). Muốn chạy không mật khẩu (chỉ local) thì set `ALLOW_NOAUTH=1`. Dùng mật khẩu mạnh (≥8 ký tự).

## Deploy lên Render (global, có HTTPS + mật khẩu)

### Bước 1 — đưa code lên GitHub

`.gitignore` đã loại sẵn mọi file chứa secret (account, token, log), nên chỉ cần push bình
thường là an toàn. Chọn 1 trong 2 cách:

**Cách A — GitHub Desktop (GUI, dễ nhất, không cần gõ lệnh):**
1. Tải + cài **GitHub Desktop** (desktop.github.com) → đăng nhập GitHub.
2. **File → New Repository…** → "Local path" trỏ tới thư mục này (`H:\Tải\json`).
   GitHub Desktop tự đọc `.gitignore` → các file secret (`accounts.csv`, `*.json`, `out/`)
   sẽ KHÔNG xuất hiện trong danh sách change.
3. Đặt tên repo → **Create repository** → **Publish repository** (chọn public nếu muốn người
   khác clone/dùng, hoặc private).
4. Kiểm tra: danh sách file được push KHÔNG có `accounts.csv` hay `CLIProxyAPI_*.json`.

**Cách B — git command-line:**
```powershell
# (cài git nếu chưa: winget install Git.Git  rồi mở terminal mới)
cd h:\Tải\json
git init
git add .                       # .gitignore tự loại secret
git commit -m "Kiro account checker (pass + credit + keys)"
# tạo repo rỗng trên github.com (không tick README/.gitignore) rồi copy URL của nó:
git branch -M main
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main
```

> Đăng nhập GitHub từ git: dùng **Personal Access Token** (github.com → Settings → Developer
> settings → Tokens) làm mật khẩu khi push, hoặc GitHub CLI (`gh auth login`). KHÔNG dán token
> vào đâu khác ngoài máy của bạn.

### Bước 2 — tạo service trên Render
1. Vào https://render.com → **New +** → **Blueprint** → chọn repo.
2. Render tự đọc `render.yaml` (service `kiro-checker`, runtime docker, plan free).
3. Khi được hỏi biến môi trường, nhập:
   - `CHECKPASS_PASSWORD` = mật khẩu truy cập web của bạn.
   - (`SECRET_KEY` Render tự sinh; `OUT_DIR` đã có sẵn.)
4. **Apply** → Render build image (cài Chromium + Playwright, ~3–5 phút lần đầu) → deploy.

### Bước 3 — dùng
Render cấp 1 URL kiểu `https://kiro-checker-xxxx.onrender.com` → mở, nhập mật khẩu, dán account, Run.

## Lưu ý quan trọng
- **Plan free**: 512MB RAM, sleep sau 15' không hoạt động (lần truy cập sau cần ~30s wake). Nếu check nhiều acc hoặc cần ổn định → đổi plan **Starter**.
- **1 job/lúc + giới hạn**: 1 worker = 1 browser, xử lý tuần tự. Tối đa 3 job đang chạy + 500 acc/submission + body ≤256KB (quá → 429/400).
- **Job nằm trong RAM**: Render free sleep/restart → mất job đang chạy/kết quả (chạy lại là xong). Bản chất app 1 user, không lưu DB.
- **Bảo mật đã dựng**: mật khẩu truy cập bắt buộc + rate-limit login (8 sai/phút/IP) + CSRF token + cookie Secure + chống clickjacking + non-root container. Vẫn: dùng mật khẩu mạnh, KHÔNG share URL+pass.
- **Chromium trong Docker** chạy `--no-sandbox` (Playwright cần khi container non-root thiếu cap) — bình thường cho app tự host.

## Deploy khác (Railway / Fly.io)
Cũng dùng Dockerfile:
- **Railway**: `railway up` (cài railway CLI), set env `CHECKPASS_PASSWORD` + `PORT`.
- **Fly.io**: `fly launch` (chọn Dockerfile), `fly secrets set CHECKPASS_PASSWORD=...`, `fly deploy`.
