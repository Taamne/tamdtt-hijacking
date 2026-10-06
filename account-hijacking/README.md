# Lab: Thực hành khai thác Account Hijacking

## Mục đích

Hiểu cách credential bị lộ (file backup cũ còn sót trên portal) có thể
dẫn đến việc chiếm quyền sử dụng tài khoản của nạn nhân.

## Kiến thức yêu cầu

- Linux cơ bản (`curl`, `grep`, `cat`)
- HTTP cơ bản (truy cập URL, form login, cookie session)
- username/password, web session cơ bản

## Kiến trúc

```
attacker  --HTTP-->  victim-web (Flask portal :8000, SQLite)
```

- `attacker`: terminal thực hành (`curl`, `grep`, `cat`, `find`, `python3`)
- `victim-web`: portal với 2 tài khoản `victim` (employee, có private
  note) và `attacker` (guest, không thấy dữ liệu victim)

## Cách chạy (khuyến nghị: imodule + DockerHub)

```bash
cd ~/labtainer/labtainer-student
imodule https://github.com/<user>/<repo>/raw/main/account-hijacking/imodule_web-attk-account-hijacking.tar
labtainer web-attk-account-hijacking
```

Image đã publish tại `taamne/web-attk-account-hijacking.{attacker,victim-web}.student`
(`https://hub.docker.com/u/taamne`) nên sinh viên không cần build local.

Cách thủ công (không dùng imodule): copy thư mục `lab/` vào
`~/labtainer/trunk/labs/web-attk-account-hijacking` rồi chạy `labtainer`
như trên (lần đầu sẽ tự build image).

Target: `http://victim-web:8000`

## Nhiệm vụ (không lời giải)

1. Điều tra portal, tìm artifact (file backup cũ) làm lộ credential.
2. Dùng credential đó đăng nhập với tài khoản victim.
3. Truy cập trang profile riêng của victim, đọc private note.
4. Chạy checkwork:

```bash
checkwork web-attk-account-hijacking
```

Kết quả mong muốn:

```
 Y - credential_discovered
 Y - victim_login
 Y - account_hijacked
```

## Reset / dừng

```bash
labtainer -r web-attk-account-hijacking  # làm lại từ đầu
stoplab web-attk-account-hijacking       # dừng lab
```

## Nguồn lab

Thư mục `lab/` chứa toàn bộ source Labtainer (`config/`,
`dockerfiles/`, `attacker/`, `victim-web/`, `instr_config/`, `docs/`).
Copy vào `~/labtainer/trunk/labs/web-attk-account-hijacking` rồi chạy
như trên. Không commit secret thật, build artifact hay log máy local.
