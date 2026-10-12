# Lab: Thực hành khai thác Token Hijacking

## Mục đích

Hiểu cách session token bị lộ (debug endpoint bị quên) cho phép kẻ
tấn công mạo danh nạn nhân mà không cần biết password (replay token).

## Kiến thức yêu cầu

- Linux cơ bản (`curl`, `grep`)
- HTTP cơ bản (cookie, JSON API đơn giản)
- Khái niệm session/bearer token

## Kiến trúc

```
victim (172.28.0.4) ──giữ session sống──▶ victim-portal (172.28.0.2)
attacker (172.28.0.3) ──đọc token + replay──▶ victim-portal
```

- `victim`: máy nhân viên, tự động duy trì session (không cần đụng)
- `victim-portal`: portal `http://victim-portal:8000` + diagnostic
  endpoint bị quên; 2 tài khoản `victim`/`attacker`
- `attacker`: terminal thực hành (`curl`, `grep`, `python3`)

## Cách chạy (khuyến nghị: imodule + DockerHub)

```bash
cd ~/labtainer/labtainer-student
imodule https://github.com/Taamne/tamdtt-hijacking/raw/main/token-hijacking/imodule_web-attk-token-hijacking.tar
labtainer web-attk-token-hijacking
```

Image đã publish tại `taamne/web-attk-token-hijacking.{attacker,victim-portal,victim}.student`
(`https://hub.docker.com/u/taamne`) nên sinh viên không cần build local.

Cách thủ công (không dùng imodule): copy thư mục `lab/` vào
`~/labtainer/trunk/labs/web-attk-token-hijacking` rồi chạy `labtainer`
như trên (lần đầu sẽ tự build image).

## Nhiệm vụ (không lời giải)

1. Tìm diagnostic endpoint bị quên và đọc session token của victim.
2. Replay token đó để mở profile riêng của victim, đọc private note.
3. Chạy checkwork:

```bash
checkwork web-attk-token-hijacking
```

Kết quả mong muốn:

```
 Y - token_discovered
 Y - session_replayed
 Y - token_hijacked
```

## Reset / dừng

```bash
labtainer -r web-attk-token-hijacking  # làm lại từ đầu (token + flag mới)
stoplab web-attk-token-hijacking       # dừng lab
```

## Nguồn lab

Thư mục `lab/` chứa toàn bộ source Labtainer (`config/`,
`dockerfiles/`, `attacker/`, `victim/`, `victim-portal/`,
`instr_config/`, `docs/`). Không commit secret thật, build artifact
hay log máy local.
