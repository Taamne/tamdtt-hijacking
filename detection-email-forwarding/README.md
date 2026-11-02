# Lab: Phát hiện Email Forwarding độc hại (Detection)

## Mục đích

Hiểu cách phát hiện rule chuyển tiếp mail độc ẩn trong hàng chục
rule hợp lệ: đối chiếu inventory đã phê duyệt (baseline), triage
nghi vấn bằng log đăng nhập + phân tích domain, và viết rule
allowlist thay vì chạy theo IOC cũ.

## Kiến thức yêu cầu

- Linux cơ bản (`scp`, `grep`, `sqlite3` khái niệm)
- Đọc hiểu log đăng nhập (timestamp, source IP)
- Khái niệm forwarding rule, allowlist, IOC

## Kiến trúc

```
victim-mail (172.26.0.2) : portal + audit log + 19 rule hợp lệ seed sẵn
attacker    (172.26.0.3) : threat emulator (cài 1 rule độc)
analyst     (172.26.0.4) : trạm SOC (thu thập log, diff, detect)
```

- Kẻ tấn công (mô phỏng) chiếm mailbox và cài rule chuyển tiếp ra
  `payroll-archive@company-backup.com` (domain lookalike).
- Analyst thu thập log + DB qua `scp`, chạy `detect.py --diff` để tìm
  rule ngoài inventory, triage, sửa `rules.json` sang chế độ allowlist,
  chạy `detect.py --detect` để sinh cảnh báo.

## Cách chạy (khuyến nghị: imodule + DockerHub)

```bash
cd ~/labtainer/labtainer-student
imodule https://github.com/Taamne/tamdtt-hijacking/raw/main/detection-email-forwarding/imodule_web-detk-email-forwarding.tar
labtainer web-detk-email-forwarding
```

Image đã publish tại `taamne/web-detk-email-forwarding.{attacker,victim-mail,analyst}.student`
(`https://hub.docker.com/u/taamne`) nên sinh viên không cần build local.

## Nhiệm vụ (không tiết lộ đáp án)

1. Chạy threat emulator trên attacker để tái hiện vụ chiếm hộp thư.
2. Thu thập log + DB về analyst (`fetch_logs.sh`).
3. Diff với inventory (`detect.py --diff`) để tìm rule lạ.
4. Triage: kiểm tra thời điểm tạo rule và login gần nhất, phân tích domain.
5. Sửa `rules.json` sang chế độ allowlist, chạy `detect.py --detect`.
6. Chạy checkwork:

```bash
checkwork web-detk-email-forwarding
```

Kết quả mong muốn:

```
 Y - rogue_forward_detected
 Y - no_false_positive
 Y - allowlist_applied
```

## Reset / dừng

```bash
labtainer -q -r web-detk-email-forwarding  # làm lại từ đầu
stoplab web-detk-email-forwarding         # dừng lab
```

## Nguồn lab

Thư mục `lab/` chứa toàn bộ source Labtainer. Không commit secret thật,
build artifact hay log máy local.
