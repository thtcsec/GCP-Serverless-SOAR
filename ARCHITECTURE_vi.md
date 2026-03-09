# 🧠 Kiến trúc Nội bộ: GCP Serverless SOAR

Một khung làm việc **Điều phối Bảo mật (Security Orchestration)** nâng cao, sử dụng làm giàu tín hiệu từ nhiều nguồn để tự động hóa phản ứng sự cố.

## 1. Các trụ cột chính

*   **Thu thập (SCC & Cloud Audit Logs):** Giám sát thời gian thực các hành vi lạm dụng Service Account (SA) và các mẫu exfiltration (thoát dữ liệu) từ Storage bucket.
*   **Bộ máy Làm giàu (Enrichment Engine):**
    *   **Tích hợp VirusTotal:** Đối soát IP nguồn với cơ sở dữ liệu mối đe dọa toàn cầu (~70 engines).
    *   **Tích hợp AbuseIPDB:** Loại bỏ các máy quét (scanners) và bot brute-force đã biết dựa trên điểm uy tín từ cộng đồng.
*   **Điều phối (Scoring Engine):**
    *   Chuyển đổi các tín hiệu thô thành **Điểm rủi ro (Risk Scores)** có thể hành động.
    *   Logic quyết định tự động: `AUTO_ISOLATE` cho các mối đe dọa nghiêm trọng, `REQUIRE_APPROVAL` cho các tín hiệu nghi vấn.
*   **Thực thi (Cloud Functions):** Các responder kích hoạt theo sự kiện, thực hiện các kịch bản phản ứng (playbooks) một cách chính xác.

## 2. Luồng Xử lý Tự động

1.  **Tín hiệu:** SCC phát hiện việc tạo khóa Service Account đáng ngờ hoặc tải xuống dữ liệu khối lượng lớn từ Cloud Storage.
2.  **Phân tích:** Hệ thống làm giàu thông tin bằng Tình báo mối đe dọa bên ngoài. Nếu IP có **Abuse Confidence Score** cao, hệ thống sẽ kích hoạt cách ly.
3.  **Hành động (Phản ứng chính xác):**
    *   **Khóa danh tính:** Vô hiệu hóa các khóa SA và gỡ bỏ các vai trò IAM quan trọng (Project Editor/Owner).
    *   **Cách ly mạng:** Chặn lưu lượng ra bằng Cloud Armor hoặc các tag Firewall động.
    *   **Bảo vệ dữ liệu:** Kích hoạt S3/Storage Versioning và Object Lock để ngăn chặn việc sửa đổi dữ liệu.
    *   **Chứng cứ:** Chụp snapshot các đĩa cứng để phục vụ đội IR.
4.  **Quản trị:** Xuất bản đầy đủ bối cảnh sự cố lên Pub/Sub và tạo hồ sơ pháp y trên **Jira**.

## 3. Tại sao hệ thống này lại xịn?
*   **Tự động 100%:** Trộm vào lúc 3 giờ sáng, hệ thống tự nhốt trộm lại khi bạn đang ngủ.
*   **Mở rộng vô hạn:** Dù 1 hay 1.000 máy bị tấn công, Google Cloud sẽ tự đẻ ra 1.000 con Robot để xử lý cùng lúc.

---
**Kết luận:** Bạn đã xây dựng được một hệ thống "Tự chữa lành" (Self-Healing). Đây là tiêu chuẩn vàng trong bảo mật đám mây hiện nay! 🛡️
