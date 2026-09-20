# AGENTS.md - Quy Chuẩn Kỹ Thuật Bắt Buộc (Always-On System Rule)

Tài liệu này là quy chuẩn kỹ thuật bắt buộc dành cho AI Agent khi phát triển và bảo trì repository **AgentGuard-CI**. Dự án đã được cài đặt và tích hợp sẵn 3 Skill tinh hoa từ GitHub (nằm trong `.agents/skills/`). AI Agent bắt buộc phải tuân thủ nghiêm ngặt 3 trụ cột này trong từng dòng code và thao tác:

---

## 1. Trụ Cột 1: Karpathy Guidelines (`.agents/skills/karpathy-guidelines/`)
*Nguồn: `forrestchang/andrej-karpathy-skills` (Dựa trên quan sát thực tế của Andrej Karpathy)*

* **Suy nghĩ trước khi code (Think Before Coding):** Luôn nêu rõ các giả định (assumptions). Nếu có điểm mơ hồ, phải hỏi rõ trước khi làm; không tự tiện suy đoán ngầm.
* **Tối giản là số 1 (Simplicity First):** Chỉ viết lượng code tối thiểu cần thiết để giải quyết đúng vấn đề được yêu cầu. Tuyệt đối không tạo các abstraction suy đoán (no speculative abstractions), không over-engineering.
* **Thay đổi chuẩn xác (Surgical Changes):** Chỉ sửa đúng những chỗ cần sửa. Không tự ý format lại hoặc làm xáo trộn các vùng code xung quanh không liên quan.
* **Thực thi theo mục tiêu kiểm chứng (Goal-Driven Execution):** Mọi tính năng hay sửa lỗi đều phải có tiêu chí kiểm thử rõ ràng và lặp lại cho đến khi pass 100%.

---

## 2. Trụ Cột 2: Impeccable Craftsmanship (`.agents/skills/impeccable/`)
*Nguồn: `pbakaus/impeccable` (Chuẩn mực chế tác sản phẩm & Chống "AI Slop")*

* **Không có AI Slop:** Không bao giờ để lại code dở dang (`// TODO: implement later`, `any`, placeholder tạm bợ). Mọi chức năng, giao diện hoặc văn bản tạo ra phải đạt đẳng cấp sản phẩm thương mại hoàn chỉnh.
* **Trình bày tinh xảo:** Mọi báo cáo PR Markdown, bảng biểu hay giao diện terminal phải có cấu trúc thông tin rõ ràng, phân cấp thị giác chuẩn xác và thẩm mỹ cao.
* **Strict Typing & Error Handling:** Bắt lỗi tường minh, không nuốt lỗi trong catch rỗng. Khai báo kiểu dữ liệu an toàn 100%.

---

## 3. Trụ Cột 3: Deep Modules & Enterprise Architecture (`.agents/skills/codebase-design/`)
*Nguồn: `mattpocock/skills` (Triết lý thiết kế module chiều sâu - Deep Modules của Matt Pocock)*

* **Module Chiều Sâu (Deep Modules):** Giao diện bên ngoài (Interface) phải cực kỳ nhỏ gọn, đơn giản và dễ dùng; nhưng toàn bộ logic phức tạp được giấu kín bên trong Implementation.
* **Tổ chức Clean Architecture phân tầng nghiêm ngặt:**
  * `src/core/`: Lõi logic domain thuần túy, hàm thuần (pure functions), không phụ thuộc I/O.
  * `src/core/rules/`: Các quy tắc bảo mật cắm rút độc lập (Plug-and-play). Thêm rule mới không làm vỡ scanner.
  * `src/core/formatter/`: Tầng trình bày dữ liệu riêng biệt.
  * `src/review/`: Động cơ tổng hợp review (Offline + OpenAI Semantic Layer).
  * `src/cli/` & `src/action/`: Tầng adapter ngoại vi (Terminal & GitHub Octokit).
* **Kiểm thử tự động bắt buộc:** 100% các module đều phải được kiểm thử độc lập qua Unit Test (`tests/`). Chạy `npm test` luôn phải xanh lá 100%.

---

## Mục Tiêu Tối Thượng
Mọi file mã nguồn, commit và tài liệu trong repo này phải thể hiện trình độ chuyên nghiệp của một Senior/Staff Open-Source Engineer nhằm đạt tỷ lệ xét duyệt cao nhất cho chương trình **OpenAI Codex for Open Source ($1,200 / 6 tháng ChatGPT Pro 20x)**.
