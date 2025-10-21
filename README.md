# 🚀 NT230 RQ01 - EPO Virus Implementation

## 👥 Thông Tin
- **MSSV**: 23521308-23521761-23521828-23521840
- **Yêu cầu**: RQ01 (8 điểm)
- **Mục tiêu**: Virus PE file 32-bit với 2 chiến lược EPO khác nhau

---

## ⚡ Bắt Đầu Nhanh

```bash
# 1. Kiểm tra hệ thống
check_system.bat

# 2. Build dự án
build.bat

# 3. Chạy virus
cd bin
NT230_EPO_Virus.exe
```

---

## 📋 Yêu Cầu Hệ Thống

| Yêu Cầu | Chi Tiết |
|---------|---------|
| **OS** | Windows 7+ |
| **IDE** | Visual Studio 2022 Community |
| **Compiler** | MSVC v143 (14.44+) |
| **Architecture** | Win32 (x86/32-bit) |

---

## ✨ Chức Năng Chính

### 1️⃣ Hiển Thị Thông Điệp
- **Tiêu đề**: "Infection by NT230"
- **Nội dung**: "23521308-23521761-23521828-23521840"

### 2️⃣ Lây Nhiễm PE Files
- Quét `.exe` và `.dll` trong thư mục
- Kiểm tra infection marker để ngăn re-infection
- Chỉ nhiễm file chưa bị lây nhiễm

### 3️⃣ Bảo Toàn Chức Năng
- Host program hoạt động bình thường sau nhiễm
- Virus chạy stealth thông qua EPO

---

## 🔍 2 Chiến Lược EPO

### **Chiến Lược 1: Call Hijacking**
- Thay thế thunk trong IAT → virus code
- Virus chạy trước, sau đó gọi hàm gốc
- Entry point không thay đổi → khó phát hiện

### **Chiến Lược 2: IAT Replacing**
- Redirect import entries sang virus code
- Virus intercept hàm import
- Chỉ sửa IAT, không sửa code section

---

## 📂 Cấu Trúc Dự Án

```
RQ01/
├── src/
│   ├── main.c              # Entry point (virus injector)
│   ├── virus_payload.c     # Popup, directory scan
│   ├── pe_infector.c       # EPO infection (2 techniques)
│   └── host.c              # Demo target program
├── include/
│   ├── virus_payload.h     # Interfaces & constants
│   └── pe_infector.h       # PE manipulation
├── bin/                    # Compiled executables
├── RQ01.sln                # Solution file
└── README.md               # This file
```

---

## 🔧 Cách Sử Dụng

### **1. Kiểm tra Build**
```bash
check_system.bat     # Xác minh VS2022 & MSBuild
build.bat            # Compile project
```

### **2. Nhiễm File**
```bash
cd bin
NT230_EPO_Virus.exe  # Scan & infect PE files
```

### **3. Test với Host Program**
```bash
cd bin
copy NT230_HostProgram.exe test.exe
NT230_EPO_Virus.exe
test.exe             # Chạy để thấy popup
```

---

## 🔑 Infection Marker

**Marker:** `NT230_INFECTED_VIRUS_PAYLOAD_2025`
- **Kích thước:** 33 bytes
- **Mục đích:** Ngăn re-infection
- **Kiểm tra:** `IsFileInfected()` search marker trong file

---

## ⚠️ Lưu Ý Quan Trọng

1. **Educational Purpose Only**
   - Project này để học virus mechanics
   - Không sử dụng vào mục đích xấu

2. **Compiler Status**
   - ✅ C4996 fopen: Đã fix
   - ⚠️ C4101 Unreferenced vars: Không ảnh hưởng

3. **Antivirus Detection**
   - AV software có thể flag executable (expected)
   - Code kiểm tra infection + display popup

4. **Platform**
   - Chỉ Windows, 32-bit (Win32)
   - PE format: 32-bit Portable Executable

---

## 📊 Kết Quả Build

```
====================================================
Build SUCCEEDED
====================================================
Output: bin\NT230_EPO_Virus.exe
        bin\NT230_HostProgram.exe
```

---

**Status:** ✅ Ready to Use | **Updated:** Oct 21, 2025
