"""
Heat Project 2 REZ File Parser
Reverse-engineered from Lithtech.exe (CRezMgr class)

REZ Format:
  - 202-byte header (CRezHeader) with magic validation
  - Encrypted directory tree at rootDirPos
  - Resource data embedded in file body
  - Directory entries (type=1) and file entries (type!=1) use different encryption

Directory/Name Encryption:
  - Dir header:  3-byte XOR key [0x83, 0x3E, 0x02]
  - File header: 6-byte XOR key [0x53, 0x74, 0x02, 0x2F, 0x5E, 0x3A]
  - Dir names:   byte_table[idx % 10], key_base from dir entry fields
  - File names:  byte_table[idx % 5],  key_base = (size%35) + (field6%80)

File Data Encryption (sub_4CF840):
  - XOR with extended byte table (513 bytes at 0x5899F0)
  - Key parameters computed from typeId, fsize, field6
  - Uses 32-bit signed integer overflow in multiplication
  - BINARIES.REZ uses this; Engine.REZ does not

File Header Field Order (32 bytes, 8x uint32):
  [offset, size, time, id, type_id, key_ary_size, field6, name_len]
"""

import struct
import os
import sys

# XOR lookup table at 0x5899F0 in Lithtech.exe (first 10 bytes used for name decryption)
BYTE_TABLE = [0x66, 0xA7, 0xEF, 0x1F, 0xDE, 0x7F, 0x1E, 0xD5, 0x71, 0x47]

# Extended XOR table (513 bytes from 0x5899F0) for file data decryption
# fmt: off
EXT_TABLE = [
    0x66, 0xA7, 0xEF, 0x1F, 0xDE, 0x7F, 0x1E, 0xD5, 0x71, 0x47,
    0x35, 0x46, 0x26, 0x9C, 0x74, 0x29, 0x53, 0x47, 0xEA, 0x2B,
    0x8B, 0x0C, 0xB6, 0x85, 0xF7, 0xD0, 0x27, 0x45, 0xF0, 0x35,
    0x5C, 0x1C, 0xFF, 0xF6, 0x91, 0x38, 0x20, 0x3D, 0x9D, 0x76,
    0xED, 0xE7, 0xBB, 0x6F, 0x63, 0xD9, 0x80, 0x75, 0x8F, 0x57,
    0xFA, 0x6D, 0x6A, 0x16, 0xA1, 0xDF, 0x43, 0xC5, 0x6D, 0x74,
    0x7E, 0x58, 0x99, 0x0D, 0xAF, 0xE1, 0x99, 0x98, 0x0C, 0x2C,
    0xE4, 0xBE, 0x12, 0xBD, 0xC0, 0x56, 0x1B, 0xF9, 0x2F, 0xD8,
    0x8B, 0xBB, 0xCD, 0xBB, 0xCD, 0x8D, 0xC3, 0x88, 0x93, 0x73,
    0xAB, 0xAF, 0x81, 0x3D, 0x8D, 0x20, 0x92, 0xFE, 0x50, 0xFC,
    0x22, 0x9E, 0xB7, 0xA3, 0x41, 0x0E, 0x4D, 0x31, 0x86, 0x78,
    0x75, 0xC2, 0xEF, 0x56, 0x67, 0xE3, 0xC6, 0xFB, 0xFD, 0x74,
    0x9F, 0xFB, 0xBA, 0xC9, 0xF0, 0x5C, 0xB7, 0xC9, 0xA2, 0xC5,
    0x70, 0x0B, 0x64, 0x65, 0x7A, 0xC6, 0x32, 0xEF, 0xB0, 0x34,
    0x0B, 0x88, 0x2D, 0xF0, 0x9E, 0xFC, 0x49, 0x66, 0x46, 0xEF,
    0x2A, 0x8B, 0x58, 0xDB, 0x7E, 0x9C, 0x79, 0xB1, 0x87, 0x30,
    0x78, 0x89, 0xDA, 0x7D, 0x2A, 0xCE, 0xCE, 0x27, 0x18, 0x51,
    0xEB, 0xFF, 0x6F, 0x6C, 0x95, 0x34, 0x93, 0xAE, 0x15, 0x81,
    0x1A, 0xEA, 0x5B, 0x20, 0xD4, 0x4D, 0x99, 0xCA, 0xC1, 0x74,
    0xAA, 0x58, 0x58, 0x18, 0x0B, 0x32, 0xA1, 0x36, 0x47, 0x14,
    0x01, 0x1C, 0x2D, 0x9B, 0xD3, 0x3B, 0xB7, 0xD3, 0x8A, 0xE3,
    0x99, 0x53, 0x1E, 0xA4, 0x70, 0x97, 0x1E, 0x7D, 0xDC, 0xBE,
    0x7B, 0x3C, 0xF8, 0x8C, 0xA1, 0x32, 0x3B, 0x47, 0x21, 0x43,
    0x40, 0x3C, 0xF3, 0xDB, 0x38, 0xE3, 0x9A, 0xD4, 0x89, 0x4E,
    0x48, 0x87, 0xE5, 0x0F, 0xE9, 0xF5, 0xD5, 0x5A, 0xF0, 0xE3,
    0x0D, 0xD9, 0xB8, 0x45, 0x07, 0x55, 0x66, 0x86, 0x5E, 0x60,
    0x6D, 0x18, 0x20, 0x78, 0x4F, 0x3B, 0xB1, 0x5C, 0xF5, 0x34,
    0xAA, 0xE2, 0x7F, 0x1C, 0xC8, 0x6F, 0x24, 0x65, 0x8A, 0xA1,
    0x55, 0xA1, 0xD8, 0x3A, 0x3C, 0x6E, 0x21, 0x8E, 0xC1, 0x16,
    0x1B, 0x7A, 0x9D, 0xF7, 0xAD, 0x25, 0x6C, 0xBD, 0x0B, 0x96,
    0xB0, 0x1F, 0x6E, 0xC3, 0x47, 0xD4, 0xF9, 0x6F, 0xEF, 0x74,
    0xBE, 0x64, 0x39, 0xFE, 0x77, 0xCA, 0x93, 0x4D, 0xA7, 0xE4,
    0x52, 0xFE, 0x33, 0x57, 0xA3, 0x21, 0x19, 0x73, 0xDE, 0x93,
    0x5E, 0x68, 0x03, 0x4D, 0x30, 0xE2, 0x2C, 0xEB, 0x14, 0x6B,
    0x0F, 0xE6, 0xD4, 0xD1, 0xBA, 0x29, 0xD8, 0xB2, 0xBD, 0x0C,
    0x60, 0x72, 0x9A, 0x44, 0x35, 0x68, 0xDF, 0xED, 0xC4, 0xAB,
    0xA6, 0x9F, 0x1E, 0xB1, 0x3F, 0xDE, 0x84, 0xFA, 0xF8, 0xDA,
    0xC6, 0x6C, 0xA8, 0x48, 0x6C, 0x86, 0x34, 0x3C, 0x78, 0x11,
    0x80, 0x6F, 0x09, 0xDD, 0x37, 0x8B, 0xAC, 0x4F, 0xB8, 0x48,
    0x34, 0x02, 0x46, 0xD7, 0xF9, 0xF6, 0x45, 0xF8, 0x07, 0x70,
    0xCF, 0x96, 0xEE, 0x52, 0x39, 0x9A, 0x24, 0x83, 0x2E, 0x85,
    0x06, 0x46, 0x39, 0x85, 0x64, 0xFD, 0x19, 0x0B, 0x3E, 0x70,
    0x7F, 0xCB, 0x08, 0xFF, 0x88, 0xD1, 0xDB, 0xBE, 0xB2, 0xD0,
    0x20, 0x10, 0x1E, 0xD5, 0x06, 0xF4, 0x72, 0x43, 0xED, 0xEA,
    0xA2, 0xB0, 0xF5, 0x53, 0x81, 0x15, 0xF8, 0x87, 0xD2, 0xF4,
    0xBF, 0x59, 0x1C, 0x49, 0xF6, 0xB0, 0xEE, 0x8E, 0x83, 0x39,
    0x54, 0x1D, 0x26, 0x8F, 0xFF, 0x3E, 0x60, 0xE7, 0x7E, 0x31,
    0x42, 0xCC, 0x37, 0x18, 0xD1, 0x6B, 0xAF, 0x96, 0xCD, 0xBE,
    0xD9, 0x33, 0x98, 0x76, 0xFC, 0x1A, 0x10, 0xDE, 0x80, 0x13,
    0x82, 0x3A, 0x27, 0xF6, 0x9D, 0x0D, 0x46, 0x8A, 0x8D, 0x45,
    0x24, 0xE6, 0x73, 0x2C, 0xEB, 0x4B, 0xAD, 0xE2, 0xEA, 0xAE,
    0x65, 0x7D, 0x00,
]
# fmt: on

# Encryption keys (from disassembly, not decompiler - decompiler had wrong constant)
DIR_HEADER_KEY = [0x83, 0x3E, 0x02]               # 3-byte key for 16-byte dir headers
FILE_HEADER_KEY = [0x53, 0x74, 0x02, 0x2F, 0x5E, 0x3A]  # 6-byte key for 32-byte file headers


def decrypt_xor_cyclic(buf, key):
    """XOR decrypt buffer with repeating key."""
    out = bytearray(buf)
    for i in range(len(out)):
        out[i] ^= key[i % len(key)]
    return bytes(out)


def decrypt_dir_name(buf, name_len, f0, f1, f2):
    """Decrypt directory entry name string.
    Uses byte_table[idx % 10] with key_base derived from dir entry fields.
    f0=field[0] (dataPos), f1=field[1] (dataSize), f2=field[2] (time)
    """
    # key_base = f0 + f2 + nameLen - 5*(f0//5 + 4*(f2//20) + 10*(nameLen//50))
    v6 = 5 * (f0 // 5 + 4 * (f2 // 20) + 10 * (name_len // 50))
    key_base = f2 + f0 + name_len - v6
    out = bytearray(buf)
    for i in range(name_len):
        idx = (key_base + i) % 10
        out[i] ^= BYTE_TABLE[idx]
    return bytes(out)


def decrypt_file_name(buf, name_len, size_val, field6):
    """Decrypt file entry name string.
    Uses byte_table[idx % 5] with key_base = (size%35) + (field6%80).
    Note: uses fsize (v15[1]), NOT foffset - confirmed from CRezMgr__ParseDirEntries.
    """
    key_base = (size_val % 35) + (field6 % 80)
    out = bytearray(buf)
    for i in range(name_len):
        idx = (key_base + i) % 5
        out[i] ^= BYTE_TABLE[idx]
    return bytes(out)


def _i32(x):
    """Truncate to signed 32-bit integer (C int overflow behavior)."""
    x = x & 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def _cmod(a, b):
    """C-style signed modulo (truncation toward zero, like x86 idiv)."""
    r = a % b
    if r != 0 and ((a < 0) != (b < 0)):
        r -= b
    return r


def decrypt_file_data(buf, fsize, field6, type_id, read_pos=0):
    """Decrypt file data using extended XOR table.
    Reverse-engineered from sub_4CF840 in Lithtech.exe.
    Uses typeId, fsize, field6 to compute XOR key parameters.
    read_pos is the byte offset within the resource (0 for full extraction).
    """
    buf_len = len(buf)
    if buf_len == 0:
        return buf

    # v11 = (fsize + field6 + 32*typeId - 35*(fsize/35)) % 125
    v11 = (fsize + field6 + 32 * type_id - 35 * (fsize // 35)) % 125

    # v6 = (typeId + field6 + fsize*(typeId%428) - 55*(typeId/55) - 30*(field6/30)) % 513
    # The multiplication fsize*(typeId%428) can overflow signed 32-bit
    mul = _i32(fsize * (type_id % 428))
    v6_raw = _i32(type_id + field6 + mul - 55 * (type_id // 55) - 30 * (field6 // 30))
    v6 = _cmod(v6_raw, 513)

    # v7 = v11 - 50*(fsize/50)
    v7 = v11 - 50 * (fsize // 50)

    # if (v7 + fsize >= v6): v6 = v7 + fsize
    if v7 + fsize >= v6:
        v6 = v7 + fsize

    # v9 = v6 - v11 + 1 (modulus for table index)
    v9 = v6 - v11 + 1
    if v9 <= 0:
        return bytes(buf)

    out = bytearray(buf)
    for i in range(buf_len):
        idx = (v11 + read_pos + i) % v9
        out[i] ^= EXT_TABLE[idx]
    return bytes(out)


class RezHeader:
    """202-byte REZ file header."""
    SIZE = 202
    MAGIC_BYTE = 0x18
    MAGIC_CHECKS = {0: 0x18, 1: 0x51, 62: 0x2A, 63: 0x2E, 124: 0x4A, 125: 0x50, 126: 0x47}

    def __init__(self, data):
        if len(data) < self.SIZE:
            raise ValueError(f"Header too short: {len(data)} < {self.SIZE}")
        # Validate magic bytes
        for offset, expected in self.MAGIC_CHECKS.items():
            if data[offset] != expected:
                raise ValueError(f"Magic check failed at offset {offset}: "
                               f"got 0x{data[offset]:02X}, expected 0x{expected:02X}")

        self.magic = data[0]
        self.copyright = data[1:62].rstrip(b'\x00 ').decode('ascii', errors='replace')
        self.marker = data[62:64]
        self.description = data[64:124].rstrip(b'\x00 ').decode('ascii', errors='replace')
        self.ext_tag = data[124:127].decode('ascii', errors='replace')
        self.flag = data[127]
        self.numeric_key_raw = data[128:161]
        self.numeric_key = data[128:161].split(b'\x00')[0].decode('ascii', errors='replace')

        self.version = struct.unpack_from('<I', data, 161)[0]
        self.root_dir_pos = struct.unpack_from('<I', data, 165)[0]
        self.root_dir_size = struct.unpack_from('<I', data, 169)[0]
        self.root_dir_time = struct.unpack_from('<I', data, 173)[0]
        self.next_write_pos = struct.unpack_from('<I', data, 177)[0]
        self.last_mod_time = struct.unpack_from('<I', data, 181)[0]
        self.largest_key_ary = struct.unpack_from('<I', data, 185)[0]
        self.largest_dir_name = struct.unpack_from('<I', data, 189)[0]
        self.largest_rez_name = struct.unpack_from('<I', data, 193)[0]
        self.largest_comment = struct.unpack_from('<I', data, 197)[0]
        self.is_sorted = data[201]

    def __repr__(self):
        return (f"RezHeader(copyright='{self.copyright}', desc='{self.description}', "
                f"version={self.version}, rootDirPos={self.root_dir_pos}, "
                f"rootDirSize={self.root_dir_size})")


class RezDirEntry:
    """Directory entry in the rez tree."""
    def __init__(self, name, data_pos, data_size, time_val):
        self.name = name
        self.data_pos = data_pos
        self.data_size = data_size
        self.time = time_val
        self.children_dirs = []
        self.children_files = []

    def __repr__(self):
        return f"RezDir({self.name}, pos={self.data_pos}, size={self.data_size})"


class RezFileEntry:
    """File/resource entry in the rez tree."""
    def __init__(self, name, res_id, offset, time_val, size, type_id, field6, comment=""):
        self.name = name
        self.id = res_id
        self.offset = offset
        self.time = time_val
        self.size = size
        self.type_id = type_id
        self.field6 = field6
        self.comment = comment

    @property
    def extension(self):
        """Get file extension from type_id (LE bytes reversed)."""
        if not self.type_id:
            return ""
        raw = struct.pack('<I', self.type_id).rstrip(b'\x00')
        try:
            return "." + raw.decode('ascii')[::-1].lower()
        except (UnicodeDecodeError, ValueError):
            return ""

    @property
    def filename(self):
        """Full filename with extension."""
        return self.name + self.extension

    def __repr__(self):
        return f"RezFile({self.filename}, id={self.id}, offset={self.offset}, size={self.size})"


class RezParser:
    """Parser for Heat Project 2 REZ files."""

    def __init__(self, filepath):
        with open(filepath, 'rb') as f:
            self.data = f.read()
        self.filepath = filepath
        self.header = RezHeader(self.data[:RezHeader.SIZE])
        self.root = RezDirEntry("ROOT", self.header.root_dir_pos,
                                self.header.root_dir_size, self.header.root_dir_time)
        self._parse_dir_tree(self.root)

    def _parse_dir_tree(self, parent_dir):
        """Recursively parse directory tree from rez file data."""
        if parent_dir.data_pos <= 0 or parent_dir.data_size <= 0:
            return
        end = parent_dir.data_pos + parent_dir.data_size
        if end > len(self.data):
            return

        dir_data = bytearray(self.data[parent_dir.data_pos:end])
        self._parse_entries(dir_data, parent_dir)

        # Recurse into subdirectories
        for child_dir in parent_dir.children_dirs:
            self._parse_dir_tree(child_dir)

    def _parse_entries(self, data, parent_dir):
        """Parse directory/file entries from a data buffer."""
        pos = 0
        while pos + 4 <= len(data):
            entry_type = struct.unpack_from('<I', data, pos)[0]
            pos += 4

            if entry_type == 1:
                # Directory entry
                if pos + 16 > len(data):
                    break
                hdr = decrypt_xor_cyclic(data[pos:pos+16], DIR_HEADER_KEY)
                f0, f1, f2, name_len = struct.unpack('<4I', hdr)
                pos += 16

                if name_len > 4096 or pos + name_len > len(data):
                    break
                name = decrypt_dir_name(bytearray(data[pos:pos+name_len]),
                                       name_len, f0, f1, f2)
                name_str = name.rstrip(b'\x00').decode('ascii', errors='replace')
                pos += name_len

                child = RezDirEntry(name_str, f0, f1, f2)
                parent_dir.children_dirs.append(child)
            else:
                # File/resource entry
                if pos + 32 > len(data):
                    break
                hdr = decrypt_xor_cyclic(data[pos:pos+32], FILE_HEADER_KEY)
                foffset, fsize, ftime, fid, ftype_id, key_ary_size, ffield6, name_len = \
                    struct.unpack('<8I', hdr)
                pos += 32

                if name_len > 65536 or pos + name_len > len(data):
                    break
                name = decrypt_file_name(bytearray(data[pos:pos+name_len]),
                                        name_len, fsize, ffield6)
                name_str = name.rstrip(b'\x00').decode('ascii', errors='replace')
                pos += name_len

                # Comment string (null-terminated)
                comment = ""
                comment_end = pos
                while comment_end < len(data) and data[comment_end] != 0:
                    comment_end += 1
                if comment_end > pos:
                    comment = bytes(data[pos:comment_end]).decode('ascii', errors='replace')
                pos = min(comment_end + 1, len(data))

                # Key array (keyArySize * 4 bytes)
                pos += key_ary_size * 4

                entry = RezFileEntry(name_str, fid, foffset, ftime, fsize,
                                    ftype_id, ffield6, comment)
                parent_dir.children_files.append(entry)

    def print_tree(self, node=None, depth=0):
        """Print the directory tree."""
        if node is None:
            node = self.root
        indent = "  " * depth
        print(f"{indent}[DIR] {node.name}/  (pos={node.data_pos}, size={node.data_size})")
        for f in node.children_files:
            print(f"{indent}  [FILE] {f.filename}  (offset={f.offset}, size={f.size})")
        for d in node.children_dirs:
            self.print_tree(d, depth + 1)

    def get_file_data(self, entry, decrypt=False):
        """Get raw or decrypted file data for an entry."""
        if entry.size <= 0:
            return b''
        file_data = self.data[entry.offset:entry.offset + entry.size]
        if decrypt and entry.type_id:
            file_data = decrypt_file_data(file_data, entry.size, entry.field6, entry.type_id)
        return file_data

    def extract_file(self, entry, output_path, decrypt=False):
        """Extract a file entry to disk."""
        file_data = self.get_file_data(entry, decrypt=decrypt)
        with open(output_path, 'wb') as f:
            f.write(file_data)

    def extract_all(self, output_dir, node=None, current_path="", decrypt=False):
        """Extract all files to a directory tree."""
        if node is None:
            node = self.root
        dir_path = os.path.join(output_dir, current_path, node.name) if current_path else output_dir
        os.makedirs(dir_path, exist_ok=True)

        for f in node.children_files:
            file_path = os.path.join(dir_path, f.filename)
            self.extract_file(f, file_path, decrypt=decrypt)

        for d in node.children_dirs:
            self.extract_all(output_dir, d, os.path.join(current_path, node.name) if current_path else "",
                           decrypt=decrypt)

    def list_all_files(self, node=None, path=""):
        """Generator yielding (path, entry) for all files."""
        if node is None:
            node = self.root
        current_path = f"{path}/{node.name}" if path else node.name
        for f in node.children_files:
            yield f"{current_path}/{f.filename}", f
        for d in node.children_dirs:
            yield from self.list_all_files(d, current_path)


def main():
    if len(sys.argv) < 2:
        print("Usage: python rez_parser.py <file.rez> [--extract <output_dir>] [--list]")
        print()
        print("Options:")
        print("  --list       List all files with details")
        print("  --extract    Extract all files to output directory")
        print("  --info       Show header information only")
        print("  --decrypt    Decrypt file data during extraction (for BINARIES.REZ)")
        sys.exit(1)

    rez_path = sys.argv[1]
    if not os.path.exists(rez_path):
        print(f"Error: File not found: {rez_path}")
        sys.exit(1)

    try:
        parser = RezParser(rez_path)
    except ValueError as e:
        print(f"Error: Not a valid REZ file: {e}")
        sys.exit(1)

    if "--info" in sys.argv:
        h = parser.header
        print(f"=== REZ Header ===")
        print(f"Copyright:      {h.copyright}")
        print(f"Description:    {h.description}")
        print(f"Extension Tag:  {h.ext_tag}")
        print(f"Version:        {h.version}")
        print(f"Root Dir Pos:   {h.root_dir_pos}")
        print(f"Root Dir Size:  {h.root_dir_size}")
        print(f"Next Write Pos: {h.next_write_pos}")
        print(f"Last Mod Time:  0x{h.last_mod_time:08X}")
        print(f"Is Sorted:      {h.is_sorted}")
        print(f"Numeric Key:    {h.numeric_key}")
        print()

    if "--list" in sys.argv:
        total_files = 0
        total_size = 0
        for path, entry in parser.list_all_files():
            print(f"  {path}  (offset={entry.offset}, size={entry.size})")
            total_files += 1
            total_size += entry.size
        print(f"\nTotal: {total_files} files, {total_size} bytes")
        print()

    decrypt = "--decrypt" in sys.argv

    if "--extract" in sys.argv:
        idx = sys.argv.index("--extract")
        if idx + 1 >= len(sys.argv):
            print("Error: --extract requires output directory")
            sys.exit(1)
        output_dir = sys.argv[idx + 1]
        print(f"Extracting to: {output_dir}" + (" (with decryption)" if decrypt else ""))
        parser.extract_all(output_dir, decrypt=decrypt)
        total = sum(1 for _ in parser.list_all_files())
        print(f"Extracted {total} files.")
    elif "--list" not in sys.argv and "--info" not in sys.argv:
        # Default: print tree
        parser.print_tree()


if __name__ == "__main__":
    main()
