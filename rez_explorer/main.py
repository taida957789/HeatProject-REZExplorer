"""
REZ Explorer - PySide6 GUI for browsing/editing LithTech REZ archives.
Supports encrypted BINARIES.REZ and plain Engine.REZ files.
"""

import struct
import os
import sys
import time

from .rez_parser import (
    RezParser, RezHeader, RezDirEntry, RezFileEntry,
    decrypt_file_data, decrypt_xor_cyclic, decrypt_dir_name, decrypt_file_name,
    DIR_HEADER_KEY, FILE_HEADER_KEY, BYTE_TABLE, EXT_TABLE,
)

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QSplitter, QTreeWidget, QTreeWidgetItem,
    QListWidget, QListWidgetItem, QToolBar, QStatusBar, QMenuBar, QMenu,
    QFileDialog, QMessageBox, QAbstractItemView, QInputDialog, QProgressDialog,
)
from PySide6.QtCore import Qt, Signal, QSize, QMimeData
from PySide6.QtGui import QIcon, QAction, QKeySequence, QDragEnterEvent, QDropEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ext_to_type_id(ext: str) -> int:
    """Convert file extension like '.dll' to LithTech type_id (LE uint32 of reversed uppercase)."""
    ext = ext.lstrip('.').upper()
    if not ext:
        return 0
    # Reverse + pad to 4 bytes, pack as LE uint32
    rev = ext[::-1].ljust(4, '\x00')[:4]
    return struct.unpack('<I', rev.encode('ascii'))[0]


def format_size(size: int) -> str:
    """Human-readable file size."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / (1024 * 1024):.1f} MB"


def collect_all_files(node: RezDirEntry) -> list:
    """Recursively collect all RezFileEntry objects."""
    files = list(node.children_files)
    for d in node.children_dirs:
        files.extend(collect_all_files(d))
    return files


def count_entries(node: RezDirEntry) -> tuple:
    """Return (file_count, total_bytes) under a directory tree."""
    nfiles = len(node.children_files)
    nbytes = sum(f.size for f in node.children_files)
    for d in node.children_dirs:
        cf, cb = count_entries(d)
        nfiles += cf
        nbytes += cb
    return nfiles, nbytes


# ---------------------------------------------------------------------------
# REZ Writer
# ---------------------------------------------------------------------------

def encrypt_dir_name(name_bytes: bytes, name_len: int, f0: int, f1: int, f2: int) -> bytes:
    """Encrypt directory name (XOR is symmetric, same as decrypt)."""
    return decrypt_dir_name(bytearray(name_bytes), name_len, f0, f1, f2)


def encrypt_file_name(name_bytes: bytes, name_len: int, size_val: int, field6: int) -> bytes:
    """Encrypt file name (XOR is symmetric)."""
    return decrypt_file_name(bytearray(name_bytes), name_len, size_val, field6)


def encrypt_file_data(buf: bytes, fsize: int, field6: int, type_id: int) -> bytes:
    """Encrypt file data (XOR is symmetric)."""
    return decrypt_file_data(buf, fsize, field6, type_id, read_pos=0)


def build_rez_file(root: RezDirEntry, source_encrypted: bool,
                   parser: "RezParser | None", progress_cb=None) -> bytes:
    """
    Build a complete REZ file from a directory tree.
    Returns the full file bytes.

    For files that have _raw_data attribute (newly added), uses that data.
    For files from the original archive, reads from parser.data and re-encrypts if needed.
    """
    # Phase 1: Layout file data sequentially after the 202-byte header
    data_offset = RezHeader.SIZE
    file_data_parts = []  # list of (entry, data_bytes) — data as stored (encrypted)
    entry_offsets = {}  # RezFileEntry id() → new offset

    all_files = collect_all_files(root)
    for i, entry in enumerate(all_files):
        if progress_cb:
            progress_cb(i, len(all_files), f"Packing {entry.filename}...")

        # Get the raw file bytes
        if hasattr(entry, '_raw_data'):
            # Newly added file — _raw_data is plaintext, encrypt it
            raw = entry._raw_data
            if source_encrypted and entry.type_id:
                stored = encrypt_file_data(raw, entry.size, entry.field6, entry.type_id)
            else:
                stored = raw
        else:
            # Existing file from original archive — read raw bytes from parser
            if parser is not None:
                stored = parser.data[entry.offset:entry.offset + entry.size]
            else:
                stored = b'\x00' * entry.size

        entry_offsets[id(entry)] = data_offset
        file_data_parts.append((entry, stored))
        data_offset += len(stored)

    # Phase 2: Build directory tree blocks (post-order: children before parents)
    dir_blocks = {}  # id(dir_entry) → (block_bytes, block_offset)
    # We build from leaves up, so do a post-order traversal

    def build_dir_block(dir_entry: RezDirEntry):
        """Build encrypted directory block, returns bytes."""
        # First build all child directories so their blocks exist
        for child_dir in dir_entry.children_dirs:
            build_dir_block(child_dir)

        parts = []

        # Write file entries
        for fentry in dir_entry.children_files:
            new_offset = entry_offsets.get(id(fentry), fentry.offset)
            # entry_type = 0 for files
            parts.append(struct.pack('<I', 0))

            # Build 32-byte file header
            name_bytes = fentry.name.encode('ascii') + b'\x00'
            name_len = len(name_bytes)
            hdr = struct.pack('<8I',
                              new_offset,          # offset
                              fentry.size,          # size
                              fentry.time,          # time
                              fentry.id,            # id
                              fentry.type_id,       # type_id
                              0,                    # key_ary_size
                              fentry.field6,        # field6
                              name_len)             # name_len
            enc_hdr = decrypt_xor_cyclic(hdr, FILE_HEADER_KEY)
            parts.append(enc_hdr)

            # Encrypted name
            enc_name = encrypt_file_name(bytearray(name_bytes), name_len,
                                         fentry.size, fentry.field6)
            parts.append(enc_name)

            # Comment (null-terminated, just a single null)
            parts.append(b'\x00')
            # No key array (key_ary_size=0)

        # Write directory entries
        for child_dir in dir_entry.children_dirs:
            parts.append(struct.pack('<I', 1))  # entry_type = 1

            child_block_offset, child_block_size = dir_blocks[id(child_dir)]
            name_bytes = child_dir.name.encode('ascii') + b'\x00'
            name_len = len(name_bytes)

            # 16-byte dir header: [dataPos, dataSize, time, nameLen]
            hdr = struct.pack('<4I',
                              child_block_offset,
                              child_block_size,
                              child_dir.time,
                              name_len)
            enc_hdr = decrypt_xor_cyclic(hdr, DIR_HEADER_KEY)
            parts.append(enc_hdr)

            enc_name = encrypt_dir_name(bytearray(name_bytes), name_len,
                                        child_block_offset, child_block_size, child_dir.time)
            parts.append(enc_name)

        block = b''.join(parts)
        block_offset = data_offset
        dir_blocks[id(dir_entry)] = (block_offset, len(block))
        return block

    # Post-order: collect blocks bottom-up
    dir_data_parts = []

    def collect_dir_blocks(dir_entry: RezDirEntry):
        nonlocal data_offset
        for child_dir in dir_entry.children_dirs:
            collect_dir_blocks(child_dir)
        block = build_dir_block_only(dir_entry)
        dir_blocks[id(dir_entry)] = (data_offset, len(block))
        dir_data_parts.append(block)
        data_offset += len(block)

    def build_dir_block_only(dir_entry: RezDirEntry) -> bytes:
        """Build encrypted directory block bytes."""
        parts = []

        for fentry in dir_entry.children_files:
            new_offset = entry_offsets.get(id(fentry), fentry.offset)
            parts.append(struct.pack('<I', 0))

            name_bytes = fentry.name.encode('ascii') + b'\x00'
            name_len = len(name_bytes)
            hdr = struct.pack('<8I',
                              new_offset, fentry.size, fentry.time, fentry.id,
                              fentry.type_id, 0, fentry.field6, name_len)
            enc_hdr = decrypt_xor_cyclic(hdr, FILE_HEADER_KEY)
            parts.append(enc_hdr)

            enc_name = encrypt_file_name(bytearray(name_bytes), name_len,
                                         fentry.size, fentry.field6)
            parts.append(enc_name)
            parts.append(b'\x00')

        for child_dir in dir_entry.children_dirs:
            parts.append(struct.pack('<I', 1))
            child_block_offset, child_block_size = dir_blocks[id(child_dir)]
            name_bytes = child_dir.name.encode('ascii') + b'\x00'
            name_len = len(name_bytes)
            hdr = struct.pack('<4I', child_block_offset, child_block_size,
                              child_dir.time, name_len)
            enc_hdr = decrypt_xor_cyclic(hdr, DIR_HEADER_KEY)
            parts.append(enc_hdr)
            enc_name = encrypt_dir_name(bytearray(name_bytes), name_len,
                                        child_block_offset, child_block_size, child_dir.time)
            parts.append(enc_name)

        return b''.join(parts)

    # Reset and do actual collection
    dir_blocks.clear()
    dir_data_parts.clear()
    collect_dir_blocks(root)

    # Phase 3: Build header
    root_offset, root_size = dir_blocks[id(root)]
    total_size = data_offset

    # Use original header bytes as template, or build fresh
    hdr_bytes = bytearray(RezHeader.SIZE)
    # Magic / copyright / markers from standard LithTech REZ
    hdr_bytes[0] = 0x18
    copyright_str = b"Copyright (C) 1995-2002 LithTech Inc.  All Rights Reserved."
    hdr_bytes[1:1 + len(copyright_str)] = copyright_str
    hdr_bytes[1 + len(copyright_str):62] = b'\x00' * (61 - len(copyright_str))
    hdr_bytes[62] = 0x2A
    hdr_bytes[63] = 0x2E
    desc_str = b"LithTech Resource File"
    hdr_bytes[64:64 + len(desc_str)] = desc_str
    hdr_bytes[64 + len(desc_str):124] = b'\x00' * (60 - len(desc_str))
    hdr_bytes[124:127] = b'JPG'
    hdr_bytes[127] = 0x00
    # numeric_key — 33 bytes of zeros
    hdr_bytes[128:161] = b'\x00' * 33
    # version = 1
    struct.pack_into('<I', hdr_bytes, 161, 1)
    # rootDirPos
    struct.pack_into('<I', hdr_bytes, 165, root_offset)
    # rootDirSize
    struct.pack_into('<I', hdr_bytes, 169, root_size)
    # rootDirTime
    struct.pack_into('<I', hdr_bytes, 173, root.time)
    # nextWritePos = start of dir data
    struct.pack_into('<I', hdr_bytes, 177, total_size)
    # lastModTime
    struct.pack_into('<I', hdr_bytes, 181, int(time.time()) & 0xFFFFFFFF)
    # largest fields — compute from tree
    largest_key_ary = 0
    largest_dir_name = 0
    largest_rez_name = 0

    def compute_largest(node):
        nonlocal largest_dir_name, largest_rez_name
        largest_dir_name = max(largest_dir_name, len(node.name))
        for f in node.children_files:
            largest_rez_name = max(largest_rez_name, len(f.name))
        for d in node.children_dirs:
            compute_largest(d)

    compute_largest(root)
    struct.pack_into('<I', hdr_bytes, 185, largest_key_ary)
    struct.pack_into('<I', hdr_bytes, 189, largest_dir_name)
    struct.pack_into('<I', hdr_bytes, 193, largest_rez_name)
    struct.pack_into('<I', hdr_bytes, 197, 0)  # largest_comment
    hdr_bytes[201] = 1  # is_sorted

    # If we had the original header, copy the magic bytes exactly
    if parser is not None:
        # Copy original header's immutable fields for perfect reproduction
        orig = parser.data[:RezHeader.SIZE]
        hdr_bytes[0:128] = orig[0:128]
        hdr_bytes[128:161] = orig[128:161]

    # Assemble final file
    out = bytearray(hdr_bytes)
    for _, stored_data in file_data_parts:
        out.extend(stored_data)
    for block in dir_data_parts:
        out.extend(block)

    return bytes(out)


# ---------------------------------------------------------------------------
# Custom QListWidget with drag-drop support
# ---------------------------------------------------------------------------

class FileDropListWidget(QListWidget):
    """QListWidget that accepts file drops from Windows Explorer."""
    filesDropped = Signal(list)  # emits list of file paths

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setViewMode(QListWidget.ViewMode.IconMode)
        self.setIconSize(QSize(48, 48))
        self.setGridSize(QSize(100, 80))
        self.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.setMovement(QListWidget.Movement.Static)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setWordWrap(True)
        self.setSpacing(8)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            # Only accept if at least one is a local file
            for url in event.mimeData().urls():
                if url.isLocalFile() and os.path.isfile(url.toLocalFile()):
                    event.acceptProposedAction()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            if url.isLocalFile():
                path = url.toLocalFile()
                if os.path.isfile(path):
                    paths.append(path)
        if paths:
            self.filesDropped.emit(paths)
            event.acceptProposedAction()
        else:
            event.ignore()


# ---------------------------------------------------------------------------
# Main Window
# ---------------------------------------------------------------------------

class RezExplorer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("REZ Explorer")
        self.resize(1000, 650)

        self.parser: RezParser | None = None
        self.root: RezDirEntry | None = None
        self.current_dir: RezDirEntry | None = None
        self.source_encrypted: bool = False
        self._filepath: str = ""
        # Map tree items to dir entries
        self._tree_map: dict[int, RezDirEntry] = {}
        # Map list items to file entries
        self._list_map: dict[int, RezFileEntry] = {}

        self._build_ui()

    # ---- UI Construction ----

    def _build_ui(self):
        # Menu bar
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        act_open = file_menu.addAction("&Open...")
        act_open.setShortcut(QKeySequence.StandardKey.Open)
        act_open.triggered.connect(self._on_open)

        act_save = file_menu.addAction("&Save As...")
        act_save.setShortcut(QKeySequence("Ctrl+Shift+S"))
        act_save.triggered.connect(self._on_save_as)

        file_menu.addSeparator()
        act_exit = file_menu.addAction("E&xit")
        act_exit.setShortcut(QKeySequence("Alt+F4"))
        act_exit.triggered.connect(self.close)

        edit_menu = menubar.addMenu("&Edit")
        act_add = edit_menu.addAction("&Add Files...")
        act_add.triggered.connect(self._on_add_files)
        edit_menu.addSeparator()
        act_delete = edit_menu.addAction("&Delete Selected")
        act_delete.setShortcut(QKeySequence.StandardKey.Delete)
        act_delete.triggered.connect(self._on_delete_selected)

        tools_menu = menubar.addMenu("&Tools")
        act_extract_all = tools_menu.addAction("Extract &All...")
        act_extract_all.triggered.connect(self._on_extract_all)

        # Splitter: left tree + right icon grid
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        self.dir_tree = QTreeWidget()
        self.dir_tree.setHeaderLabel("Directories")
        self.dir_tree.setMinimumWidth(180)
        self.dir_tree.itemClicked.connect(self._on_tree_click)
        self.dir_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.dir_tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        splitter.addWidget(self.dir_tree)

        self.file_list = FileDropListWidget()
        self.file_list.filesDropped.connect(self._on_files_dropped)
        self.file_list.customContextMenuRequested.connect(self._on_context_menu)
        self.file_list.itemDoubleClicked.connect(self._on_item_double_click)
        splitter.addWidget(self.file_list)

        splitter.setSizes([220, 780])

        # Status bar
        self.statusBar().showMessage("No file loaded. Use File → Open to load a REZ archive.")

    # ---- File I/O ----

    def _on_open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open REZ File", "",
            "REZ Files (*.rez);;All Files (*)")
        if not path:
            return
        try:
            parser = RezParser(path)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to parse REZ file:\n{e}")
            return

        self.parser = parser
        self.root = parser.root
        self._filepath = path
        self.source_encrypted = self._detect_encryption(parser)

        enc_label = "encrypted" if self.source_encrypted else "plain"
        self.setWindowTitle(f"REZ Explorer — {os.path.basename(path)} ({enc_label})")

        self._populate_tree()
        self._show_dir(self.root)

    def _detect_encryption(self, parser: RezParser) -> bool:
        """Auto-detect if file data is encrypted by checking DLL entries."""
        for _, entry in parser.list_all_files():
            if entry.extension == '.dll' and entry.size > 2:
                raw = parser.data[entry.offset:entry.offset + 2]
                if raw == b'MZ':
                    return False  # data already readable
                dec = parser.get_file_data(entry, decrypt=True)
                if dec[:2] == b'MZ':
                    return True  # decryption produces valid PE
                return False
        return False

    def _on_save_as(self):
        if self.root is None:
            QMessageBox.warning(self, "No Data", "No REZ archive loaded to save.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save REZ File As", "",
            "REZ Files (*.rez);;All Files (*)")
        if not path:
            return

        progress = QProgressDialog("Building REZ file...", "Cancel", 0, 100, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.setValue(0)

        def on_progress(current, total, msg):
            if total > 0:
                progress.setValue(int(current / total * 90))
            progress.setLabelText(msg)
            QApplication.processEvents()

        try:
            data = build_rez_file(self.root, self.source_encrypted, self.parser,
                                  progress_cb=on_progress)
            progress.setLabelText("Writing file...")
            progress.setValue(95)
            QApplication.processEvents()

            with open(path, 'wb') as f:
                f.write(data)

            progress.setValue(100)
            self.statusBar().showMessage(f"Saved: {path} ({format_size(len(data))})")
        except Exception as e:
            progress.close()
            QMessageBox.critical(self, "Error", f"Failed to save REZ file:\n{e}")

    # ---- Tree Navigation ----

    def _populate_tree(self):
        self.dir_tree.clear()
        self._tree_map.clear()
        if self.root is None:
            return

        root_item = QTreeWidgetItem([self.root.name])
        self._tree_map[id(root_item)] = self.root
        self.dir_tree.addTopLevelItem(root_item)
        self._add_tree_children(root_item, self.root)
        root_item.setExpanded(True)

    def _add_tree_children(self, parent_item: QTreeWidgetItem, parent_dir: RezDirEntry):
        for child_dir in parent_dir.children_dirs:
            item = QTreeWidgetItem([child_dir.name])
            self._tree_map[id(item)] = child_dir
            parent_item.addChild(item)
            self._add_tree_children(item, child_dir)

    def _on_tree_click(self, item: QTreeWidgetItem, column: int):
        dir_entry = self._tree_map.get(id(item))
        if dir_entry:
            self._show_dir(dir_entry)

    def _show_dir(self, dir_entry: RezDirEntry):
        """Display files of a directory in the icon grid."""
        self.current_dir = dir_entry
        self.file_list.clear()
        self._list_map.clear()

        icon_provider = _get_icon_for_ext  # function-based

        for f in dir_entry.children_files:
            icon = icon_provider(f.extension)
            item = QListWidgetItem(icon, f.filename)
            item.setToolTip(
                f"Name: {f.filename}\n"
                f"Size: {format_size(f.size)}\n"
                f"Offset: 0x{f.offset:X}\n"
                f"TypeID: 0x{f.type_id:08X}\n"
                f"Field6: {f.field6}"
            )
            self.file_list.addItem(item)
            self._list_map[id(item)] = f

        # Also show subdirectories as folder items
        for d in dir_entry.children_dirs:
            icon = _get_folder_icon()
            cf, cb = count_entries(d)
            item = QListWidgetItem(icon, d.name)
            item.setToolTip(f"Directory: {d.name}\n{cf} files, {format_size(cb)}")
            item.setData(Qt.ItemDataRole.UserRole, ("dir", d))
            self.file_list.addItem(item)

        nf, nb = count_entries(dir_entry)
        enc_label = " [encrypted]" if self.source_encrypted else ""
        self.statusBar().showMessage(
            f"{dir_entry.name}: {len(dir_entry.children_files)} files, "
            f"{len(dir_entry.children_dirs)} dirs — "
            f"Total: {nf} files, {format_size(nb)}{enc_label}"
        )

    def _on_item_double_click(self, item: QListWidgetItem):
        """Double-click on a folder navigates into it."""
        data = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, tuple) and data[0] == "dir":
            dir_entry = data[1]
            self._show_dir(dir_entry)
            # Select it in the tree as well
            self._select_tree_item(dir_entry)

    def _select_tree_item(self, target_dir: RezDirEntry):
        """Find and select a directory in the tree widget."""
        for item_id, dir_entry in self._tree_map.items():
            if dir_entry is target_dir:
                # Find the QTreeWidgetItem — iterate all items
                it = _find_tree_item(self.dir_tree, target_dir, self._tree_map)
                if it:
                    self.dir_tree.setCurrentItem(it)
                break

    # ---- Add / Delete / Extract ----

    def _on_add_files(self):
        if self.current_dir is None:
            QMessageBox.warning(self, "No Directory",
                                "Open a REZ file and select a directory first.")
            return

        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add Files to REZ", "", "All Files (*)")
        if paths:
            self._add_files_to_current(paths)

    def _on_files_dropped(self, paths: list[str]):
        if self.current_dir is None:
            QMessageBox.warning(self, "No Directory",
                                "Open a REZ file first before dropping files.")
            return
        self._add_files_to_current(paths)

    def _add_files_to_current(self, paths: list[str]):
        """Add external files to the current directory."""
        for path in paths:
            basename = os.path.basename(path)
            name, ext = os.path.splitext(basename)
            type_id = ext_to_type_id(ext) if ext else 0

            with open(path, 'rb') as f:
                raw_data = f.read()

            entry = RezFileEntry(
                name=name.upper(),
                res_id=0,
                offset=0,  # will be assigned on save
                time_val=int(os.path.getmtime(path)) & 0xFFFFFFFF,
                size=len(raw_data),
                type_id=type_id,
                field6=0,
            )
            entry._raw_data = raw_data
            self.current_dir.children_files.append(entry)

        self._show_dir(self.current_dir)
        self.statusBar().showMessage(f"Added {len(paths)} file(s).")

    # ---- Directory Tree Context Menu ----

    def _on_tree_context_menu(self, pos):
        item = self.dir_tree.itemAt(pos)
        dir_entry = self._tree_map.get(id(item)) if item else None

        menu = QMenu(self)
        act_new = menu.addAction("New Folder...")
        act_rename = menu.addAction("Rename...")
        act_delete = menu.addAction("Delete")

        # Only enable rename/delete for non-root directories
        is_root = (dir_entry is self.root)
        act_rename.setEnabled(dir_entry is not None and not is_root)
        act_delete.setEnabled(dir_entry is not None and not is_root)
        act_new.setEnabled(dir_entry is not None)

        action = menu.exec(self.dir_tree.mapToGlobal(pos))
        if action == act_new and dir_entry:
            self._on_new_folder(dir_entry)
        elif action == act_rename and dir_entry:
            self._on_rename_folder(dir_entry)
        elif action == act_delete and dir_entry:
            self._on_delete_folder(dir_entry)

    def _on_new_folder(self, parent_dir: RezDirEntry):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:")
        if ok and name.strip():
            new_dir = RezDirEntry(name.strip().upper(), 0, 0,
                                  int(time.time()) & 0xFFFFFFFF)
            parent_dir.children_dirs.append(new_dir)
            self._populate_tree()
            if self.current_dir is parent_dir:
                self._show_dir(parent_dir)

    def _on_rename_folder(self, dir_entry: RezDirEntry):
        name, ok = QInputDialog.getText(self, "Rename Folder",
                                        "New name:", text=dir_entry.name)
        if ok and name.strip():
            dir_entry.name = name.strip().upper()
            self._populate_tree()
            if self.current_dir is dir_entry:
                self._show_dir(dir_entry)

    def _on_delete_folder(self, dir_entry: RezDirEntry):
        nf, nb = count_entries(dir_entry)
        msg = f"Delete folder \"{dir_entry.name}\"?"
        if nf > 0:
            msg += f"\n(Contains {nf} file(s), {format_size(nb)})"
        reply = QMessageBox.question(self, "Confirm Delete", msg)
        if reply != QMessageBox.StandardButton.Yes:
            return
        # Find parent and remove
        parent = self._find_parent_dir(self.root, dir_entry)
        if parent:
            parent.children_dirs.remove(dir_entry)
            self._populate_tree()
            # If we were viewing the deleted dir, go to parent
            if self.current_dir is dir_entry:
                self._show_dir(parent)
            elif self.current_dir:
                self._show_dir(self.current_dir)

    def _find_parent_dir(self, node: RezDirEntry,
                         target: RezDirEntry) -> RezDirEntry | None:
        """Find the parent directory of target in the tree."""
        if target in node.children_dirs:
            return node
        for child in node.children_dirs:
            result = self._find_parent_dir(child, target)
            if result:
                return result
        return None

    def _on_delete_selected(self):
        if self.current_dir is None:
            return
        selected = self.file_list.selectedItems()
        if not selected:
            return

        names = [item.text() for item in selected]
        if len(names) > 5:
            msg = f"Delete {len(names)} selected items?"
        else:
            msg = f"Delete:\n" + "\n".join(f"  {n}" for n in names)
        reply = QMessageBox.question(self, "Confirm Delete", msg)
        if reply != QMessageBox.StandardButton.Yes:
            return

        for item in selected:
            # Check if it's a directory
            data = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(data, tuple) and data[0] == "dir":
                dir_entry = data[1]
                if dir_entry in self.current_dir.children_dirs:
                    self.current_dir.children_dirs.remove(dir_entry)
            else:
                # File entry
                fentry = self._list_map.get(id(item))
                if fentry and fentry in self.current_dir.children_files:
                    self.current_dir.children_files.remove(fentry)

        self._populate_tree()
        self._show_dir(self.current_dir)

    def _on_extract_selected(self):
        selected = self.file_list.selectedItems()
        if not selected:
            QMessageBox.information(self, "Nothing Selected",
                                    "Select files to extract first.")
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Extract To")
        if not out_dir:
            return

        extracted = 0
        for item in selected:
            data = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(data, tuple) and data[0] == "dir":
                continue  # skip dirs for now
            fentry = self._list_map.get(id(item))
            if fentry:
                self._extract_entry(fentry, out_dir)
                extracted += 1

        self.statusBar().showMessage(f"Extracted {extracted} file(s) to {out_dir}")

    def _on_extract_all(self):
        if self.root is None:
            return
        out_dir = QFileDialog.getExistingDirectory(self, "Extract All To")
        if not out_dir:
            return

        all_files = collect_all_files(self.root)
        for f in all_files:
            self._extract_entry(f, out_dir)

        self.statusBar().showMessage(
            f"Extracted {len(all_files)} file(s) to {out_dir}")

    def _extract_entry(self, entry: RezFileEntry, out_dir: str):
        """Extract a single file entry to disk."""
        if hasattr(entry, '_raw_data'):
            data = entry._raw_data
        elif self.parser is not None:
            data = self.parser.get_file_data(entry, decrypt=self.source_encrypted)
        else:
            data = b''

        out_path = os.path.join(out_dir, entry.filename)
        with open(out_path, 'wb') as f:
            f.write(data)

    # ---- Context Menu ----

    def _on_context_menu(self, pos):
        menu = QMenu(self)
        selected = self.file_list.selectedItems()

        if selected:
            act_extract = menu.addAction("Extract...")
            act_delete = menu.addAction("Delete")
            action = menu.exec(self.file_list.mapToGlobal(pos))
            if action == act_extract:
                self._on_extract_selected()
            elif action == act_delete:
                self._on_delete_selected()
        else:
            act_extract_all = menu.addAction("Extract All...")
            action = menu.exec(self.file_list.mapToGlobal(pos))
            if action == act_extract_all:
                self._on_extract_all()


# ---------------------------------------------------------------------------
# Icon helpers — uses QFileIconProvider for real Windows system icons
# ---------------------------------------------------------------------------

_icon_cache: dict[str, QIcon] = {}
_icon_provider = None  # lazy-init QFileIconProvider


def _get_provider():
    global _icon_provider
    if _icon_provider is None:
        from PySide6.QtWidgets import QFileIconProvider
        _icon_provider = QFileIconProvider()
    return _icon_provider


def _get_icon_for_ext(ext: str) -> QIcon:
    """Get the Windows system icon for a file extension (e.g. DLL gear icon)."""
    ext = ext.lower()
    if ext in _icon_cache:
        return _icon_cache[ext]

    from PySide6.QtCore import QFileInfo
    # QFileIconProvider.icon(QFileInfo) uses SHGetFileInfo on Windows,
    # which resolves icons by extension even for non-existent paths.
    info = QFileInfo("dummy" + ext)
    icon = _get_provider().icon(info)

    # Fallback if the provider returned a null icon
    if icon.isNull():
        from PySide6.QtWidgets import QStyle
        icon = QApplication.instance().style().standardIcon(
            QStyle.StandardPixmap.SP_FileIcon)

    _icon_cache[ext] = icon
    return icon


def _get_folder_icon() -> QIcon:
    if "folder" in _icon_cache:
        return _icon_cache["folder"]
    from PySide6.QtWidgets import QFileIconProvider
    icon = _get_provider().icon(QFileIconProvider.IconType.Folder)
    _icon_cache["folder"] = icon
    return icon


def _find_tree_item(tree: QTreeWidget, target: RezDirEntry,
                    tree_map: dict) -> QTreeWidgetItem | None:
    """Find QTreeWidgetItem for a given RezDirEntry."""
    def _search(item: QTreeWidgetItem):
        if tree_map.get(id(item)) is target:
            return item
        for i in range(item.childCount()):
            result = _search(item.child(i))
            if result:
                return result
        return None

    for i in range(tree.topLevelItemCount()):
        result = _search(tree.topLevelItem(i))
        if result:
            return result
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("REZ Explorer")

    window = RezExplorer()
    window.show()

    # If a file was passed on command line, open it
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        window._filepath = sys.argv[1]
        try:
            parser = RezParser(sys.argv[1])
            window.parser = parser
            window.root = parser.root
            window.source_encrypted = window._detect_encryption(parser)
            enc_label = "encrypted" if window.source_encrypted else "plain"
            window.setWindowTitle(
                f"REZ Explorer — {os.path.basename(sys.argv[1])} ({enc_label})")
            window._populate_tree()
            window._show_dir(window.root)
        except Exception as e:
            QMessageBox.critical(window, "Error", f"Failed to open: {e}")

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
