# REZ Explorer

PySide6 GUI for browsing and editing LithTech REZ archive files.

Built for **Heat Project** (韓國線上賽車遊戲), but should work with other LithTech Jupiter engine REZ files.

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)
![PySide6](https://img.shields.io/badge/GUI-PySide6-green)

## Features

- **Browse** — Directory tree + icon grid view with Windows system icons
- **Auto-detect encryption** — Automatically detects encrypted archives (e.g. BINARIES.REZ)
- **Extract** — Extract selected files or all files, with automatic decryption
- **Add files** — Drag-and-drop from Windows Explorer or via menu
- **Delete** — Remove files or folders from the archive
- **New Folder / Rename** — Right-click directory tree to manage folders
- **Save As** — Write modified archive back to REZ format with proper encryption

## Requirements

- Python 3.10+
- PySide6

```
pip install PySide6
```

## Usage

```bash
# Launch GUI
python main.py

# Open a REZ file directly
python main.py path/to/file.rez
```

### Browsing

1. **File → Open** to load a `.rez` archive
2. Click directories in the left tree to browse
3. Double-click folders in the icon grid to navigate into them

### Editing

- **Drag-and-drop** files from Windows Explorer onto the icon grid
- **Right-click** directory tree → New Folder / Rename / Delete
- **Right-click** icon grid → Extract or Delete selected files
- **Right-click** icon grid (no selection) → Extract All

### Saving

**File → Save As** writes a complete REZ file. Newly added files are encrypted if the source archive was encrypted.

## REZ Format

REZ is LithTech's custom resource archive format:

- 202-byte header with magic validation
- Encrypted directory tree (XOR-based)
- Optional file data encryption (extended 513-byte XOR table)

Requires `rez_parser.py` in the parent directory for parsing/encryption logic.

## Known REZ Files (Heat Project)

| File | Encrypted | Contents |
|------|-----------|----------|
| Engine.REZ | No | RenderStyles (.ltb), Console font (.dtx) |
| BINARIES.REZ | Yes | cshell.dll, cres.dll, sres.dll, object.lto, etc. |

> **Note:** `GameInterface.rez`, `Resource.rez`, `Resourcex.rez` are disguised DLLs (MZ/PE header), not REZ format.

## License

MIT
