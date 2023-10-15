# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(
    ['src\\manager.py'],
    pathex=[],
    binaries=[],
    datas=[('src/images\\1.png', 'images/.'), ('src/images\\eye_icon1.png', 'images/.'), ('src/images\\generate.png', 'images/.'), ('src/images\\hidden1.png', 'images/.'), ('src/images\\key.png', 'images/.'), ('src/images\\net.ico', 'images/.'), ('src/images\\shield.ico', 'images/.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SecurEntry',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['src\\images\\shield.ico'],
)
