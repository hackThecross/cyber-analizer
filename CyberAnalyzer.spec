# -*- mode: python ; coding: utf-8 -*-
import os
import sys

block_cipher = None

added_files = [
    ('imagenes', 'imagenes'),
    ('ioc', 'ioc'),
    ('world.geojson', '.'),
    ('map_tiles', 'map_tiles'),
]

a = Analysis(
    ['main.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    datas=added_files,
    hiddenimports=[
        'PIL',
        'PIL._tkinter_finder',
        'psutil',
        'requests',
        'urllib.request',
        'tkinter',
        'tkinter.ttk',
        'tkinter.messagebox',
        'tkinter.simpledialog',
        'tkinter.filedialog',
        'core',
        'core.diagnostico',
        'core.red',
        'core.edr_actions',
        'core.vt_client',
        'core.software_inventory',
        'core.hash_utils',
        'core.threat_intel',
        'core.process_activity',
        'core.usb_diagnostico',
        'core.optimizer',
        'core.deep_scan',
        'core.security_logs',
        'core.settings_manager',
        'core.redr',
        'core.utils_red',
        'core.edr.persistencia',
        'core.firewall_guard',
        'core.firewall_map',
        'core.toast_notifier',
        'core.panic_mode',
        'core.report_generator',
        'core.anti_ransomware',
        'core.usb_dlp',
        'core.file_integrity',
        'core.dns_sinkhole',
        'core.audio_alerts',
        'core.updater',
        'packaging',
        'packaging.version',
    ],
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
    [],
    exclude_binaries=True,
    name='CyberAnalyzer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
    icon='imagenes/icono.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CyberAnalyzer',
)
