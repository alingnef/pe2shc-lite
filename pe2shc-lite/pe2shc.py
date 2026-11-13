#!/usr/bin/env python3
"""Convert a native Windows EXE into input.exe.shc (Python 3.10+, no pip).

The runtime loaders are unchanged bytes from hasherezade/pe_to_shellcode:
49ba145dac7761c63563617db8d54cde39e4149d, loader_v2. See LICENSE.txt.
"""
import argparse
import base64
import hashlib
from pathlib import Path
import struct
import sys

LIMIT = 256 * 1024 * 1024
REDIRECT = {
    32: bytes.fromhex("4d5a4552e8000000005883e809500500000000ffd0c300"),
    64: bytes.fromhex("4d5a4552e800000000594883e909488bc1480500000000ffd0c300"),
}
STUB_HASH = {
    32: "9c703588c7d8e1e4f0e949da269eee353bba661eadcd3011c829dde778526acf",
    64: "e79c91e8157fef862be8cbe80bdf57b87a541416717265f81f669d751fca4a3d",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(data, offset, fmt="I"):
    size = struct.calcsize("<" + fmt)
    require(0 <= offset <= len(data) - size, "PE field is outside the file/image")
    return struct.unpack_from("<" + fmt, data, offset)[0]


def cstring(image, rva):
    require(0 < rva < len(image), "Invalid import-name RVA")
    end = image.find(b"\0", rva, min(len(image), rva + 4096))
    require(end > rva, "Empty or unterminated import name")


def check_loader(image, directories, bits, base, headers):
    """Check the subset understood by the embedded, unchanged loader v2."""
    ptr, fmt = bits // 8, "Q" if bits == 64 else "I"
    for index, name in ((11, "Bound imports"), (13, "Delay imports"), (14, ".NET/CLR")):
        require(not directories[index][0], name + " are not supported")

    cursor, size = directories[5]
    require(cursor and size, "EXE needs base relocations; rebuild without /FIXED")
    end, relocated = cursor + size, set()
    while cursor < end:
        require(end - cursor >= 8, "Truncated relocation block")
        page, block = struct.unpack_from("<II", image, cursor)
        if not page:
            require(not any(image[cursor:end]), "Invalid relocation terminator")
            break
        require(8 <= block <= end - cursor and block % 4 == 0, "Invalid relocation block")
        padding = False
        for pos in range(cursor + 8, cursor + block, 2):
            item = number(image, pos, "H")
            kind, target = item >> 12, page + (item & 0xFFF)
            if not kind:
                padding = True
                continue
            require(not padding, "Loader v2 requires ABSOLUTE padding at block end")
            require(kind == (10 if bits == 64 else 3), "Unsupported relocation type")
            require(headers <= target <= len(image) - ptr and target not in relocated,
                    "Invalid or duplicate relocation target")
            relocated.add(target)
        cursor += block
    # Upstream iterates until a zero PageRVA, not until directory.Size.
    require(number(image, cursor) == 0, "Loader v2 needs a zero relocation sentinel")

    cursor, size = directories[1]
    if cursor:
        end = cursor + size
        while True:
            require(cursor + 20 <= end, "Missing import descriptor terminator")
            oft, stamp, chain, name, thunk = struct.unpack_from("<IIIII", image, cursor)
            if not name:
                require(not any((oft, stamp, chain, thunk)), "Invalid import terminator")
                break
            require(not stamp and thunk, "Bound or invalid import descriptor")
            cstring(image, name)
            while True:
                value = number(image, thunk, fmt)
                if not value:
                    break
                if value & (1 << (bits - 1)):
                    require(value & ~((1 << (bits - 1)) | 0xFFFF) == 0,
                            "Invalid ordinal import")
                else:
                    cstring(image, value + 2)
                thunk += ptr
            cursor += 20

    tls, size = directories[9]
    if tls:
        require(size >= (40 if bits == 64 else 24), "Truncated TLS directory")
        start, end, index, callbacks = (number(image, tls + i * ptr, fmt) for i in range(4))
        require(start == end and number(image, tls + 4 * ptr) == 0,
                "Static TLS is unsupported; only callback-only TLS can be used")
        if callbacks:
            require(tls + 3 * ptr in relocated, "TLS callback array lacks relocation")
            cursor = callbacks - base
            while True:
                callback = number(image, cursor, fmt)
                if not callback:
                    break
                require(cursor in relocated and headers <= callback - base < len(image),
                        "Invalid TLS callback or missing relocation")
                cursor += ptr


def convert(data):
    """Return (shellcode_bytes, architecture_bits). Does not execute the EXE."""
    require(64 <= len(data) <= LIMIT and data[:2] == b"MZ", "Invalid/oversized MZ file")
    require(data[:5] != b"MZER\xe8", "Already converted; select the original EXE")
    nt = number(data, 0x3C)
    require(64 <= nt <= len(data) - 24 and data[nt:nt + 4] == b"PE\0\0", "Invalid PE header")
    machine, count = number(data, nt + 4, "H"), number(data, nt + 6, "H")
    opt_size, flags = number(data, nt + 20, "H"), number(data, nt + 22, "H")
    opt = nt + 24
    kind = (machine, number(data, opt, "H"))
    require(kind in ((0x14C, 0x10B), (0x8664, 0x20B)), "Only native x86/x64 EXEs are supported")
    bits = 64 if machine == 0x8664 else 32
    directory_offset = 112 if bits == 64 else 96
    require(opt_size >= directory_offset + 16 * 8 and opt + opt_size <= len(data),
            "Expected a complete PE optional header with 16 data directories")
    require(number(data, opt + directory_offset - 4) == 16, "Expected 16 data directories")
    require(flags & 2 and not flags & (0x2000 | 1), "Expected EXE with relocations, not DLL")
    require(number(data, opt + 68, "H") in (2, 3), "Only Windows GUI/console EXEs are supported")
    base = number(data, opt + (24 if bits == 64 else 28), "Q" if bits == 64 else "I")
    entry = number(data, opt + 16)
    sa, fa = number(data, opt + 32), number(data, opt + 36)
    size, headers = number(data, opt + 56), number(data, opt + 60)
    require(4096 <= sa <= 65536 and sa & (sa - 1) == 0, "Unsupported SectionAlignment")
    require(512 <= fa <= sa and fa & (fa - 1) == 0, "Invalid FileAlignment")
    require(0 < size <= LIMIT and size % sa == 0, "Invalid SizeOfImage")
    table = opt + opt_size
    require(1 <= count <= 96 and table + count * 40 <= headers <= min(len(data), size),
            "Invalid section table or SizeOfHeaders")
    require(headers % fa == 0, "Invalid header alignment")

    # File layout -> memory layout: copy each raw section to its RVA.
    image = bytearray(size)
    image[:headers] = data[:headers]
    sections, ranges = [], []
    previous_end, entry_ok = (headers + sa - 1) // sa * sa, False
    for i in range(count):
        pos = table + i * 40
        vs, va, raw_size, raw = struct.unpack_from("<IIII", data, pos + 8)
        span = (vs + sa - 1) // sa * sa
        require(vs and va % sa == 0 and va >= previous_end and va + span <= size,
                "Invalid or overlapping virtual section")
        require(raw_size <= span, "Raw section exceeds its virtual span")
        if raw_size:
            require(raw >= headers and raw % fa == 0 and raw_size % fa == 0
                    and raw + raw_size <= len(data), "Invalid/truncated raw section")
            require(all(raw >= end or start >= raw + raw_size for start, end in ranges),
                    "Overlapping raw sections")
            ranges.append((raw, raw + raw_size))
            image[va:va + raw_size] = data[raw:raw + raw_size]
        entry_ok |= va <= entry < va + vs and bool(number(data, pos + 36) & 0x20000000)
        sections.append((pos, span, va))
        previous_end = va + span
    require(entry_ok, "Entry point is not in an executable section")
    directories = [struct.unpack_from("<II", data, opt + directory_offset + i * 8) for i in range(16)]
    for i, (rva, length) in enumerate(directories):
        if rva and i != 4:  # Security directory uses file offsets.
            require(rva < size and length <= size - rva, "Data directory exceeds image")
    check_loader(image, directories, bits, base, headers)

    # Redirect from byte zero to the loader appended after SizeOfImage.
    redirect = bytearray(REDIRECT[bits])
    struct.pack_into("<I", redirect, len(redirect) - 8, size)
    image[:len(redirect)] = redirect
    image[0x20] = 0  # LDS_CLEAN; preserve e_lfanew at 0x3c.
    struct.pack_into("<I", image, opt + 36, sa)
    for pos, span, va in sections:
        struct.pack_into("<IIII", image, pos + 8, span, va, span, va)
    # These original file offsets/checksums no longer describe the output.
    struct.pack_into("<I", image, opt + 64, 0)
    struct.pack_into("<II", image, nt + 12, 0, 0)
    for i in (4, 6):
        struct.pack_into("<II", image, opt + directory_offset + i * 8, 0, 0)
    stub = base64.b64decode(STUB_BASE64[bits])
    require(hashlib.sha256(stub).hexdigest() == STUB_HASH[bits], "Embedded loader is corrupted")
    return bytes(image) + stub, bits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Original native Windows EXE")
    parser.add_argument("-o", "--output", type=Path, help="Default: input path + .shc")
    args = parser.parse_args()
    try:
        require(args.input.stat().st_size <= LIMIT, "Input exceeds 256 MiB")
        blob, bits = convert(args.input.read_bytes())
        output = args.output or Path(str(args.input) + ".shc")
        # Exclusive creation also protects the input and existing files.
        with output.open("xb") as file:
            file.write(blob)
        runner = "runshc.exe" if bits == 64 else "runshc32.exe"
        print(f"[+] {bits}-bit EXE -> {output} ({len(blob)} bytes)")
        print(f'[+] Windows: .\\{runner} "{output}"')
        return 0
    except (OSError, ValueError, struct.error, MemoryError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


# Embedded data, not additional Python dependencies. Populated from upstream.
STUB_BASE64 = {
    32: (
        'VYvsUVGNRfhTUOgHAgAAWYTAdQiDyP/pAQEAAFaLdQi4TVoAAFdmOQYPhekAAACLfjwD/oE/UEUAAA+F2AAAAIpG'
        'IDwCD4TGAAAAPAN1LLgAIAAAZoVHFg+EswAAAItHKDPbU1MDxlb/0IXAD4SpAAAAxkYgAumgAAAAM9uEwHVkjYeg'
        'AAAAORh1B2r96YgAAAD/dzRWUOgSAQAAg8QMhMB1BGr863M5n4AAAAB0I1b/t4QAAAD/t4AAAAD/dfz/dfjohgAA'
        'AIPEFITAdQRq++tIjYfAAAAAORh0CVZQ6D8AAABZWcZGIAG5ACAAAItHKAPGxkYgAmaFTxZ0EFNqAVb/0IXAdBTG'
        'RiAD6w7/0OsKuN8EAADrA2r+WF9eW8nCBACLRCQEVleLfCQQiwCLdDgMhfZ0EosOhcl0DGoAagFX/9GDxgR17l+w'
        'AV7DU4tcJBhVVot0JBhXA/PrPAPDUP9UJBiL6IXtdECLfhAD++sfeQUPt8HrBY1DAgPBhcB0KVBV/1QkIIXAdB+J'
        'B4PHBIsPhcl124PGFItGDIXAdb2F9g+VwF9eXVvDMsDr94tEJARTVVaLCANMJBRX60eLQQSD+AhyP41o+NHtagBb'
        'dDIPt1RZCGaLwmbB6AxmhcB0IWaD+AN1K4tEJBiB4v8PAAArRCQcA9YDVCQYAQJDO91yzgNJBIsxhfZ1s7ABX15d'
        'W8MywOv3VldoAp/mauiLAQAAi/BZhfZ0MWiNvcE/Vuh8AAAAi/hZWYX/dB5o/x98yVboaQAAAFlZhcB0DYtMJAyJ'
        'QQSwAYk56wIywF9ew1NWi3QkDIPK/4oehNt0O4p8JBBXhP91Co1DvzwZdwOAwyBqCF+Lyg++w9HpM8KL0YHyIIO4'
        '7SQBD0TR0PuD7wF140aKHoTbdctf99Jei8Jbw1FRU1VWi3QkGLhNWgAAV2Y5BnVhi0Y8i0QweIXAdFaLVDAcM/+L'
        'TDAYiVQkHItUMCCLRDAkiUwkEIXJdDiNHDKNLDCLTCQcD7dFAGoBjQSBA8aJRCQYiwMDxlDoT////1lZO0QkIHQW'
        'R4PFAoPDBDt8JBByzjPAX15dW1lZw4tEJBSLAAPG6+9WV4t8JAyDyv8z9g+3B2aFwHRbU1WAfCQYAA+3yIlMJBR1'
        'EI1Bv2aD+Bl3B4PBIIlMJBRmi1wkFGoIXYvCM8rR6IvQgfIgg7jtgOEBD0TQZtHrZolcJBSD7QF0BotMJBTr2UYP'
        'twR3ZoXAdaldW/fSX4vCXsNkoTAAAABTVleLeAyDxxSLN+sojUb4hcB0JYtYGIXbdB6DeDAAdBJqAP9wMOha////'
        'WVk7RCQQdAyLNjv3ddQzwF9eW8OLw+v4AAAAAAAAAAAAAA=='
    ),
    64: (
        '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'
        'AAAAAAAAAAAAAAAAAAAAAAAA'
    ),
}


if __name__ == "__main__":
    raise SystemExit(main())
