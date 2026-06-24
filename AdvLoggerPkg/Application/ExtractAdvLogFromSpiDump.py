#!/usr/bin/env python3
# @file
#
# Extract and decode persisted AdvLog data from a BIOS SPI dump.
#
# Expected workflow:
#   1) Find ALGR persistence signature near the provided SPI offset.
#   2) Parse ADVLOG_FLASH_PERSISTENCE_HEADER.
#   3) Read exactly [header + DataSize] bytes from the dump.
#   4) Drop the header, then decompress payload if flagged compressed.
#   5) Decode the recovered AdvLogger buffer into a text log via DecodeUefiLog.py.
#
# Copyright (c) Microsoft Corporation.
# SPDX-License-Identifier: BSD-2-Clause-Patent

import argparse
import binascii
import lzma
import os
import struct
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

ADVLOG_SIGNATURE_SEARCH_WINDOW = 0x00400000  # 4MB bounded signature scan window.
# 64-byte ADVLOG_FLASH_PERSISTENCE_HEADER (pack(1)):
#   Signature(4), Version(2), AdvLogInfoVersion(2), DataSize(4),
#   Codec(2), NotifyPhase(2), TicksAtTime(8), TimerFrequency(8),
#   AdvLogInfoTime.EFI_TIME(16): Year(2),Month,Day,Hour,Min,Sec,Pad1,Nanosecond(4),TZ(2),DL,Pad2,
#   OriginalDataSize(4), Crc32(4), Reserved[2](8)
ADVLOG_HEADER_STRUCT_FORMAT = "<IHHIHHQQHBBBBBxIhBxIIII"
ADVLOG_HEADER_SIZE = struct.calcsize(ADVLOG_HEADER_STRUCT_FORMAT)
ADVLOG_SIG_BYTES = b"ALGR"
ADVLOG_SIG_U32 = 0x52474C41  # SIGNATURE_32('A','L','G','R')
# Python parser version guard for ADVLOG SPI dump records.
# Keep this aligned with firmware ADVLOG_FLASH_PERSISTENCE_VERSION.
# If ADVLOG_FLASH_PERSISTENCE_HEADER layout/version changes in firmware and
# this script is not updated, parsing is blocked to avoid struct mismatch.
ADVLOG_SPI_DUMP_PYTHON_VERSION = 0x00000001

# ADVLOG_COMPRESS_ALGORITHM values from AdvLogPersistenceLib.h (Codec field).
ADVLOG_COMPRESS_NONE = 0
ADVLOG_COMPRESS_LZ4 = 1
ADVLOG_COMPRESS_LZMA = 2

# ADVLOG_PERSISTENCE_PHASE display strings.
_ADVLOG_NOTIFY_PHASE_STRINGS = ["[CAR]", "[SHADOW]", "[ENDOFPEI]", "[DXE]"]

# Phase strings from AdvancedLoggerInternal.h (ADVANCED_LOGGER_PHASE_*).
_ALM_PHASE_STRINGS = [
    "", "[SEC]", "[PEI]", "[PEI64]", "[DXE]",
    "[RUNTIME]", "[MM_CORE]", "[MM]", "[SMM_CORE]", "[SMM]", "[TFA]",
]

# Debug level strings from MdePkg/Include/Library/DebugLib.h.
_ALM_DEBUG_LEVEL_STRINGS = {
    0x00000001: "[INIT]",
    0x00000002: "[WARN]",
    0x00000004: "[LOAD]",
    0x00000008: "[FS]",
    0x00000010: "[POOL]",
    0x00000020: "[PAGE]",
    0x00000040: "[INFO]",
    0x00000080: "[DISPATCH]",
    0x00000100: "[VARIABLE]",
    0x00000200: "[SMI]",
    0x00000400: "[BM]",
    0x00001000: "[BLKIO]",
    0x00004000: "[NET]",
    0x00010000: "[UNDI]",
    0x00020000: "[LOADFILE]",
    0x00080000: "[EVENT]",
    0x00100000: "[GCD]",
    0x00200000: "[CACHE]",
    0x00400000: "[VERBOSE]",
    0x00800000: "[MANAGEABILITY]",
    0x80000000: "[ERROR]",
}

ALM_SIGNATURES = (b"ALM2", b"ALMS")
ALMS_HEADER_MIN = 18
ALM2_HEADER_MIN = 24


def _phase_str(phase: int) -> str:
    """Return formatted phase string like '[PEI] ' or '' for unspecified."""
    if 0 < phase < len(_ALM_PHASE_STRINGS) and _ALM_PHASE_STRINGS[phase]:
        return _ALM_PHASE_STRINGS[phase] + " "
    return ""


def _level_str(debug_level: int) -> str:
    """Return formatted debug level string like '[INFO] ' or '' if unknown."""
    s = _ALM_DEBUG_LEVEL_STRINGS.get(debug_level, "")
    return (s + " ") if s else ""


def _make_timer_info_from_header(
    ticks_at_time: int,
    timer_frequency: int,
    year: int, month: int, day: int,
    hour: int, minute: int, second: int,
    nanosecond: int,
) -> Optional[dict]:
    """Build a timer_info dict from ADVLOG_FLASH_PERSISTENCE_HEADER fields.

    Returns None when TicksAtTime or TimerFrequency is 0 (pre-memory records).
    """
    if ticks_at_time == 0 or timer_frequency == 0:
        return None
    return {
        "frequency": timer_frequency,
        "ticks_at_time": ticks_at_time,
        "year": year, "month": month, "day": day,
        "hour": hour, "minute": minute, "second": second,
        "nanosecond": nanosecond,
    }


def _parse_alog_timer_info(data: bytes) -> Optional[dict]:
    """Extract TimerFrequency, TicksAtTime and EFI_TIME from ADVANCED_LOGGER_INFO V2+.

    ADVANCED_LOGGER_INFO V5/V6 layout (packed):
      offset  0: Signature (4)
      offset  4: Version   (2)
      offset  6: Reserved[3] (6)
      offset 12: LogBufferOffset (4)
      offset 16: Reserved4 (4)
      offset 20: LogCurrentOffset (4)
      offset 24: DiscardedSize (4)
      offset 28: LogBufferSize (4)
      offset 32: flags/booleans (5+3=8)
      offset 40: TimerFrequency (8)
      offset 48: TicksAtTime (8)
      offset 56: EFI_TIME Year(2),Month,Day,Hour,Min,Sec,Pad1,Nanosecond(4),TZ(2),DL,Pad2
    """
    if len(data) < 72 or data[:4] != b"ALOG":
        return None
    version = struct.unpack_from("<H", data, 4)[0]
    if version < 2:
        return None
    try:
        frequency = struct.unpack_from("<Q", data, 40)[0]
        ticks_at_time = struct.unpack_from("<Q", data, 48)[0]
        year, month, day, hour, minute, second = struct.unpack_from("<HBBBBBB", data, 56)[:6]
        nanosecond = struct.unpack_from("<I", data, 64)[0]
        if frequency == 0:
            return None
        return {
            "frequency": frequency,
            "ticks_at_time": ticks_at_time,
            "year": year, "month": month, "day": day,
            "hour": hour, "minute": minute, "second": second,
            "nanosecond": nanosecond,
        }
    except Exception:
        return None


def _ticks_to_time_str(tsc: int, timer_info: dict) -> str:
    """Convert a raw TSC counter value to HH:MM:SS.mmm string.

    Uses _Compute_Basetime approach from DecodeUefiLog.py:
      BaseTimeNs = (HH*3600 + MM*60 + SS) * 1e9 + Nanosecond
      BaseTimeTicks = BaseTimeNs * Frequency / 1e9
      EntryTimeNs = (TSC - TicksAtTime + BaseTimeTicks) * 1e9 / Frequency
    """
    frequency = timer_info.get("frequency", 0)
    if frequency == 0:
        return "??:??:??.???"
    ticks_at_time = timer_info.get("ticks_at_time", 0)
    base_ns = (
        (timer_info.get("hour", 0) * 3600
         + timer_info.get("minute", 0) * 60
         + timer_info.get("second", 0)) * 1_000_000_000
        + timer_info.get("nanosecond", 0)
    )
    delta_ticks = tsc - ticks_at_time
    # Use integer arithmetic to avoid float precision loss
    delta_ns = (delta_ticks * 1_000_000_000) // frequency
    total_ns = base_ns + delta_ns
    if total_ns < 0:
        total_ns = 0
    total_ms = total_ns // 1_000_000
    h = (total_ms // (3_600_000)) % 24
    m = (total_ms % 3_600_000) // 60_000
    s = (total_ms % 60_000) // 1_000
    ms = total_ms % 1_000
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _find_next_alm_signature(payload: bytes, start: int) -> Tuple[int, bytes]:
    next_off = len(payload)
    next_sig = b""

    for sig in ALM_SIGNATURES:
        idx = payload.find(sig, start)
        if idx != -1 and idx < next_off:
            next_off = idx
            next_sig = sig

    if next_sig:
        return next_off, next_sig

    return -1, b""


def decode_raw_alm_stream(payload: bytes, timer_info: Optional[dict] = None) -> Tuple[List[str], Dict[str, int]]:
    lines: List[str] = []
    stats: Dict[str, int] = {
        "records": 0,
        "alm2": 0,
        "alms": 0,
        "resyncs": 0,
        "errors": 0,
        "first_valid_offset": -1,
    }

    offset = 0

    pending_message = ""
    pending_prefix = ""

    _seen_alm2_versions: set = set()

    def _flush_pending() -> None:
        nonlocal pending_message, pending_prefix
        if pending_prefix and pending_message:
            lines.append(f"{pending_prefix}{pending_message}")
        pending_message = ""
        pending_prefix = ""

    def _append_message(prefix: str, msg_text: str) -> None:
        # DecodeUefiLog reconstructs logical log lines by concatenating
        # message fragments until a newline appears. Mirror that behavior
        # for raw ALM fallback output.
        nonlocal pending_message, pending_prefix

        if pending_prefix == "":
            pending_prefix = prefix
        pending_message += msg_text
        pending_prefix = prefix

        while True:
            newline_idx = pending_message.find("\n")
            if newline_idx == -1:
                break

            line_text = pending_message[:newline_idx]
            lines.append(f"{pending_prefix}{line_text}")
            pending_message = pending_message[newline_idx + 1:]

    while offset + 4 <= len(payload):
        signature = payload[offset:offset + 4]

        if signature == b"ALMS":
            # ALMS layout:
            #   UINT32 Signature
            #   UINT32 DebugLevel
            #   UINT64 TimeStamp
            #   UINT16 MessageLen
            #   CHAR8  MessageText[]
            if offset + ALMS_HEADER_MIN > len(payload):
                stats["errors"] += 1
                break

            _, debug_level, timestamp, msg_len = struct.unpack_from("<IIQH", payload, offset)
            msg_start = offset + ALMS_HEADER_MIN
            msg_end = msg_start + msg_len
            if msg_end > len(payload):
                stats["errors"] += 1
                next_offset, _ = _find_next_alm_signature(payload, offset + 1)
                if next_offset == -1:
                    break
                offset = next_offset
                stats["resyncs"] += 1
                continue

            msg_text = payload[msg_start:msg_end].decode("utf-8", "replace")
            time_s = _ticks_to_time_str(timestamp, timer_info) if timer_info else f"[TSC=0x{timestamp:016X}]"
            level_s = _level_str(debug_level)
            _append_message(
                f"{time_s} : {level_s}",
                msg_text,
            )
            if stats["first_valid_offset"] == -1:
                stats["first_valid_offset"] = offset
            stats["records"] += 1
            stats["alms"] += 1
            offset = _align8(msg_end)
            continue

        if signature == b"ALM2":
            # ALM2 layout:
            #   UINT32 Signature
            #   UINT8  MajorVersion
            #   UINT8  MinorVersion
            #   UINT32 DebugLevel
            #   UINT64 TimeStamp
            #   UINT16 Phase
            #   UINT16 MessageLen
            #   UINT16 MessageOffset
            #   CHAR8  MessageText[]
            if offset + ALM2_HEADER_MIN > len(payload):
                stats["errors"] += 1
                break

            major = payload[offset + 4]
            minor = payload[offset + 5]
            debug_level = struct.unpack_from("<I", payload, offset + 6)[0]
            timestamp = struct.unpack_from("<Q", payload, offset + 10)[0]
            phase = struct.unpack_from("<H", payload, offset + 18)[0]
            msg_len = struct.unpack_from("<H", payload, offset + 20)[0]
            msg_off = struct.unpack_from("<H", payload, offset + 22)[0]

            if msg_off < ALM2_HEADER_MIN:
                stats["errors"] += 1
                next_offset, _ = _find_next_alm_signature(payload, offset + 1)
                if next_offset == -1:
                    break
                offset = next_offset
                stats["resyncs"] += 1
                continue

            msg_start = offset + msg_off
            msg_end = msg_start + msg_len
            if msg_end > len(payload):
                stats["errors"] += 1
                next_offset, _ = _find_next_alm_signature(payload, offset + 1)
                if next_offset == -1:
                    break
                offset = next_offset
                stats["resyncs"] += 1
                continue

            msg_text = payload[msg_start:msg_end].decode("utf-8", "replace")
            ver_key = (major, minor)
            if ver_key not in _seen_alm2_versions:
                _seen_alm2_versions.add(ver_key)
                print(f"INFO: ALM2 version {major}.{minor}")
            time_s = _ticks_to_time_str(timestamp, timer_info) if timer_info else f"[TSC=0x{timestamp:016X}]"
            phase_s = _phase_str(phase)
            level_s = _level_str(debug_level)
            _append_message(
                f"{time_s} : {phase_s}{level_s}",
                msg_text,
            )
            if stats["first_valid_offset"] == -1:
                stats["first_valid_offset"] = offset
            stats["records"] += 1
            stats["alm2"] += 1
            offset = _align8(offset + msg_off + msg_len)
            continue

        # Unknown bytes at current offset; resynchronize to next ALM signature.
        next_offset, _ = _find_next_alm_signature(payload, offset + 1)
        if next_offset == -1:
            break
        offset = next_offset
        stats["resyncs"] += 1

    _flush_pending()

    return lines, stats


def detect_payload_format(payload: bytes) -> str:
    if len(payload) < 4:
        return "UNKNOWN"

    sig = payload[:4]
    if sig == b"ALOG":
        return "ALOG"
    if sig == b"ALM2":
        return "ALM2"
    if sig == b"ALMS":
        return "ALMS"
    return "UNKNOWN"


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_header(blob: bytes, offset: int) -> tuple:
    if offset + ADVLOG_HEADER_SIZE > len(blob):
        raise ValueError("ALGR header extends beyond selected region")

    # Returns 21-element tuple:
    # (sig, version, adl_info_ver, data_size, codec, notify_phase, ticks_at_time,
    #  timer_frequency, year, month, day, hour, minute, second, nanosecond, timezone, daylight,
    #  orig_data_size, crc32, r0, r1)
    return struct.unpack_from(ADVLOG_HEADER_STRUCT_FORMAT, blob, offset)


def parse_compress_algorithm(value: str) -> Tuple[int, str]:
    v = value.strip().lower()

    if v in ("advlogcompressnone", "none", "0"):
        return ADVLOG_COMPRESS_NONE, "none"
    if v in ("advlogcompresslz4", "lz4", "1"):
        return ADVLOG_COMPRESS_LZ4, "lz4"
    if v in ("advlogcompresslzma", "lzma", "2"):
        return ADVLOG_COMPRESS_LZMA, "lzma"

    raise argparse.ArgumentTypeError(
        "invalid algorithm. Use one of: "
        "AdvLogCompressNone|AdvLogCompressLz4|AdvLogCompressLzma or none|lz4|lzma or 0|1|2"
    )


def decompress_payload(payload: bytes, codec: str, original_data_size: int) -> bytes:
    if codec == "lzma":
        # LzmaUefiCompress emits an LZMA "alone" stream with 13-byte header.
        return lzma.decompress(payload, format=lzma.FORMAT_ALONE)

    if codec == "lz4":
        try:
            import lz4.block  # type: ignore[import-not-found]
            import lz4.frame  # type: ignore[import-not-found]
        except ImportError as ex:
            raise RuntimeError(
                "LZ4 codec selected but Python package 'lz4' is not available. "
                "Install it with: pip install lz4"
            ) from ex

        # Try block API first (common for firmware payloads), then frame API.
        try:
            if original_data_size > 0:
                return lz4.block.decompress(payload, uncompressed_size=original_data_size)
            return lz4.block.decompress(payload)
        except Exception:
            return lz4.frame.decompress(payload)

    raise RuntimeError(f"Unsupported codec: {codec}")


def _other_codec(codec: str) -> str:
    if codec == "lzma":
        return "lz4"
    if codec == "lz4":
        return "lzma"
    return ""


def codec_for_algorithm(algorithm: int) -> str:
    if algorithm == ADVLOG_COMPRESS_NONE:
        return "none"
    if algorithm == ADVLOG_COMPRESS_LZ4:
        return "lz4"
    if algorithm == ADVLOG_COMPRESS_LZMA:
        return "lzma"
    return ""


def header_algorithm_from_codec(codec: int) -> Tuple[Optional[int], bool]:
    # Codec is ADVLOG_COMPRESS_ALGORITHM stored directly in the header Codec field.
    if codec not in (ADVLOG_COMPRESS_NONE, ADVLOG_COMPRESS_LZ4, ADVLOG_COMPRESS_LZMA):
        raise ValueError(f"unsupported Codec value in header: 0x{codec:04X}")
    return codec, (codec != ADVLOG_COMPRESS_NONE)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract persisted AdvLog from BIOS dump using ALGR header at a given SPI offset, "
            "then decode to text log."
        )
    )
    parser.add_argument("dump_file", nargs="?",
                        help="(Legacy) Path to BIOS dump binary. Prefer -i/--input.")
    parser.add_argument("-i", "--input", dest="input_file",
                        help="Path to BIOS dump binary (e.g. dump_bios0_run_vincent_32MB_FD_SMM.bin)")
    parser.add_argument("-s", "--start", required=True, type=parse_int, help="Start offset of ADVLOG region (e.g. 0x01000000)")
    parser.add_argument("-o", "--output", required=True, help="Output decoded text log path")
    parser.add_argument(
        "-c", "--codec", required=False, type=parse_compress_algorithm,
        metavar="ALGORITHM",
        help=(
            "Compression algorithm hint/override. "
            "Accepts AdvLogCompressNone|AdvLogCompressLz4|AdvLogCompressLzma, "
            "or none|lz4|lzma, or 0|1|2. "
            "Normally inferred from header Flags field."
        )
    )

    args = parser.parse_args()

    input_file = args.input_file if args.input_file else args.dump_file
    if not input_file:
        print("ERROR: input dump file is required. Use -i/--input (or legacy positional dump_file).")
        return 2

    dump_path = os.path.abspath(input_file)
    output_log_path = os.path.abspath(args.output)
    start_offset = args.start
    hint_algorithm: Optional[int] = None
    hint_codec: Optional[str] = None
    if args.codec is not None:
        hint_algorithm, hint_codec = args.codec

    if start_offset < 0:
        print("ERROR: start offset must be >= 0")
        return 2

    if not os.path.isfile(dump_path):
        print(f"ERROR: dump file not found: {dump_path}")
        return 2

    with open(dump_path, "rb") as fd:
        fd.seek(0, os.SEEK_END)
        file_size = fd.tell()
        if start_offset >= file_size:
            print(f"ERROR: start offset 0x{start_offset:X} is beyond file size 0x{file_size:X}")
            return 2

        # Prefer exact header-at-start parsing; if not present, do a bounded scan.
        fd.seek(start_offset)
        header_probe = fd.read(ADVLOG_HEADER_SIZE)

        sig_abs = -1
        if len(header_probe) >= ADVLOG_HEADER_SIZE and header_probe[:4] == ADVLOG_SIG_BYTES:
            sig_abs = start_offset
            header_blob = header_probe
        else:
            scan_size = min(ADVLOG_SIGNATURE_SEARCH_WINDOW, file_size - start_offset)
            fd.seek(start_offset)
            scan_blob = fd.read(scan_size)
            sig_rel = scan_blob.find(ADVLOG_SIG_BYTES)
            if sig_rel < 0:
                print(
                    "ERROR: ALGR signature not found in selected search window "
                    f"(0x{scan_size:X} bytes)"
                )
                return 1

            sig_abs = start_offset + sig_rel
            if sig_abs + ADVLOG_HEADER_SIZE > file_size:
                print("ERROR: ALGR header extends beyond end of file")
                return 1

            fd.seek(sig_abs)
            header_blob = fd.read(ADVLOG_HEADER_SIZE)

    if len(header_blob) < ADVLOG_HEADER_SIZE:
        print("ERROR: not enough data to contain ALGR header")
        return 2

    (signature, version, adl_info_ver, data_size, codec, notify_phase, ticks_at_time,
     timer_frequency,
     adl_year, adl_month, adl_day, adl_hour, adl_minute, adl_second,
     adl_nanosecond, adl_timezone, adl_daylight,
     original_data_size, crc32_expected, *_) = parse_header(header_blob, 0)

    notify_phase_str = (
        _ADVLOG_NOTIFY_PHASE_STRINGS[notify_phase]
        if notify_phase < len(_ADVLOG_NOTIFY_PHASE_STRINGS)
        else f"[0x{notify_phase:04X}]"
    )
    adl_time_str = f"{adl_hour:02d}:{adl_minute:02d}:{adl_second:02d}"

    print(
        "DEBUG: Parsed ADVLOG_FLASH_PERSISTENCE_HEADER "
        f"(size=0x{ADVLOG_HEADER_SIZE:X}) DataSize=0x{data_size:X}"
    )

    if signature != ADVLOG_SIG_U32:
        print(f"ERROR: signature mismatch: 0x{signature:08X}")
        return 1

    if version != ADVLOG_SPI_DUMP_PYTHON_VERSION:
        print(
            "ERROR: ADVLOG_FLASH_PERSISTENCE_VERSION mismatch: "
            f"header=0x{version:08X}, "
            f"script=0x{ADVLOG_SPI_DUMP_PYTHON_VERSION:08X}. "
            "ADVLOG_FLASH_PERSISTENCE_HEADER may have changed; "
            "update ExtractAdvLogFromSpiDump.py before parsing this data."
        )
        return 1

    payload_abs = sig_abs + ADVLOG_HEADER_SIZE
    payload_end = payload_abs + data_size
    print(
        "DEBUG: Payload range from header/DataSize: "
        f"[0x{payload_abs:X}, 0x{payload_end:X})"
    )
    if payload_end > file_size:
        print(
            "ERROR: payload exceeds dump file bounds: "
            f"payload_end=0x{payload_end:X}, file_size=0x{file_size:X}"
        )
        return 1

    with open(dump_path, "rb") as fd:
        fd.seek(payload_abs)
        payload = fd.read(data_size)

    if len(payload) != data_size:
        print(
            "ERROR: short payload read from dump: "
            f"expected=0x{data_size:X}, got=0x{len(payload):X}"
        )
        return 1

    try:
        header_algorithm, is_compressed = header_algorithm_from_codec(codec)
    except ValueError as ex:
        print(f"ERROR: {ex}")
        return 1

    effective_algorithm: Optional[int] = header_algorithm
    if hint_algorithm is not None and header_algorithm is not None and hint_algorithm != header_algorithm:
        print(
                "WARNING: -c hint does not match header Codec algorithm; "
        )
    if not is_compressed:
        if hint_algorithm is not None and hint_algorithm != ADVLOG_COMPRESS_NONE:
            print("WARNING: payload is not flagged compressed; selected algorithm hint is ignored for this record")
        raw_log = payload
        effective_algorithm = ADVLOG_COMPRESS_NONE
    else:
        codecs_to_try: List[str] = []

        if effective_algorithm is not None and effective_algorithm != ADVLOG_COMPRESS_NONE:
            codec_from_header = codec_for_algorithm(effective_algorithm)
            if codec_from_header:
                codecs_to_try.append(codec_from_header)

        # For v1 legacy compressed records or explicit user hint, allow hint-first probing.
        if hint_codec and hint_codec not in codecs_to_try and hint_codec != "none":
            codecs_to_try.insert(0, hint_codec)

        # Ensure both known codecs are available as fallback probes.
        for candidate in ("lz4", "lzma"):
            if candidate not in codecs_to_try:
                codecs_to_try.append(candidate)

        raw_log = b""
        decode_errors: List[str] = []
        for candidate_codec in codecs_to_try:
            try:
                raw_try = decompress_payload(payload, candidate_codec, original_data_size)
            except Exception as ex:
                decode_errors.append(f"{candidate_codec}: {ex}")
                continue

            if detect_payload_format(raw_try) != "UNKNOWN":
                raw_log = raw_try
                effective_algorithm = ADVLOG_COMPRESS_LZ4 if candidate_codec == "lz4" else ADVLOG_COMPRESS_LZMA
                break

            decode_errors.append(f"{candidate_codec}: decompressed stream not recognized")

        if not raw_log:
            print("ERROR: Unable to decompress payload with recognized AdvLogger stream.")
            for err in decode_errors:
                print(f"  - {err}")
            return 1

    payload_format = detect_payload_format(raw_log)

    # Guard against parsing wrong data when an incorrect codec was selected.
    if payload_format == "UNKNOWN":
        if is_compressed:
            seed_codec = codec_for_algorithm(effective_algorithm) if effective_algorithm is not None else ""
            alt_codec = _other_codec(seed_codec)
            alt_format = "UNKNOWN"
            if alt_codec:
                try:
                    alt_raw = decompress_payload(payload, alt_codec, original_data_size)
                    alt_format = detect_payload_format(alt_raw)
                except Exception:
                    alt_format = "UNKNOWN"

            if alt_format != "UNKNOWN":
                print(
                    "ERROR: Decompressed payload is not a recognized AdvLogger stream "
                    f"with selected codec path, but alternate codec ({alt_codec}) produced {alt_format}."
                )
            else:
                print(
                    "ERROR: Decompressed payload is not a recognized AdvLogger stream. "
                    "Check -s offset, dump integrity, and -c codec selection."
                )
        else:
            print(
                "ERROR: Uncompressed payload is not a recognized AdvLogger stream. "
                "Check -s offset and dump integrity."
            )

        return 1

    crc32_actual = binascii.crc32(raw_log) & 0xFFFFFFFF
    if crc32_actual != crc32_expected:
        print(
            "WARNING: CRC32 mismatch for uncompressed payload: "
            f"expected=0x{crc32_expected:08X}, actual=0x{crc32_actual:08X}"
        )

    if original_data_size != 0 and original_data_size != len(raw_log):
        print(
            "WARNING: OriginalDataSize mismatch: "
            f"header=0x{original_data_size:X}, actual=0x{len(raw_log):X}"
        )

    decode_script = os.path.join(os.path.dirname(__file__), "DecodeUefiLog", "DecodeUefiLog.py")
    if not os.path.isfile(decode_script):
        print(f"ERROR: DecodeUefiLog script not found: {decode_script}")
        return 1

    output_dir = os.path.dirname(output_log_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    print(f"Found ALGR at absolute offset 0x{sig_abs:X}")
    codec_name = {ADVLOG_COMPRESS_NONE: "none", ADVLOG_COMPRESS_LZ4: "lz4", ADVLOG_COMPRESS_LZMA: "lzma"}.get(codec, f"0x{codec:04X}")
    print(
        "Header: "
        f"Version=0x{version:04X}, AdvLogInfoVersion=0x{adl_info_ver:04X}, DataSize=0x{data_size:X}, "
        f"Codec={codec_name}, NotifyPhase={notify_phase_str}, "
        f"AdvLogInfoTime={adl_time_str}, OriginalDataSize=0x{original_data_size:X}, "
        f"TicksAtTime=0x{ticks_at_time:016X}, TimerFrequency={timer_frequency}"
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(raw_log)
        temp_path = tmp.name

    try:
        decode_failed = True

        if payload_format == "ALOG":
            cmd = [
                sys.executable,
                decode_script,
                "-l", temp_path,
                "-o", output_log_path,
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                print(result.stdout.strip())
            if result.stderr:
                print(result.stderr.strip())

            # DecodeUefiLog.py can print an internal exception but still return 0.
            decode_failed = (
                (result.returncode != 0) or
                ("Error processing log output." in (result.stdout or ""))
            )
        else:
            print(
                "Payload format is "
                f"{payload_format}; skipping DecodeUefiLog (expects ALOG header), "
                "using raw ALM2/ALMS fallback decode."
            )

        if decode_failed:
            if payload_format == "ALOG":
                print("DecodeUefiLog path failed, trying raw ALM2/ALMS fallback decode.")
            header_timer_info = _make_timer_info_from_header(
                ticks_at_time, timer_frequency,
                adl_year, adl_month, adl_day,
                adl_hour, adl_minute, adl_second, adl_nanosecond,
            )
            fallback_lines, fallback_stats = decode_raw_alm_stream(
                raw_log, timer_info=_parse_alog_timer_info(raw_log) or header_timer_info
            )
            if not fallback_lines:
                print("ERROR: Fallback decode also failed; payload is not recognizable ALM2/ALMS stream.")
                if fallback_stats["errors"]:
                    print(
                        "Fallback parse diagnostics: "
                        f"errors={fallback_stats['errors']}, resyncs={fallback_stats['resyncs']}, "
                        f"first_valid_offset={fallback_stats['first_valid_offset']}"
                    )
                return 1

            print(
                "Fallback parse summary: "
                f"records={fallback_stats['records']} "
                f"(ALM2={fallback_stats['alm2']}, ALMS={fallback_stats['alms']}), "
                f"resyncs={fallback_stats['resyncs']}, first_valid_offset={fallback_stats['first_valid_offset']}"
            )

            with open(output_log_path, "w", encoding="utf-8", newline="\n") as out_fd:
                out_fd.write(f"Log from  {adl_month}/{adl_day}/{adl_year} at {adl_time_str}\n\n")
                for line in fallback_lines:
                    out_fd.write(line.rstrip("\r\n") + "\n")

    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass

    print(f"Decoded log written to: {output_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
