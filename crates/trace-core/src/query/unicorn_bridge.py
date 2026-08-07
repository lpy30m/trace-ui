#!/usr/bin/env python3
# Trace UI exact-seed Unicorn / OLLVM concrete replay bridge.
# Generated from trace-ui/unicorn-ollvm-v1. Run manually in an isolated Python environment.
import argparse
import hashlib
import json
import os
import re
import sys
import time

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from elftools.elf.elffile import ELFFile
    import unicorn
    from unicorn import (
        Uc,
        UcError,
        UC_ARCH_ARM64,
        UC_MODE_ARM,
        UC_PROT_READ,
        UC_PROT_WRITE,
        UC_PROT_EXEC,
        UC_HOOK_BLOCK,
        UC_HOOK_CODE,
        UC_HOOK_INSN_INVALID,
        UC_HOOK_MEM_READ,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_READ_UNMAPPED,
        UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
        UC_MEM_READ_UNMAPPED,
        UC_MEM_WRITE_UNMAPPED,
        UC_MEM_FETCH_UNMAPPED,
    )
    from unicorn import arm64_const
except ImportError:
    sys.stderr.write(
        "Trace UI Unicorn replay requires unicorn, capstone, and pyelftools. "
        "Install them in an isolated environment and rerun this script.\n"
    )
    raise


SCHEMA = "trace-ui/unicorn-ollvm-v1"
REPORT = json.loads(__REPORT_JSON__)
SEEDS = json.loads(__SEEDS_JSON__)
EXPECTED_BINARY_IDENTITY = json.loads(__EXPECTED_BINARY_IDENTITY__)
CONFIG = json.loads(__CONFIG_JSON__)
PAGE_SIZE = 0x1000
MAX_MISSING_RECORDS = 64
MAX_BLOCK_RECORDS = 100000


def _align_down(value):
    return value & ~(PAGE_SIZE - 1)


def _align_up(value):
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _parse_hex(value):
    if isinstance(value, int):
        return value
    return int(str(value), 16)


def _hex(value):
    return hex(int(value) & 0xFFFFFFFFFFFFFFFF)


def _register_ids():
    result = {}
    for index in range(29):
        result["x{}".format(index)] = getattr(arm64_const, "UC_ARM64_REG_X{}".format(index))
    result.update({
        "x29": arm64_const.UC_ARM64_REG_X29,
        "x30": arm64_const.UC_ARM64_REG_X30,
        "sp": arm64_const.UC_ARM64_REG_SP,
        "pc": arm64_const.UC_ARM64_REG_PC,
        "nzcv": arm64_const.UC_ARM64_REG_NZCV,
    })
    return result


REGISTER_IDS = _register_ids()


def _normalize_register(name):
    value = (name or "").lower()
    if value in ("xzr", "wzr", "zr"):
        return None
    if value == "fp":
        return "x29"
    if value == "lr":
        return "x30"
    if value == "wsp":
        return "sp"
    match = re.fullmatch(r"w([0-9]|[12][0-9]|30)", value)
    if match:
        return "x{}".format(match.group(1))
    match = re.fullmatch(r"[vqdsbh]([0-9]|[12][0-9]|3[01])", value)
    if match:
        return "v{}".format(match.group(1))
    return value


def _is_vector_register(name):
    return bool(re.fullmatch(r"v([0-9]|[12][0-9]|3[01])", name or ""))


def _permission(flags):
    result = 0
    if flags & 4:
        result |= UC_PROT_READ
    if flags & 2:
        result |= UC_PROT_WRITE
    if flags & 1:
        result |= UC_PROT_EXEC
    return result or UC_PROT_READ


def _module_offset(layout, address):
    if layout["moduleBase"] <= address < layout["moduleBase"] + layout["moduleSize"]:
        return _hex(address - layout["moduleBase"])
    return None


def _range_contains(ranges, address, size):
    end = address + max(int(size), 1)
    cursor = address
    while cursor < end:
        next_end = cursor
        for start, stop, _kind in ranges:
            if start <= cursor < stop:
                next_end = max(next_end, stop)
        if next_end == cursor:
            return False
        cursor = min(next_end, end)
    return True


def _range_kind(ranges, address):
    kinds = [kind for start, stop, kind in ranges if start <= address < stop]
    return kinds[-1] if kinds else None


def _map_page_runs(uc, page_permissions, mapped_pages):
    pages = sorted(page_permissions)
    index = 0
    while index < len(pages):
        start = pages[index]
        permissions = page_permissions[start]
        end = start + PAGE_SIZE
        index += 1
        while index < len(pages) and pages[index] == end and page_permissions[pages[index]] == permissions:
            end += PAGE_SIZE
            index += 1
        uc.mem_map(start, end - start, permissions)
        for page in range(start, end, PAGE_SIZE):
            mapped_pages.add(page)


def _ensure_mapped(uc, mapped_pages, address, size, permissions=UC_PROT_READ | UC_PROT_WRITE):
    start = _align_down(address)
    end = _align_up(address + max(int(size), 1))
    for page in range(start, end, PAGE_SIZE):
        if page not in mapped_pages:
            uc.mem_map(page, PAGE_SIZE, permissions)
            mapped_pages.add(page)


def _load_elf(uc, binary_path, requested_module_base):
    with open(binary_path, "rb") as source:
        elf = ELFFile(source)
        if elf.get_machine_arch().lower() not in ("aarch64", "arm64"):
            raise RuntimeError("Unicorn replay requires an AArch64 ELF, got {}".format(elf.get_machine_arch()))
        segments = []
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            segments.append({
                "vaddr": int(segment["p_vaddr"]),
                "fileSize": int(segment["p_filesz"]),
                "memorySize": int(segment["p_memsz"]),
                "flags": int(segment["p_flags"]),
                "data": segment.data(),
            })
    if not segments:
        raise RuntimeError("ELF has no PT_LOAD segments")
    minimum_vaddr = min(_align_down(segment["vaddr"]) for segment in segments)
    maximum_vaddr = max(_align_up(segment["vaddr"] + segment["memorySize"]) for segment in segments)
    module_base = requested_module_base if requested_module_base is not None else 0x40000000
    module_size = maximum_vaddr - minimum_vaddr
    page_permissions = {}
    for segment in segments:
        mapped = module_base + (segment["vaddr"] - minimum_vaddr)
        start = _align_down(mapped)
        end = _align_up(mapped + segment["memorySize"])
        permissions = _permission(segment["flags"])
        for page in range(start, end, PAGE_SIZE):
            page_permissions[page] = page_permissions.get(page, 0) | permissions
    mapped_pages = set()
    _map_page_runs(uc, page_permissions, mapped_pages)
    valid_ranges = []
    executable_ranges = []
    writable_static_ranges = []
    for segment in segments:
        mapped = module_base + (segment["vaddr"] - minimum_vaddr)
        if segment["data"]:
            uc.mem_write(mapped, segment["data"])
        if segment["flags"] & 1:
            executable_ranges.append((mapped, mapped + segment["memorySize"]))
        if segment["flags"] & 2:
            if segment["fileSize"]:
                writable_static_ranges.append((mapped, mapped + segment["fileSize"]))
        elif segment["fileSize"]:
            valid_ranges.append((mapped, mapped + segment["fileSize"], "elf-static"))
    return {
        "moduleBase": module_base,
        "moduleSize": module_size,
        "minimumVaddr": minimum_vaddr,
        "mappedPages": mapped_pages,
        "validRanges": valid_ranges,
        "executableRanges": executable_ranges,
        "writableStaticRanges": writable_static_ranges,
    }


def _is_executable(layout, address):
    return any(start <= address < end for start, end in layout["executableRanges"])


def _rebase_seed_value(value, seed, layout):
    source_base = seed.get("moduleBase")
    source_size = int(seed.get("moduleSize") or 0)
    if source_base and source_size > 0:
        source_base = _parse_hex(source_base)
        if source_base <= value < source_base + source_size:
            return layout["moduleBase"] + (value - source_base)
    return value


def _apply_seed(uc, seed, layout):
    valid_registers = {"pc"}
    for register in seed.get("registers", []):
        name = _normalize_register(register.get("name"))
        if name not in REGISTER_IDS:
            continue
        value = _parse_hex(register["value"])
        if name not in ("nzcv",):
            value = _rebase_seed_value(value, seed, layout)
        uc.reg_write(REGISTER_IDS[name], value)
        valid_registers.add(name)
    for region in seed.get("memoryRegions", []):
        address = _rebase_seed_value(_parse_hex(region["address"]), seed, layout)
        data = bytes.fromhex(region["bytesHex"])
        if not data:
            continue
        _ensure_mapped(uc, layout["mappedPages"], address, len(data))
        uc.mem_write(address, data)
        layout["validRanges"].append((address, address + len(data), "frida-capture"))
    return valid_registers


def _read_registers(uc):
    result = {}
    for name, register_id in REGISTER_IDS.items():
        if name == "pc":
            continue
        try:
            result[name.upper()] = _hex(uc.reg_read(register_id))
        except UcError:
            pass
    return result


def _register_changes(before, after):
    changes = []
    for name in sorted(set(before) | set(after)):
        if before.get(name) != after.get(name):
            changes.append({"register": name, "before": before.get(name, "unavailable"), "after": after.get(name, "unavailable")})
    return changes


def _dispatcher_candidates():
    return {candidate["startOffset"].lower(): candidate for candidate in REPORT.get("dispatcherCandidates", [])}


def _seed_kind(seed):
    provenance = seed.get("provenance") or {}
    offset = seed.get("captureOffset", "").lower()
    if offset in [value.lower() for value in provenance.get("matchedDispatcherOffsets", [])]:
        return "frida-capture-exact-dispatcher"
    if offset in [value.lower() for value in provenance.get("matchedBranchOffsets", [])]:
        for candidate in REPORT.get("opaqueBranchCandidates", []):
            if candidate["branchOffset"].lower() == offset:
                return "frida-capture-exact-branch"
        return "frida-capture-exact-condition-source"
    return "frida-capture-exact-offset"


def _state_values(uc, register_names):
    values = []
    for original in register_names[:16]:
        name = _normalize_register(original)
        if name not in REGISTER_IDS:
            values.append({"register": original.upper(), "status": "unavailable", "value": None})
            continue
        try:
            values.append({"register": original.upper(), "status": "concrete", "value": _hex(uc.reg_read(REGISTER_IDS[name]))})
        except UcError:
            values.append({"register": original.upper(), "status": "unavailable", "value": None})
    return values


def _memory_operand_hint(instruction):
    if instruction is None:
        return None, None
    match = re.search(r"\[(x(?:[12][0-9]|30|[0-9])|sp)(?:,\s*#?(-?(?:0x[0-9a-f]+|[0-9]+)))?", instruction.op_str.lower())
    if not match:
        return None, None
    base = match.group(1).upper()
    displacement = match.group(2)
    if displacement is None:
        return base, "0x0"
    try:
        parsed = int(displacement, 0)
        return base, "-0x{:x}".format(-parsed) if parsed < 0 else "0x{:x}".format(parsed)
    except ValueError:
        return base, displacement


def _instruction_text(instruction):
    if instruction is None:
        return None
    return "{} {}".format(instruction.mnemonic, instruction.op_str).strip()


def _call_target(uc, instruction, layout):
    if instruction is None:
        return None, None
    operand = instruction.op_str.strip().lower().lstrip("#")
    target = None
    if instruction.mnemonic == "bl":
        try:
            target = int(operand, 0)
        except ValueError:
            target = None
    elif instruction.mnemonic == "blr":
        name = _normalize_register(operand)
        if name in REGISTER_IDS:
            try:
                target = uc.reg_read(REGISTER_IDS[name])
            except UcError:
                target = None
    return (_hex(target) if target is not None else None, _module_offset(layout, target) if target is not None else None)


def _run_seed(binary_path, seed):
    requested_base = _parse_hex(seed["moduleBase"]) if seed.get("moduleBase") else None
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    layout = _load_elf(uc, binary_path, requested_base)
    valid_registers = _apply_seed(uc, seed, layout)
    start_offset = seed["captureOffset"].lower()
    start_address = layout["moduleBase"] + _parse_hex(start_offset)
    uc.reg_write(REGISTER_IDS["pc"], start_address)
    before_registers = _read_registers(uc)
    dispatchers = _dispatcher_candidates()
    source_candidate = dispatchers.get(start_offset)
    source_state_values = _state_values(uc, source_candidate.get("stateRegisters", [])) if source_candidate else []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True
    state = {
        "startTime": time.monotonic(),
        "stopReason": None,
        "error": None,
        "instructionCount": 0,
        "executedOffsets": [],
        "executedOffsetsTruncated": False,
        "blockOffsets": [],
        "blockOffsetsTruncated": False,
        "memoryWrites": [],
        "memoryWritesTruncated": False,
        "writeKeys": set(),
        "callBoundaries": [],
        "missingMemory": [],
        "warnings": [],
        "visits": {},
        "currentInstruction": None,
        "currentPcOffset": start_offset,
        "matchedDispatcherOffset": None,
        "validRegisters": valid_registers,
        "validVectors": set(),
        "syntheticWritePages": set(),
    }

    def request_stop(reason, error=None):
        if state["stopReason"] is None:
            state["stopReason"] = reason
            state["error"] = error
            uc.emu_stop()

    def add_missing(access, address, size):
        if len(state["missingMemory"]) >= MAX_MISSING_RECORDS:
            return
        base_register, displacement = _memory_operand_hint(state["currentInstruction"])
        state["missingMemory"].append({
            "access": access,
            "address": _hex(address),
            "size": int(size),
            "pcOffset": state["currentPcOffset"],
            "instruction": _instruction_text(state["currentInstruction"]),
            "baseRegister": base_register,
            "displacement": displacement,
        })

    def record_write(address, size, value):
        key = (state["currentPcOffset"], int(address), int(size), int(value))
        if key in state["writeKeys"]:
            return
        state["writeKeys"].add(key)
        layout["validRanges"].append((address, address + max(int(size), 1), "replay-write"))
        if len(state["memoryWrites"]) >= int(CONFIG["maxMemoryWrites"]):
            state["memoryWritesTruncated"] = True
            return
        value_hex = None
        if 0 < size <= 32:
            mask = (1 << (size * 8)) - 1
            value_hex = (int(value) & mask).to_bytes(size, "little").hex()
        state["memoryWrites"].append({
            "address": _hex(address),
            "offset": _module_offset(layout, address),
            "size": int(size),
            "valueHex": value_hex,
            "pcOffset": state["currentPcOffset"],
        })

    def on_block(_uc, address, _size, _user_data):
        offset = _module_offset(layout, address)
        if offset is None:
            return
        if len(state["blockOffsets"]) < MAX_BLOCK_RECORDS:
            state["blockOffsets"].append(offset)
        else:
            state["blockOffsetsTruncated"] = True

    def on_code(_uc, address, size, _user_data):
        offset = _module_offset(layout, address)
        state["currentPcOffset"] = offset
        if offset is None or not _is_executable(layout, address):
            request_stop("outside-executable")
            return
        if state["instructionCount"] > 0 and offset in dispatchers and offset != start_offset:
            state["matchedDispatcherOffset"] = offset
            request_stop("next-dispatcher")
            return
        visits = state["visits"].get(offset, 0) + 1
        state["visits"][offset] = visits
        if visits > int(CONFIG["loopVisitLimit"]):
            request_stop("loop-detected")
            return
        if state["instructionCount"] >= int(CONFIG["maxInstructions"]):
            request_stop("instruction-limit")
            return
        elapsed_ms = (time.monotonic() - state["startTime"]) * 1000.0
        if elapsed_ms >= int(CONFIG["timeoutMs"]):
            request_stop("timeout")
            return
        try:
            raw = bytes(_uc.mem_read(address, size))
            instruction = next(md.disasm(raw, address, count=1), None)
        except Exception as error:
            request_stop("invalid-instruction", str(error))
            return
        if instruction is None:
            request_stop("invalid-instruction", "Capstone could not decode the instruction")
            return
        state["currentInstruction"] = instruction
        state["instructionCount"] += 1
        if len(state["executedOffsets"]) < int(CONFIG["maxRecordedOffsets"]):
            state["executedOffsets"].append(offset)
        else:
            state["executedOffsetsTruncated"] = True
        if instruction.mnemonic in ("mrs", "msr") and "nzcv" not in instruction.op_str.lower():
            request_stop("unsupported-system-state", _instruction_text(instruction))
            return
        try:
            read_ids, write_ids = instruction.regs_access()
            read_names = [_normalize_register(md.reg_name(register_id)) for register_id in read_ids]
            write_names = [_normalize_register(md.reg_name(register_id)) for register_id in write_ids]
        except Exception:
            read_names = []
            write_names = []
        for name in read_names:
            if name is None or name == "pc":
                continue
            if _is_vector_register(name):
                if name not in state["validVectors"]:
                    request_stop("unsupported-simd-state", "uncaptured {} read by {}".format(name.upper(), _instruction_text(instruction)))
                    return
            elif name in REGISTER_IDS and name not in state["validRegisters"]:
                request_stop("missing-register", "uncaptured {} read by {}".format(name.upper(), _instruction_text(instruction)))
                return
        for name in write_names:
            if name is None:
                continue
            if _is_vector_register(name):
                state["validVectors"].add(name)
            elif name in REGISTER_IDS:
                state["validRegisters"].add(name)
        if instruction.mnemonic == "ret":
            request_stop("return")
            return
        if bool(CONFIG["stopOnCall"]) and instruction.mnemonic in ("bl", "blr"):
            target_address, target_offset = _call_target(_uc, instruction, layout)
            return_address = address + size
            state["callBoundaries"].append({
                "pcOffset": offset,
                "mnemonic": _instruction_text(instruction),
                "targetAddress": target_address,
                "targetOffset": target_offset,
                "returnAddress": _hex(return_address),
                "returnOffset": _module_offset(layout, return_address),
            })
            request_stop("call-boundary")

    def on_read(_uc, _access, address, size, _value, _user_data):
        if _range_contains(layout["validRanges"], address, size):
            return
        kind = _range_kind(layout["validRanges"], address)
        add_missing("read" if kind is None else "partial-read", address, size)
        request_stop("missing-memory")

    def on_write(_uc, _access, address, size, value, _user_data):
        record_write(address, size, value)

    def on_unmapped(_uc, access, address, size, value, _user_data):
        if access == UC_MEM_WRITE_UNMAPPED:
            try:
                _ensure_mapped(_uc, layout["mappedPages"], address, size)
                state["syntheticWritePages"].add(_align_down(address))
                record_write(address, size, value)
                return True
            except UcError as error:
                request_stop("emulation-error", str(error))
                return False
        if access == UC_MEM_FETCH_UNMAPPED:
            request_stop(
                "outside-executable",
                "instruction fetch left the mapped executable image at {}".format(_hex(address)),
            )
            return False
        add_missing("read", address, size)
        request_stop("missing-memory")
        return False

    def on_invalid(_uc, _user_data):
        request_stop("invalid-instruction")
        return False

    uc.hook_add(UC_HOOK_BLOCK, on_block)
    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped)
    uc.hook_add(UC_HOOK_INSN_INVALID, on_invalid)
    try:
        uc.emu_start(
            start_address,
            0,
            timeout=int(CONFIG["timeoutMs"]) * 1000,
            count=int(CONFIG["maxInstructions"]) + 1,
        )
    except UcError as error:
        if state["stopReason"] is None:
            state["stopReason"] = "emulation-error"
            state["error"] = str(error)
    elapsed_ms = int((time.monotonic() - state["startTime"]) * 1000.0)
    if state["stopReason"] is None:
        if state["instructionCount"] >= int(CONFIG["maxInstructions"]):
            state["stopReason"] = "instruction-limit"
        elif elapsed_ms >= int(CONFIG["timeoutMs"]):
            state["stopReason"] = "timeout"
        else:
            state["stopReason"] = "completed"
    terminal_address = uc.reg_read(REGISTER_IDS["pc"])
    after_registers = _read_registers(uc)
    target_candidate = dispatchers.get(state["matchedDispatcherOffset"] or "")
    target_state_values = _state_values(uc, target_candidate.get("stateRegisters", [])) if target_candidate else []
    if state["syntheticWritePages"]:
        state["warnings"].append(
            "{} previously unmapped page(s) were created only because replay wrote them before reading; untouched bytes remain invalid.".format(
                len(state["syntheticWritePages"])
            )
        )
    if layout["writableStaticRanges"]:
        state["warnings"].append(
            "Writable ELF segment bytes are mapped but not trusted as runtime state unless Frida captured or replay wrote them."
        )
    return {
        "sourceEventIndex": int(seed["sourceEventIndex"]),
        "seedKind": _seed_kind(seed),
        "startOffset": start_offset,
        "mappedBase": _hex(layout["moduleBase"]),
        "stopReason": state["stopReason"],
        "instructionCount": int(state["instructionCount"]),
        "elapsedMs": elapsed_ms,
        "terminalAddress": _hex(terminal_address),
        "terminalOffset": _module_offset(layout, terminal_address),
        "matchedDispatcherOffset": state["matchedDispatcherOffset"],
        "sourceStateValues": source_state_values,
        "targetStateValues": target_state_values,
        "executedOffsets": state["executedOffsets"],
        "executedOffsetsTruncated": state["executedOffsetsTruncated"],
        "blockOffsets": state["blockOffsets"],
        "blockOffsetsTruncated": state["blockOffsetsTruncated"],
        "registerChanges": _register_changes(before_registers, after_registers),
        "memoryWrites": state["memoryWrites"],
        "memoryWritesTruncated": state["memoryWritesTruncated"],
        "callBoundaries": state["callBoundaries"],
        "missingMemory": state["missingMemory"],
        "warnings": state["warnings"],
        "error": state["error"],
    }


def _state_signature(values):
    parts = []
    for value in values:
        parts.append("{}={}".format(value.get("register"), value.get("value") or value.get("status")))
    return ", ".join(parts) if parts else "no-state-register"


def _transition_matrix(runs):
    grouped = {}
    for run in runs:
        if run.get("seedKind") != "frida-capture-exact-dispatcher" or not run.get("matchedDispatcherOffset"):
            continue
        key = (
            run["startOffset"],
            _state_signature(run.get("sourceStateValues", [])),
            run["matchedDispatcherOffset"],
            _state_signature(run.get("targetStateValues", [])),
            run["stopReason"],
        )
        grouped.setdefault(key, []).append(run["sourceEventIndex"])
    result = []
    for key, event_indices in grouped.items():
        result.append({
            "sourceOffset": key[0],
            "sourceState": key[1],
            "targetOffset": key[2],
            "targetState": key[3],
            "stopReason": key[4],
            "executionCount": len(event_indices),
            "sourceEventIndices": sorted(event_indices),
        })
    result.sort(key=lambda item: (int(item["sourceOffset"], 16), int(item["targetOffset"], 16), item["sourceState"], item["targetState"]))
    return result


def _recapture_suggestions(runs):
    grouped = {}
    for run in runs:
        for missing in run.get("missingMemory", []):
            pc_offset = missing.get("pcOffset")
            if not pc_offset:
                continue
            byte_length = max(1, min(int(missing.get("size") or 1), 4096))
            key = (pc_offset, missing.get("baseRegister"), missing.get("displacement"), byte_length)
            grouped.setdefault(key, set()).add(run["sourceEventIndex"])
    result = []
    for key, event_indices in grouped.items():
        if key[1]:
            expression = "{}{}".format(
                key[1],
                ("+" + key[2]) if key[2] and not key[2].startswith("-") else (key[2] or ""),
            )
            reason = "Capture {}{} for the memory read at {}.".format(
                key[1],
                ("+" + key[2]) if key[2] and not key[2].startswith("-") else (key[2] or ""),
                key[0],
            )
            try:
                displacement = int(key[2] or "0", 0)
            except ValueError:
                displacement = None
            if displacement is not None and displacement >= 0:
                window_bytes = displacement + key[3]
                register_index = int(key[1][1:]) if re.fullmatch(r"X(?:[12][0-9]|[0-9])", key[1]) else None
                if key[1] == "SP" and window_bytes <= 16384:
                    reason += " Configure an SP stack window of at least {} bytes to cover {}.".format(window_bytes, expression)
                elif register_index is not None and register_index <= 28 and window_bytes <= 4096:
                    reason += " Configure {} pointer capture with at least {} bytes to cover the displacement.".format(key[1], window_bytes)
                else:
                    reason += " The current bounded base-window options do not directly cover this expression; add a narrowly scoped exact-address capture after verification."
            else:
                reason += " Negative or unresolved displacement requires a narrowly scoped exact-address capture after verification."
        else:
            reason = "Capture the runtime memory read at {} using the reported absolute address or a verified register-relative expression.".format(key[0])
        result.append({
            "pcOffset": key[0],
            "baseRegister": key[1],
            "displacement": key[2],
            "byteLength": key[3],
            "reason": reason,
            "sourceEventIndices": sorted(event_indices),
        })
    result.sort(key=lambda item: (int(item["pcOffset"], 16), item.get("baseRegister") or ""))
    return result


def analyze(binary_path):
    with open(binary_path, "rb") as source:
        binary_sha256 = hashlib.sha256(source.read()).hexdigest()
    expected_sha256 = EXPECTED_BINARY_IDENTITY["binarySha256"].lower()
    identity_matched = binary_sha256.lower() == expected_sha256
    if not identity_matched:
        raise RuntimeError(
            "exact ELF identity mismatch: expected SHA-256 {}, got {} for {}".format(
                expected_sha256, binary_sha256, binary_path
            )
        )
    runs = [_run_seed(binary_path, seed) for seed in SEEDS]
    recapture_plans = [seed.get("recapturePlan") or {
        "sourceEventIndex": seed.get("sourceEventIndex"),
        "captureOffset": seed.get("captureOffset"),
        "windows": [],
        "carryForwardBytes": 0,
        "unsupportedMemoryRegionCount": len(seed.get("memoryRegions", [])),
        "windowsTruncated": False,
    } for seed in SEEDS]
    warnings = [
        "Concrete replay covers only the exact captured states and bounded execution performed here; it does not recover a complete OLLVM CFG.",
        "A next-dispatcher result is execution-specific Candidate/Related evidence. Alternate inputs, threads, or uncaptured memory may produce different transitions.",
        "The SHA-256 guard validates the manually selected ELF file, not the image mapped during the original runtime capture.",
    ]
    partial = [quality for quality in [seed.get("quality") for seed in SEEDS] if quality and quality.get("status") != "ready"]
    if partial:
        warnings.append("{} replay seed(s) were partial; inspect missing state and recapture suggestions.".format(len(partial)))
    unsupported_regions = sum(int(plan.get("unsupportedMemoryRegionCount") or 0) for plan in recapture_plans)
    if unsupported_regions:
        warnings.append("{} seed memory region(s) cannot be automatically carried into a later Frida recapture because no verified bounded register-relative relation was available.".format(unsupported_regions))
    if any(bool(plan.get("windowsTruncated")) for plan in recapture_plans):
        warnings.append("At least one seed recapture plan reached the 256-window bound; later replay coverage may remain incomplete.")
    return {
        "schema": SCHEMA,
        "moduleName": REPORT["scope"]["moduleName"],
        "binarySha256": binary_sha256,
        "expectedBinarySha256": expected_sha256,
        "binaryIdentityMatched": identity_matched,
        "architecture": "AArch64",
        "unicornVersion": getattr(unicorn, "__version__", "unknown"),
        "capstoneVersion": getattr(capstone, "__version__", "unknown"),
        "config": CONFIG,
        "seeds": [seed["provenance"] for seed in SEEDS],
        "seedQualities": [seed["quality"] for seed in SEEDS],
        "seedRecapturePlans": recapture_plans,
        "runs": runs,
        "transitionMatrix": _transition_matrix(runs),
        "recaptureSuggestions": _recapture_suggestions(runs),
        "warnings": warnings,
    }


def main():
    parser = argparse.ArgumentParser(description="Trace UI exact-seed Unicorn replay for ARM64 OLLVM candidates")
    parser.add_argument("binary", help="Exact AArch64 ELF/shared object used by the capture")
    parser.add_argument("-o", "--output", default="trace-ui-unicorn-ollvm.json", help="Output JSON path")
    args = parser.parse_args()
    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        parser.error("binary does not exist: {}".format(binary_path))
    result = analyze(binary_path)
    output_path = os.path.abspath(args.output)
    with open(output_path, "w", encoding="utf-8") as output:
        json.dump(result, output, ensure_ascii=False, indent=2)
    print(
        "[Trace UI] wrote {} concrete replay run(s), {} dispatcher transition group(s), and {} recapture suggestion(s) to {}".format(
            len(result["runs"]),
            len(result["transitionMatrix"]),
            len(result["recaptureSuggestions"]),
            output_path,
        )
    )


if __name__ == "__main__":
    main()
