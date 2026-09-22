"""Read ETS2 profiles. SII decoding follows sk-zk/TruckLib.Sii (MIT)."""
import ctypes
import json
import os
import re
import shutil
import tempfile
import zlib
from pathlib import Path
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.parse import urljoin

# Explicitly expose the bridge contract to the visual editor.  The editor can
# infer simple comparisons too, but declarations remain reliable if the
# dispatcher is refactored later.
SCS_ACTIONS = (
    "defaults",
    "scan_profiles",
    "read_mods",
    "load_presets",
    "apply_preset",
    "save_mod_order",
    "delete_backups",
    "set_save_format",
    "list_backups",
    "restore_backup",
    "prepare_verification",
    "verify_mod_files",
    "verify_mod_parameters",
    "verify_preset",
)
SCS_OUTPUT_IDS = ("status", "result")

AES_KEY = bytes.fromhex("2a5fcb1791d22fb60245b3d8369ed0b2c27371563fbf1f3c9edf6b11825a5d0a")
THREE_NK_TABLE = bytes.fromhex(
    "f8d1aa835c750e27b099e2cb143d466f68413a13cce59eb72009725b84add6ff"
    "d8f18aa37c552e0790b9c2eb341d664f48611a33ecc5be970029527ba48df6df"
    "b891eac31c354e67f0d9a28b547d062f28017a538ca5def76049321bc4ed96bf"
    "98b1cae33c156e47d0f982ab745d260f08215a73ac85fed74069123be4cdb69f"
    "78512a03dcf58ea73019624b94bdc6efe8c1ba934c651e37a089f2db042d567f"
    "58710a23fcd5ae871039426bb49de6cfc8e19ab36c453e1780a9d2fb240d765f"
    "38116a439cb5cee77059220bd4fd86afa881fad30c255e77e0c9b29b446d163f"
    "18314a63bc95eec75079022bf4dda68f88a1daf32c057e57c0e992bb644d361f"
)

def decrypt_aes_cbc(ciphertext, iv):
    """AES-256-CBC via Windows CryptoAPI; payload format is TruckLib.Sii's ScsC."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    provider = ctypes.c_void_p(); key = ctypes.c_void_p()
    if not advapi.CryptAcquireContextW(ctypes.byref(provider), None, None, 24, 0xF0000000):
        raise OSError(ctypes.get_last_error(), "CryptAcquireContextW failed")
    try:
        blob = b"\x08\x02\x00\x00\x10\x66\x00\x00" + len(AES_KEY).to_bytes(4, "little") + AES_KEY
        blob_data = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        if not advapi.CryptImportKey(provider, blob_data, len(blob), None, 0, ctypes.byref(key)):
            raise OSError(ctypes.get_last_error(), "CryptImportKey failed")
        iv_data = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
        if not advapi.CryptSetKeyParam(key, 1, iv_data, 0):
            raise OSError(ctypes.get_last_error(), "CryptSetKeyParam failed")
        data = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext); size = ctypes.c_uint32(len(ciphertext))
        if not advapi.CryptDecrypt(key, None, True, 0, data, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "CryptDecrypt failed")
        return bytes(data[:size.value])
    finally:
        if key: advapi.CryptDestroyKey(key)
        if provider: advapi.CryptReleaseContext(provider, 0)

def encrypt_aes_cbc(plaintext, iv):
    """AES-256-CBC counterpart for ScsC profile output."""
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    provider = ctypes.c_void_p(); key = ctypes.c_void_p()
    if not advapi.CryptAcquireContextW(ctypes.byref(provider), None, None, 24, 0xF0000000):
        raise OSError(ctypes.get_last_error(), "CryptAcquireContextW failed")
    try:
        blob = b"\x08\x02\x00\x00\x10\x66\x00\x00" + len(AES_KEY).to_bytes(4, "little") + AES_KEY
        raw_key = (ctypes.c_ubyte * len(blob)).from_buffer_copy(blob)
        if not advapi.CryptImportKey(provider, raw_key, len(blob), None, 0, ctypes.byref(key)): raise OSError(ctypes.get_last_error(), "CryptImportKey failed")
        raw_iv = (ctypes.c_ubyte * len(iv)).from_buffer_copy(iv)
        if not advapi.CryptSetKeyParam(key, 1, raw_iv, 0): raise OSError(ctypes.get_last_error(), "CryptSetKeyParam failed")
        capacity = len(plaintext) + 32; data = (ctypes.c_ubyte * capacity)(); data[:len(plaintext)] = plaintext; size = ctypes.c_uint32(len(plaintext))
        if not advapi.CryptEncrypt(key, None, True, 0, data, ctypes.byref(size), capacity): raise OSError(ctypes.get_last_error(), "CryptEncrypt failed")
        return bytes(data[:size.value])
    finally:
        if key: advapi.CryptDestroyKey(key)
        if provider: advapi.CryptReleaseContext(provider, 0)

def storage_root():
    configured = os.environ.get("SCS_TOOL_RESOURCES", "").strip()
    root = Path(configured).expanduser() if configured else Path.cwd() / "tools_resources" / "Combo_Installer"
    root.mkdir(parents=True, exist_ok=True)
    return root

def save_resource_json(name, value):
    try: (storage_root() / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError: pass

def load_resource_json(name, default):
    try:
        value = json.loads((storage_root() / name).read_text(encoding="utf-8-sig"))
        return value
    except (OSError, json.JSONDecodeError):
        return default

def decode_sii(raw):
    if raw.startswith(b"SiiNunit"):
        decoded = raw
    elif raw.startswith(b"3nK") and len(raw) >= 6:
        seed = raw[5]; decoded = bytes(value ^ THREE_NK_TABLE[(seed + index) & 255] for index, value in enumerate(raw[6:]))
    elif raw.startswith(b"ScsC") and len(raw) >= 56:
        # Header: magic (4), HMAC (32), IV (16), size (uint32); exactly as TruckLib.Sii.
        decoded = zlib.decompress(decrypt_aes_cbc(raw[56:], raw[36:52]))
    else:
        raise ValueError("Unsupported SII format")
    return decoded.decode("utf-8-sig", errors="replace")

def profile_text(path):
    return decode_sii(path.read_bytes())

def unescape_sii_string(value):
    """Decode ETS2's escaped UTF-8 bytes (for example, \\xd0\\x9e)."""
    result = bytearray(); index = 0
    escapes = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\", '"': b'"'}
    while index < len(value):
        if value[index] == "\\" and index + 3 < len(value) and value[index + 1] == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", value[index + 2:index + 4]):
            result.append(int(value[index + 2:index + 4], 16)); index += 4; continue
        if value[index] == "\\" and index + 1 < len(value) and value[index + 1] in escapes:
            result.extend(escapes[value[index + 1]]); index += 2; continue
        result.extend(value[index].encode("utf-8")); index += 1
    return result.decode("utf-8", errors="replace")

def profile_name(text):
    # ETS2 writes a quoted value for most profiles, but older/current profiles
    # may legally store simple names without quotes.
    match = re.search(r'^\s*profile_name\s*:\s*(?:"(.*)"|(\S.*?))\s*$', text, re.MULTILINE)
    if not match: return None
    return unescape_sii_string(match.group(1) if match.group(1) is not None else match.group(2).strip())

def default_game_path():
    documents = Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Documents"
    return str(documents / "Euro Truck Simulator 2")

def same_path(left, right):
    try: return os.path.normcase(os.path.abspath(os.path.expanduser(str(left)))) == os.path.normcase(os.path.abspath(os.path.expanduser(str(right))))
    except (OSError, TypeError, ValueError): return False

def reply(**data):
    # The manager reads stdout as the Windows console code page. Escaping keeps
    # Chinese, Cyrillic and other Unicode mod names from crashing that channel.
    print(json.dumps(data, ensure_ascii=True))

def profiles(game_path):
    root = Path(game_path).expanduser()
    if not root.is_dir(): return None, "game_folder_not_found"
    folder = root / "profiles"
    if not folder.is_dir(): return None, "profiles_folder_not_found"
    found = []
    for item in sorted(folder.iterdir(), key=lambda value: value.name.casefold()):
        profile = item / "profile.sii"
        if not item.is_dir() or not profile.is_file(): continue
        try:
            name = profile_name(profile_text(profile))
            if name is not None: found.append({"directory": item.name, "name": name})
        except (OSError, ValueError, zlib.error):
            continue
    if not found: return None, "no_profiles"
    save_resource_json("profiles.json", {"game_path": str(root), "profiles": found})
    return found, None

def mod_entry(index, value):
    file_name, display_name = (value.split("|", 1) + [value])[:2] if "|" in value else (value, value)
    return {"index": index, "name": unescape_sii_string(display_name), "file": unescape_sii_string(file_name), "sii_value": value}

def active_mod_entries(text):
    values = {}
    for match in re.finditer(r'^\s*active_mods\[(\d+)\]\s*:\s*"(.*)"\s*$', text, re.MULTILINE):
        values[int(match.group(1))] = match.group(2)
    return [mod_entry(index, values[index]) for index in sorted(values, reverse=True)]

def mods(game_path, directory):
    root = Path(game_path).expanduser(); profile = root / "profiles" / directory / "profile.sii"
    if not directory or Path(directory).name != directory or not profile.is_file(): return None, "profile_not_found"
    try: text = profile_text(profile)
    except (OSError, ValueError, zlib.error): return None, "profile_read_failed"
    count = re.search(r'^\s*active_mods\s*:\s*(\d+)\s*$', text, re.MULTILINE)
    active_mods = int(count.group(1)) if count else 0
    # ETS2 treats 0 as the bottom of the stack; present the list from top down.
    return {"active_mods": active_mods, "mods": active_mod_entries(text)}, None

def bundled_presets():
    folder = Path(__file__).resolve().parent / "presets"; presets = []
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else []:
        try:
            preset = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(preset, dict) and isinstance(preset.get("mods"), list): presets.append(preset)
        except (OSError, json.JSONDecodeError): pass
    return presets

def local_resource_presets():
    """Read presets created by Preset Creator from every tool resource folder."""
    root = storage_root().parent
    presets = []
    try:
        paths = sorted(root.glob("*/presets/*.json"), key=lambda item: str(item).casefold())
    except OSError:
        paths = []
    for path in paths:
        try:
            preset = json.loads(path.read_text(encoding="utf-8-sig"))
            if isinstance(preset, dict) and isinstance(preset.get("mods"), list):
                presets.append(preset)
        except (OSError, json.JSONDecodeError):
            continue
    return presets

def merge_presets(*groups):
    merged = []
    seen = set()
    for group in groups:
        for preset in group if isinstance(group, list) else []:
            preset_id = str(preset.get("id", "")) if isinstance(preset, dict) else ""
            if not preset_id or preset_id in seen:
                continue
            seen.add(preset_id); merged.append(preset)
    return merged

PRESETS_LIST_URL = "https://lyonzyileonid5.website.yandexcloud.net/tools/verified_tools/a6f3812a4e5b49c695d7f1e8c32b4a0fa6f3812a4e5b49c695d7f1e8c32b4a0f/presets/list.json"

def remote_presets():
    request = Request(PRESETS_LIST_URL, headers={"User-Agent": "SCS-Mega-Manager/1.0"})
    with urlopen(request, timeout=15) as response: listing = response.read().decode("utf-8-sig")
    try:
        parsed = json.loads(listing); entries = parsed.get("list", parsed) if isinstance(parsed, dict) else parsed
        files = [item.get("file") if isinstance(item, dict) else item for item in entries] if isinstance(entries, list) else []
    except json.JSONDecodeError:
        # Accept the initially uploaded compact form: {"list":["file":"name.json"]}.
        files = re.findall(r'"file"\s*:\s*"([^"\\/]+\.json)"', listing)
    presets = []
    for filename in files:
        if not isinstance(filename, str) or Path(filename).name != filename: continue
        with urlopen(Request(urljoin(PRESETS_LIST_URL, filename), headers={"User-Agent": "SCS-Mega-Manager/1.0"}), timeout=20) as response:
            preset = json.loads(response.read().decode("utf-8-sig"))
        if isinstance(preset, dict) and isinstance(preset.get("mods"), list): presets.append(preset)
    return presets

def available_presets(refresh=False):
    # Applying must never wait on the network: use the presets already loaded
    # by the user (and restored at startup). Only the explicit load button
    # refreshes the remote catalogue.
    cached = load_resource_json("presets.json", [])
    local = local_resource_presets()
    if not refresh and isinstance(cached, list) and cached:
        return merge_presets(local, cached)
    try:
        remote = remote_presets()
        if remote:
            save_resource_json("presets.json", remote)
            return merge_presets(local, remote)
    except Exception: pass
    if isinstance(cached, list) and cached: return merge_presets(local, cached)
    return merge_presets(local, bundled_presets())

def preset_mod_value(item):
    if isinstance(item, str) and item: return item
    if isinstance(item, dict) and isinstance(item.get("file"), str) and isinstance(item.get("name"), str): return f"{item['file']}|{item['name']}"
    if isinstance(item, dict) and isinstance(item.get("sii_value"), str) and item["sii_value"]: return item["sii_value"]
    raise ValueError("Invalid preset mod")

def text_save_format_enabled(game_path):
    """ETS2 may safely load an edited plain SII only with save_format set to 2."""
    config = Path(game_path).expanduser() / "config.cfg"
    if not config.is_file(): return False, "config_not_found"
    try:
        content = config.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return False, "config_not_found"
    # The game writes: uset g_save_format "2". Accept the equivalent plain
    # setting too, so an already hand-edited config works as expected.
    allowed = re.search(r'^\s*(?:uset\s+g_)?save_format\s*(?::|\s)\s*"?2"?\s*$', content, re.MULTILINE)
    return (True, None) if allowed else (False, "save_format_must_be_2")

def set_text_save_format(game_path):
    """Set the game option to the editable SII format, preserving config.cfg."""
    config = Path(game_path).expanduser() / "config.cfg"
    if not config.is_file(): return None, "config_not_found"
    try:
        content = config.read_text(encoding="utf-8-sig", errors="replace")
        ending = "\r\n" if "\r\n" in content else "\n"
        setting = re.compile(r'^\s*uset\s+g_save_format\s+(?:"[^"]*"|\S+)\s*$', re.MULTILINE)
        updated, replacements = setting.subn('uset g_save_format "2"', content, count=1)
        if not replacements:
            updated = content.rstrip("\r\n") + ending + 'uset g_save_format "2"' + ending
        backup = storage_root() / f"config.cfg-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(config, backup)
        handle, temporary = tempfile.mkstemp(prefix="config.cfg.combo-", suffix=".tmp", dir=str(config.parent))
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="") as output: output.write(updated)
            os.replace(temporary, config)
        except Exception:
            try: os.unlink(temporary)
            except OSError: pass
            raise
        return {"backup": str(backup)}, None
    except OSError:
        return None, "config_write_failed"

def profile_path(game_path, directory):
    profile = Path(game_path).expanduser() / "profiles" / directory / "profile.sii"
    return profile if directory and Path(directory).name == directory and profile.is_file() else None

def anchor_index(values, anchor):
    if not isinstance(anchor, dict): return None
    target = str(anchor.get("name", "")).casefold()
    match_kind = str(anchor.get("match", "display_name"))
    if not target: return None
    for index, value in enumerate(values):
        entry = mod_entry(index, value)
        candidate = entry["file"] if match_kind == "file" else entry["name"]
        if candidate.casefold() == target: return index
    return None

def write_mod_values(profile, values, backup_prefix):
    if not all(isinstance(value, str) and value and "\n" not in value and "\r" not in value for value in values): return None, "invalid_mod_order"
    try:
        text = profile_text(profile)
        pattern = re.compile(r'^\s*active_mods\s*:\s*\d+\s*$\n(?:^\s*active_mods\[\d+\]\s*:\s*".*"\s*$\n?)*', re.MULTILINE)
        if not pattern.search(text): return None, "active_mods_not_found"
        ending = "\r\n" if "\r\n" in text else "\n"
        block = f" active_mods: {len(values)}{ending}" + ending.join(f' active_mods[{index}]: "{value}"' for index, value in enumerate(reversed(values))) + ending
        resources = storage_root()
        backup = resources / f"{backup_prefix}-profile.sii-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(profile, backup)
        handle, temporary = tempfile.mkstemp(prefix="profile.sii.combo-", suffix=".tmp", dir=str(profile.parent))
        try:
            updated = pattern.sub(lambda _match: block, text, count=1).encode("utf-8")
            # save_format 2 is deliberately required above: plain SII is the
            # game-supported, editable format and avoids re-creating ScsC.
            with os.fdopen(handle, "wb") as output: output.write(updated)
            os.replace(temporary, profile)
        except Exception:
            try: os.unlink(temporary)
            except OSError: pass
            raise
        return {"backup": str(backup), "active_mods": len(values), "mods": [mod_entry(len(values) - 1 - index, value) for index, value in enumerate(values)]}, None
    except (OSError, ValueError, zlib.error): return None, "profile_write_failed"

def apply_preset(game_path, directory, preset_id, own_mods=None):
    profile = profile_path(game_path, directory)
    if not profile: return None, "profile_not_found"
    enabled, error = text_save_format_enabled(game_path)
    if not enabled: return None, error
    preset = next((item for item in available_presets() if str(item.get("id")) == str(preset_id)), None)
    if not preset: return None, "preset_not_found"
    try: values = [preset_mod_value(item) for item in preset["mods"]]
    except (KeyError, ValueError): return None, "preset_invalid"
    own_values = [str(value) for value in own_mods] if isinstance(own_mods, list) else []
    own_values = list(dict.fromkeys(value for value in own_values if value not in values))
    if own_values:
        after = anchor_index(values, preset.get("own_mods_after"))
        if after is None: return None, "own_mods_anchor_not_found"
        # The list is displayed from top to bottom: personal mods go above
        # the anchor (for example, Map FIX), leaving the anchor below them.
        values[after:after] = own_values
    result, error = write_mod_values(profile, values, directory)
    if result:
        result["own_mods"] = own_values
        save_resource_json("own_mods.json", {"game_path": str(Path(game_path).expanduser()), "preset_id": str(preset_id), "mods": own_values})
    return result, error

def save_mod_order(game_path, directory, values):
    profile = profile_path(game_path, directory)
    if not profile: return None, "profile_not_found"
    enabled, error = text_save_format_enabled(game_path)
    if not enabled: return None, error
    return write_mod_values(profile, values if isinstance(values, list) else [], directory + "-order")

def delete_backups():
    """Remove only backup files created by this tool; settings and presets remain."""
    removed = 0
    try:
        for path in storage_root().glob("*.bak"):
            if path.is_file():
                path.unlink()
                removed += 1
    except OSError:
        return None, "backup_delete_failed"
    return {"removed": removed}, None

def backup_entries():
    entries = []
    for path in sorted(storage_root().glob("*.bak"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            created = datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
            if path.name.startswith("config.cfg-"):
                entries.append({"id": path.name, "name": path.name, "kind": "config", "created": created, "mods": [], "mod_count": 0})
                continue
            match = re.match(r"^(.+)-profile\.sii-\d{8}-\d{6}\.bak$", path.name)
            if not match: continue
            directory = match.group(1).removesuffix("-order")
            text = profile_text(path); mods_list = active_mod_entries(text)
            entries.append({"id": path.name, "name": path.name, "kind": "profile", "profile_dir": directory, "created": created, "mods": mods_list, "mod_count": len(mods_list)})
        except (OSError, ValueError, zlib.error):
            continue
    return entries, None

def restore_backup(game_path, backup_id):
    if not isinstance(backup_id, str) or Path(backup_id).name != backup_id or not backup_id.endswith(".bak"): return None, "backup_not_found"
    source = storage_root() / backup_id
    if not source.is_file(): return None, "backup_not_found"
    if backup_id.startswith("config.cfg-"):
        target = Path(game_path).expanduser() / "config.cfg"
    else:
        match = re.match(r"^(.+)-profile\.sii-\d{8}-\d{6}\.bak$", backup_id)
        if not match: return None, "backup_not_found"
        target = Path(game_path).expanduser() / "profiles" / match.group(1).removesuffix("-order") / "profile.sii"
    if not target.is_file(): return None, "restore_target_not_found"
    try:
        safety = storage_root() / f"restore-before-{target.name}-{datetime.now():%Y%m%d-%H%M%S}.bak"
        shutil.copy2(target, safety); shutil.copy2(source, target)
        return {"backup": backup_id, "safety_backup": str(safety)}, None
    except OSError: return None, "restore_failed"

def verification_preset(preset_id):
    preset = next((item for item in available_presets() if str(item.get("id")) == str(preset_id)), None)
    return preset if isinstance(preset, dict) else None

def active_log_mods(game_path):
    log = Path(game_path).expanduser() / "game.log.txt"
    if not log.is_file(): return None, "game_log_not_found"
    try: lines = log.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError: return None, "game_log_not_found"
    block = []
    for line in reversed(lines):
        # Workshop entries can appear between local entries. They are active
        # mods too, and must not split the single startup block.
        if "[mods] Active local mod " in line or "[mods] Active workshop mod ID " in line: block.append(line)
        elif block: break
    if not block: return None, "active_mods_log_not_found"
    local_pattern = re.compile(r"\[mods\] Active local mod (.*?) \(name: (.*?), version: (.*?), author: (.*)\)$")
    workshop_pattern = re.compile(r"\[mods\] Active workshop mod ID (\d+) \(name: (.*?), version: (.*?), author: (.*)\)$")
    mods = {}
    for line in reversed(block):
        match = local_pattern.search(line)
        if match:
            file_id, name, version, author = match.groups()
            mods[file_id] = {"log_name": name, "version": version, "author": author}
            continue
        match = workshop_pattern.search(line)
        if match:
            workshop_id, name, version, author = match.groups()
            mods[f"workshop:{workshop_id}"] = {"log_name": name, "version": version, "author": author}
    return mods, None

def prepared_log(game_path, preset_id):
    cached = load_resource_json("verification_log.json", {})
    if isinstance(cached, dict) and cached.get("game_path") == str(Path(game_path).expanduser()) and cached.get("preset_id") == str(preset_id) and isinstance(cached.get("mods"), dict): return cached["mods"], None
    return None, "verification_not_prepared"

def mod_archive(game_path, file_id):
    folder = Path(game_path).expanduser() / "mod"
    for suffix in (".scs", ".zip"):
        candidate = folder / f"{file_id}{suffix}"
        if candidate.is_file(): return candidate
    return None

def prepare_verification(game_path, preset_id):
    if not verification_preset(preset_id): return None, "preset_not_found"
    mods, error = active_log_mods(game_path)
    if error: return None, error
    save_resource_json("verification_log.json", {"game_path": str(Path(game_path).expanduser()), "preset_id": str(preset_id), "mods": mods})
    return {"active_mods": len(mods)}, None

def verify_mod_files(game_path, preset_id):
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    missing = []
    for item in preset.get("mods", []):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str): continue
        if not isinstance(item.get("verification"), dict): continue
        file_id = unescape_sii_string(item["file"])
        if not mod_archive(game_path, file_id): missing.append({"file": file_id, "name": unescape_sii_string(str(item.get("name", file_id)))})
    return {"missing": missing, "checked": len(preset.get("mods", []))}, None

def verify_mod_parameters(game_path, preset_id):
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    logged, error = prepared_log(game_path, preset_id)
    if error: return None, error
    mismatches = []
    for item in preset.get("mods", []):
        if not isinstance(item, dict) or not isinstance(item.get("file"), str): continue
        if not isinstance(item.get("verification"), dict): continue
        expected = item["verification"]
        file_id = unescape_sii_string(item["file"]); actual = logged.get(file_id); problems = []
        for key in ("log_name", "version", "author"):
            if key in expected and (not actual or str(actual.get(key, "")) != str(expected[key])): problems.append(key)
        if "size" in expected:
            archive = mod_archive(game_path, file_id)
            if not archive or archive.stat().st_size != int(expected["size"]): problems.append("size")
        if problems: mismatches.append({"file": file_id, "name": unescape_sii_string(str(item.get("name", file_id))), "problems": problems})
    return {"mismatches": mismatches, "checked": len(preset.get("mods", []))}, None

def verify_preset(game_path, preset_id, own_mods=None):
    """Run the complete check in one request and retain the parsed log for display."""
    preset = verification_preset(preset_id)
    if not preset: return None, "preset_not_found"
    prepared, error = prepare_verification(game_path, preset_id)
    if error: return None, error
    files, error = verify_mod_files(game_path, preset_id)
    if error: return None, error
    parameters, error = verify_mod_parameters(game_path, preset_id)
    if error: return None, error
    logged, error = prepared_log(game_path, preset_id)
    if error: return None, error
    log_mods = [{"file": file_id, **value} for file_id, value in logged.items()]
    expected_files = {unescape_sii_string(item["file"]) for item in preset.get("mods", []) if isinstance(item, dict) and isinstance(item.get("file"), str)}
    if not isinstance(own_mods, list):
        saved = load_resource_json("own_mods.json", {})
        own_mods = saved.get("mods", []) if isinstance(saved, dict) and saved.get("game_path") == str(Path(game_path).expanduser()) and saved.get("preset_id") == str(preset_id) else []
    own_files = set()
    for value in own_mods:
        if not isinstance(value, str): continue
        file_id = unescape_sii_string(value.split("|", 1)[0])
        workshop = re.fullmatch(r"workshop[.:](\d+)", file_id, re.I)
        package = re.fullmatch(r"mod_workshop_package\.([0-9a-f]+)", file_id, re.I)
        if workshop: own_files.add(f"workshop:{workshop.group(1)}")
        elif package: own_files.add(f"workshop:{int(package.group(1), 16)}")
        else: own_files.add(file_id)
    extra_mods = [{"file": file_id, "name": value.get("log_name", file_id)} for file_id, value in logged.items() if file_id not in expected_files and file_id not in own_files]
    return {"active_mods": log_mods, "missing": files["missing"], "mismatches": parameters["mismatches"], "extra_mods": extra_mods}, None


SCS_ACTIONS = ("defaults", "scan_profiles", "read_profile", "save_state", "create_preset")
SCS_OUTPUT_IDS = ("status", "result")

def creator_storage_root():
    configured = os.environ.get("SCS_TOOL_RESOURCES", "").strip()
    root = Path(configured).expanduser() if configured else Path.cwd() / "tools_resources" / "Combo_Preset_Creator"
    root.mkdir(parents=True, exist_ok=True)
    return root

def creator_game_path():
    try:
        saved = json.loads((creator_storage_root() / "state.json").read_text(encoding="utf-8-sig"))
        if isinstance(saved, dict) and isinstance(saved.get("game_path"), str): return saved["game_path"]
    except (OSError, json.JSONDecodeError): pass
    return default_game_path()

def creator_state():
    try:
        value = json.loads((creator_storage_root() / "state.json").read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError): return {}

def save_creator_state(update):
    state = creator_state()
    if isinstance(update, dict):
        for key in ("game_path", "profile_dir", "id", "name", "own_mod_after", "blocked_keywords"):
            if isinstance(update.get(key), str): state[key] = update[key]
        if isinstance(update.get("profiles"), list): state["profiles"] = [item for item in update["profiles"] if isinstance(item, dict) and isinstance(item.get("directory"), str) and isinstance(item.get("name"), str)]
        if isinstance(update.get("mods"), list): state["mods"] = [item for item in update["mods"] if isinstance(item, dict) and isinstance(item.get("sii_value"), str) and isinstance(item.get("name"), str)]
    try: (creator_storage_root() / "state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError: pass
    return state

def create_preset(game_path, directory, preset_id, name, own_mod_after, keywords):
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", str(preset_id)): return None, "preset_id_invalid"
    if not isinstance(name, str) or not name.strip(): return None, "preset_name_required"
    values, error = mods(game_path, directory)
    if error: return None, error
    selected = next((item for item in values["mods"] if item["sii_value"] == own_mod_after), None)
    if not selected: return None, "own_mod_after_required"
    logged, log_error = active_log_mods(game_path)
    logged = logged if not log_error else {}
    entries = []; verified = 0
    for item in values["mods"]:
        entry = {"file": item["file"], "name": item["name"]}
        logged_item = logged.get(item["file"])
        archive = mod_archive(game_path, item["file"])
        if logged_item and archive:
            verification = dict(logged_item)
            verification["size"] = archive.stat().st_size
            entry["verification"] = verification; verified += 1
        entries.append(entry)
    blocked = [value.strip() for value in str(keywords or "").split(",") if value.strip()]
    preset = {"schema_version": 1, "id": preset_id, "name": name.strip(), "description": f"Created from profile {directory}. Mods are listed top to bottom.", "own_mods_after": {"name": selected["name"], "match": "display_name"}, "blocked_mod_keywords": blocked, "mods": entries}
    folder = creator_storage_root() / "presets"; folder.mkdir(exist_ok=True)
    path = folder / f"{preset_id}.json"
    try: path.write_text(json.dumps(preset, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError: return None, "preset_write_failed"
    return {"id": preset_id, "path": str(path), "mod_count": len(entries), "verified_count": verified, "skipped_count": len(entries) - verified}, None

def main():
    try: data = json.loads(os.environ.get("SCS_TOOL_INPUT", "{}"))
    except json.JSONDecodeError: return reply(status="error", code="generic")
    action = data.get("action"); game_path = str(data.get("game_path", "")).strip()
    if action == "defaults":
        state = creator_state(); state["game_path"] = state.get("game_path") or creator_game_path()
        return reply(status="defaults", game_path=state["game_path"], state=state)
    if action == "scan_profiles":
        value, error = profiles(game_path)
        if not error: save_creator_state({"game_path": game_path, "profiles": value})
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, profiles=value)
    if action == "read_profile":
        value, error = mods(game_path, str(data.get("profile_dir", "")))
        if not error: save_creator_state({"game_path": game_path, "profile_dir": str(data.get("profile_dir", "")), "mods": value.get("mods", [])})
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    if action == "save_state":
        state = save_creator_state(data.get("state"))
        return reply(status="ok", action=action, state=state)
    if action == "create_preset":
        value, error = create_preset(game_path, str(data.get("profile_dir", "")), data.get("id"), data.get("name"), data.get("own_mod_after"), data.get("blocked_keywords"))
        if not error: save_creator_state({"game_path": game_path, "profile_dir": str(data.get("profile_dir", "")), "id": str(data.get("id", "")), "name": str(data.get("name", "")), "own_mod_after": str(data.get("own_mod_after", "")), "blocked_keywords": str(data.get("blocked_keywords", ""))})
        return reply(status="error", action=action, code=error) if error else reply(status="ok", action=action, **value)
    reply(status="error", action=action, code="generic")

if __name__ == "__main__": main()
