import os
import hashlib
import pickle
import json
import argparse
import time

STATE_FILE = "backup_state.pkl"
LOG_FILE = "change_log.json"
REPORT_FILE = "last_report.txt"

def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

def scan_directory(base_path):
    state = {}
    for root, _, files in os.walk(base_path):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base_path)
            state[rel_path] = hash_file(full_path)
    return state

def load_previous_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, 'rb') as f:
        return pickle.load(f)

def save_current_state(state):
    with open(STATE_FILE, 'wb') as f:
        pickle.dump(state, f)

def diff_states(old, new):
    added = [f for f in new if f not in old]
    removed = [f for f in old if f not in new]
    changed = [f for f in new if f in old and old[f] != new[f]]
    return {"added": added, "removed": removed, "changed": changed}

def log_changes(diff):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "changes": diff
    }
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)
    else:
        data = []
    data.append(entry)
    with open(LOG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def generate_report(diff, folder):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    report_lines = [
        f"📁 Klasör: {folder}",
        f"🕒 Zaman: {timestamp}",
        "",
        f"➕ Eklenen Dosyalar: {len(diff['added'])}",
        *["  - " + f for f in diff["added"]],
        "",
        f"➖ Silinen Dosyalar: {len(diff['removed'])}",
        *["  - " + f for f in diff["removed"]],
        "",
        f"✏️ Değiştirilen Dosyalar: {len(diff['changed'])}",
        *["  - " + f for f in diff["changed"]],
        ""
    ]
    report = "\n".join(report_lines)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:  # <== düzeltme burada
        f.write(report)
    return report

def main(folder):
    print(f"[+] '{folder}' klasörü taranıyor...")
    current_state = scan_directory(folder)
    previous_state = load_previous_state()
    diff = diff_states(previous_state, current_state)
    save_current_state(current_state)
    log_changes(diff)
    report = generate_report(diff, folder)
    print("[✓] Tarama tamamlandı. Rapor oluşturuldu:\n")
    print(report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Backup Differ - Folder Change Tracker")
    parser.add_argument("folder", help="Hedef klasörü belirtin")
    args = parser.parse_args()
    main(args.folder)

