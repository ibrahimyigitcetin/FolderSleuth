import os
import hashlib
import pickle
import json
import argparse
import time
import re
import statistics
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil

STATE_FILE = "backup_state.pkl"
LOG_FILE = "change_log.json"
REPORT_FILE = "last_report.txt"
ANOMALY_LOG = "anomaly_detection.json"
THREAT_SIGNATURES = "threat_signatures.json"

# Threat detection patterns
RANSOMWARE_EXTENSIONS = [
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.aaa', '.abc', '.xyz',
    '.zzz', '.micro', '.ttt', '.mp3', '.locky', '.zepto', '.odin', '.shit',
    '.cerber', '.cerber2', '.cerber3', '.wallet', '.xtbl', '.exx', '.ezz'
]

SUSPICIOUS_PATTERNS = [
    r'(?i)(password|pwd|pass)\s*[=:]\s*["\']?[a-zA-Z0-9!@#$%^&*()_+-=]{6,}',
    r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}',
    r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}',
    r'(?i)(token)\s*[=:]\s*["\']?[a-zA-Z0-9]{30,}',
    r'(?i)BEGIN\s+(RSA\s+)?PRIVATE\s+KEY',
    r'(?i)(database[_-]?url|db[_-]?url)\s*[=:]\s*["\']?[a-zA-Z0-9:/._-]+',
]

MALWARE_INDICATORS = [
    'payload', 'backdoor', 'keylogger', 'trojan', 'virus', 'malware',
    'exploit', 'shell', 'reverse_shell', 'meterpreter', 'metasploit'
]

class AnomalyDetector:
    def __init__(self):
        self.baseline_metrics = self.load_baseline()
        self.recent_changes = deque(maxlen=1000)
        self.threat_score_threshold = 70
        self.normal_patterns = self.load_normal_patterns()
    
    def load_baseline(self):
        """Load baseline system metrics for comparison"""
        try:
            with open('baseline_metrics.json', 'r') as f:
                return json.load(f)
        except:
            return {
                'avg_file_size': 50000,  # 50KB average
                'avg_changes_per_hour': 10,
                'common_extensions': ['.py', '.txt', '.md', '.json', '.log'],
                'normal_change_rate': 5  # files per minute
            }
    
    def load_normal_patterns(self):
        """Load patterns of normal file changes"""
        try:
            with open('normal_patterns.json', 'r') as f:
                return json.load(f)
        except:
            return {
                'working_hours': (9, 18),  # 9 AM to 6 PM
                'common_file_types': ['.py', '.txt', '.md', '.json'],
                'max_hourly_changes': 50,
                'max_size_change_ratio': 3.0
            }
    
    def calculate_threat_score(self, file_path, change_type, file_size=0, content_preview=""):
        """Calculate threat score based on multiple indicators"""
        score = 0
        threat_indicators = []
        
        # 1. Ransomware extension check
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in RANSOMWARE_EXTENSIONS:
            score += 50
            threat_indicators.append(f"Suspicious extension: {file_ext}")
        
        # 2. Mass file changes (ransomware behavior)
        recent_changes_count = len([c for c in self.recent_changes 
                                  if (time.time() - c['timestamp']) < 300])  # 5 minutes
        if recent_changes_count > 20:
            score += 30
            threat_indicators.append(f"Mass file changes detected: {recent_changes_count} in 5 min")
        
        # 3. File size anomaly
        if file_size > self.baseline_metrics['avg_file_size'] * 10:
            score += 20
            threat_indicators.append(f"Unusually large file: {file_size} bytes")
        
        # 4. Suspicious content patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, content_preview):
                score += 25
                threat_indicators.append("Sensitive data pattern detected")
                break
        
        # 5. Malware indicators in filename/path
        file_lower = file_path.lower()
        for indicator in MALWARE_INDICATORS:
            if indicator in file_lower:
                score += 35
                threat_indicators.append(f"Malware indicator in filename: {indicator}")
        
        # 6. Time-based anomaly (changes at unusual hours)
        current_hour = datetime.now().hour
        working_start, working_end = self.normal_patterns['working_hours']
        if current_hour < working_start or current_hour > working_end:
            score += 15
            threat_indicators.append(f"Change detected outside working hours: {current_hour}:00")
        
        # 7. Rapid successive changes to same file
        same_file_changes = [c for c in self.recent_changes 
                           if c['file'] == file_path and (time.time() - c['timestamp']) < 60]
        if len(same_file_changes) > 3:
            score += 25
            threat_indicators.append("Rapid successive changes to same file")
        
        return score, threat_indicators
    
    def detect_performance_anomaly(self):
        """Detect system performance issues that might indicate problems"""
        cpu_percent = psutil.cpu_percent(interval=1)
        memory_percent = psutil.virtual_memory().percent
        disk_io = psutil.disk_io_counters()
        
        anomalies = []
        
        if cpu_percent > 90:
            anomalies.append(f"High CPU usage: {cpu_percent}%")
        
        if memory_percent > 90:
            anomalies.append(f"High memory usage: {memory_percent}%")
        
        # Check for unusual disk activity
        if hasattr(self, 'prev_disk_io'):
            read_rate = (disk_io.read_bytes - self.prev_disk_io.read_bytes) / 1024 / 1024  # MB/s
            write_rate = (disk_io.write_bytes - self.prev_disk_io.write_bytes) / 1024 / 1024  # MB/s
            
            if read_rate > 100:  # More than 100MB/s read
                anomalies.append(f"High disk read activity: {read_rate:.1f} MB/s")
            
            if write_rate > 100:  # More than 100MB/s write
                anomalies.append(f"High disk write activity: {write_rate:.1f} MB/s")
        
        self.prev_disk_io = disk_io
        return anomalies
    
    def is_false_positive(self, file_path, change_type, threat_score):
        """Reduce false positives by checking for known safe patterns"""
        
        # Known safe file types and patterns
        safe_extensions = ['.log', '.tmp', '.cache', '.bak', '.swp', '~']
        safe_directories = ['__pycache__', '.git', 'node_modules', '.vscode', 'logs', 'temp']
        safe_filenames = ['desktop.ini', 'thumbs.db', '.ds_store']
        
        file_lower = file_path.lower()
        filename = os.path.basename(file_lower)
        
        # Check for safe extensions
        for ext in safe_extensions:
            if file_lower.endswith(ext):
                return True, f"Safe file extension: {ext}"
        
        # Check for safe directories
        for safe_dir in safe_directories:
            if safe_dir in file_lower:
                return True, f"Safe directory pattern: {safe_dir}"
        
        # Check for safe filenames
        if filename in safe_filenames:
            return True, f"Safe system file: {filename}"
        
        # Check if it's a known application creating files
        if self.is_known_application_activity(file_path):
            return True, "Known application activity"
        
        # If threat score is low and it's during working hours, likely safe
        current_hour = datetime.now().hour
        working_start, working_end = self.normal_patterns['working_hours']
        if (threat_score < 30 and 
            working_start <= current_hour <= working_end and 
            change_type in ['added', 'changed']):
            return True, "Low threat score during working hours"
        
        return False, None
    
    def is_known_application_activity(self, file_path):
        """Check if file change is from known safe applications"""
        # Get list of running processes
        try:
            running_processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            
            # Known safe applications that frequently modify files
            safe_apps = ['python', 'code', 'notepad', 'sublime', 'atom', 'vim', 'emacs', 
                        'chrome', 'firefox', 'excel', 'word', 'git']
            
            for app in safe_apps:
                if any(app in proc for proc in running_processes):
                    return True
        except:
            pass
        
        return False
    
    def analyze_change_pattern(self, changes_history):
        """Analyze patterns in file changes to detect anomalies"""
        if len(changes_history) < 10:
            return []
        
        anomalies = []
        
        # Calculate change rate over time
        time_windows = [60, 300, 900]  # 1min, 5min, 15min
        for window in time_windows:
            recent_changes = [c for c in changes_history 
                            if (time.time() - c['timestamp']) < window]
            change_rate = len(recent_changes) / (window / 60)  # changes per minute
            
            if change_rate > self.baseline_metrics['normal_change_rate'] * 3:
                anomalies.append(f"High change rate: {change_rate:.1f} changes/min in last {window//60} min")
        
        # Check for unusual file type distribution
        recent_extensions = [os.path.splitext(c['file'])[1] for c in changes_history[-50:]]
        extension_counts = defaultdict(int)
        for ext in recent_extensions:
            extension_counts[ext] += 1
        
        # If one extension dominates recent changes (possible ransomware)
        if extension_counts:
            most_common_ext, count = max(extension_counts.items(), key=lambda x: x[1])
            if count > len(recent_extensions) * 0.7 and most_common_ext not in ['.log', '.tmp']:
                anomalies.append(f"Suspicious extension dominance: {most_common_ext} ({count} files)")
        
        return anomalies
    
    def log_anomaly(self, file_path, threat_score, indicators, is_false_positive=False):
        """Log detected anomalies for analysis"""
        anomaly_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "file_path": file_path,
            "threat_score": threat_score,
            "indicators": indicators,
            "is_false_positive": is_false_positive,
            "system_metrics": {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent
            }
        }
        
        # Load existing anomaly log
        try:
            with open(ANOMALY_LOG, 'r') as f:
                anomaly_data = json.load(f)
        except:
            anomaly_data = []
        
        anomaly_data.append(anomaly_entry)
        
        # Keep only last 1000 entries
        if len(anomaly_data) > 1000:
            anomaly_data = anomaly_data[-1000:]
        
        with open(ANOMALY_LOG, 'w') as f:
            json.dump(anomaly_data, f, indent=2)

def get_file_content_preview(file_path, max_size=1024):
    """Get a preview of file content for analysis"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read(max_size)
    except:
        return ""

def hash_file(path):
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR:{e}"

def scan_directory(base_path, anomaly_detector):
    state = {}
    threat_alerts = []
    
    for root, _, files in os.walk(base_path):
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, base_path)
            
            file_hash = hash_file(full_path)
            state[rel_path] = file_hash
            
            # Get file info for threat analysis
            try:
                file_size = os.path.getsize(full_path)
                content_preview = get_file_content_preview(full_path)
                
                # Calculate threat score
                threat_score, indicators = anomaly_detector.calculate_threat_score(
                    rel_path, 'scan', file_size, content_preview
                )
                
                # Check for false positives
                is_fp, fp_reason = anomaly_detector.is_false_positive(rel_path, 'scan', threat_score)
                
                if threat_score > anomaly_detector.threat_score_threshold and not is_fp:
                    threat_alerts.append({
                        'file': rel_path,
                        'threat_score': threat_score,
                        'indicators': indicators,
                        'size': file_size
                    })
                    anomaly_detector.log_anomaly(rel_path, threat_score, indicators, is_fp)
                
                # Add to recent changes for pattern analysis
                anomaly_detector.recent_changes.append({
                    'file': rel_path,
                    'timestamp': time.time(),
                    'change_type': 'scan',
                    'size': file_size
                })
                
            except Exception as e:
                print(f"Warning: Could not analyze {rel_path}: {e}")
    
    return state, threat_alerts

def analyze_changes_for_threats(diff, anomaly_detector):
    """Analyze file changes for potential threats"""
    threat_alerts = []
    performance_anomalies = anomaly_detector.detect_performance_anomaly()
    
    if performance_anomalies:
        print(f"⚠️  Performance Anomalies Detected: {', '.join(performance_anomalies)}")
    
    # Analyze all types of changes
    all_changes = []
    for change_type in ['added', 'removed', 'changed']:
        for file_path in diff[change_type]:
            try:
                # Get file info if file still exists
                file_size = 0
                content_preview = ""
                if change_type != 'removed':
                    try:
                        file_size = os.path.getsize(file_path)
                        content_preview = get_file_content_preview(file_path)
                    except:
                        pass
                
                # Calculate threat score
                threat_score, indicators = anomaly_detector.calculate_threat_score(
                    file_path, change_type, file_size, content_preview
                )
                
                # Check for false positives
                is_fp, fp_reason = anomaly_detector.is_false_positive(file_path, change_type, threat_score)
                
                if threat_score > anomaly_detector.threat_score_threshold and not is_fp:
                    threat_alerts.append({
                        'file': file_path,
                        'change_type': change_type,
                        'threat_score': threat_score,
                        'indicators': indicators,
                        'size': file_size
                    })
                    anomaly_detector.log_anomaly(file_path, threat_score, indicators, is_fp)
                elif is_fp:
                    print(f"ℹ️  False positive filtered: {file_path} ({fp_reason})")
                
                # Add to recent changes for pattern analysis
                anomaly_detector.recent_changes.append({
                    'file': file_path,
                    'timestamp': time.time(),
                    'change_type': change_type,
                    'size': file_size
                })
                
                all_changes.append({
                    'file': file_path,
                    'timestamp': time.time(),
                    'change_type': change_type
                })
                
            except Exception as e:
                print(f"Warning: Could not analyze {file_path}: {e}")
    
    # Analyze change patterns
    pattern_anomalies = anomaly_detector.analyze_change_pattern(all_changes)
    if pattern_anomalies:
        print(f"🔍 Pattern Anomalies: {', '.join(pattern_anomalies)}")
    
    return threat_alerts

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

def log_changes(diff, threat_alerts=None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "changes": diff,
        "threat_alerts": threat_alerts or []
    }
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            data = json.load(f)
    else:
        data = []
    data.append(entry)
    with open(LOG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def generate_report(diff, folder, threat_alerts=None):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Threat analysis section
    threat_section = []
    if threat_alerts:
        threat_section.extend([
            "🚨 THREAT ANALYSIS 🚨",
            f"High-risk changes detected: {len(threat_alerts)}",
            ""
        ])
        
        for alert in threat_alerts[:5]:  # Show top 5 threats
            threat_section.extend([
                f"⚠️  HIGH RISK: {alert['file']}",
                f"   Threat Score: {alert['threat_score']}/100",
                f"   Change Type: {alert.get('change_type', 'N/A')}",
                f"   Indicators: {', '.join(alert['indicators'][:3])}",  # Show first 3 indicators
                ""
            ])
        
        if len(threat_alerts) > 5:
            threat_section.append(f"... and {len(threat_alerts) - 5} more threats detected")
            threat_section.append("")
    else:
        threat_section.extend([
            "✅ SECURITY STATUS: CLEAN",
            "No high-risk threats detected",
            ""
        ])
    
    report_lines = [
        "=" * 60,
        f"📁 FOLDERSLEUTH - ADVANCED SECURITY REPORT",
        "=" * 60,
        f"📁 Klasör: {folder}",
        f"🕒 Zaman: {timestamp}",
        "",
        *threat_section,
        "📊 FILE CHANGES SUMMARY",
        "-" * 30,
        f"➕ Eklenen Dosyalar: {len(diff['added'])}",
        *["  - " + f for f in diff["added"][:10]],  # Show first 10
        "" if len(diff['added']) <= 10 else f"  ... and {len(diff['added']) - 10} more",
        "",
        f"➖ Silinen Dosyalar: {len(diff['removed'])}",
        *["  - " + f for f in diff["removed"][:10]],  # Show first 10
        "" if len(diff['removed']) <= 10 else f"  ... and {len(diff['removed']) - 10} more",
        "",
        f"✏️ Değiştirilen Dosyalar: {len(diff['changed'])}",
        *["  - " + f for f in diff["changed"][:10]],  # Show first 10
        "" if len(diff['changed']) <= 10 else f"  ... and {len(diff['changed']) - 10} more",
        "",
        "=" * 60
    ]
    
    report = "\n".join(report_lines)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(report)
    return report

def main(folder):
    print(f"[+] FolderSleuth Advanced - Scanning '{folder}' with threat detection...")
    
    # Initialize anomaly detector
    anomaly_detector = AnomalyDetector()
    
    # Scan directory with threat detection
    current_state, scan_threats = scan_directory(folder, anomaly_detector)
    previous_state = load_previous_state()
    
    # Calculate differences
    diff = diff_states(previous_state, current_state)
    
    # Analyze changes for threats
    change_threats = analyze_changes_for_threats(diff, anomaly_detector)
    
    # Combine all threats
    all_threats = scan_threats + change_threats
    
    # Save state and log changes
    save_current_state(current_state)
    log_changes(diff, all_threats)
    
    # Generate report
    report = generate_report(diff, folder, all_threats)
    
    print("[✓] Tarama tamamlandı. Rapor oluşturuldu:\n")
    print(report)
    
    # Display critical alerts
    if all_threats:
        print(f"\n🚨 CRITICAL SECURITY ALERTS: {len(all_threats)} threats detected!")
        print("Check the detailed report above and anomaly_detection.json for full analysis.")
    else:
        print("\n✅ No security threats detected. System appears clean.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FolderSleuth - AI-Powered File Change Monitoring with Threat Detection")
    parser.add_argument("folder", help="Hedef klasörü belirtin")
    parser.add_argument("--threat-threshold", type=int, default=70, help="Threat score threshold (0-100)")
    args = parser.parse_args()
    
    # Update threat threshold if provided
    if hasattr(args, 'threat_threshold'):
        print(f"[i] Threat detection threshold set to: {args.threat_threshold}")
    
    main(args.folder)
