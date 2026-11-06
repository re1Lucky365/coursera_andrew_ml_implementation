https://www.tiktok.com/@hilarysaurusrex?_r=1&_t=ZP-9BANEKfu9i3
concurrent.futures.ProcessPoolExecutor
import os
import sqlite3
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# --- LOGGING CONFIGURATION ---
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "multi_drive_indexer.log"

logger = logging.getLogger("DriveIndexer")
logger.setLevel(logging.INFO)

# Rotate logs: Max 5 files, 2MB each
log_handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5)
log_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)

# Console Output Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)


class RecoveryDatabase:
    """SQLite Database manager for tracking assets across multiple storage drives."""
    
    def __init__(self, db_path="recovery_index.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        # Enable Write-Ahead Logging (WAL) mode for concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        """Creates tables, performance indexes, and audit logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Storage Drives Registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS drives (
                    drive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    volume_label TEXT NOT NULL UNIQUE,
                    drive_type TEXT,
                    created_at_utc TEXT NOT NULL
                )
            """)
            
            # Table 2: Multi-Drive File Index
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_index (
                    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_id INTEGER NOT NULL,
                    relative_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    FOREIGN KEY (drive_id) REFERENCES drives (drive_id),
                    UNIQUE(drive_id, relative_path)
                )
            """)
            
            # Performance Indexes for high-frequency lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_index(sha256_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_index(relative_path);")
            
            # Table 3: Scan Audit Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_id INTEGER NOT NULL,
                    scan_timestamp_utc TEXT NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    FOREIGN KEY (drive_id) REFERENCES drives (drive_id)
                )
            """)
            conn.commit()
            logger.info(f"Database initialized and optimized with WAL mode at: {self.db_path}")

    def register_or_get_drive(self, volume_label, drive_type="External/Local"):
        """Registers a storage drive or fetches its drive_id."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT drive_id FROM drives WHERE volume_label = ?", (volume_label,))
            row = cursor.fetchone()
            if row:
                return row[0]
            
            cursor.execute(
                "INSERT INTO drives (volume_label, drive_type, created_at_utc) VALUES (?, ?, ?)",
                (volume_label, drive_type, now_utc)
            )
            conn.commit()
            logger.info(f"Registered new storage drive: [{volume_label}]")
            return cursor.lastrowid

    def upsert_file_record(self, drive_id, relative_path, sha256_hash, size_bytes):
        """Inserts or updates a file metadata record."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO file_index (drive_id, relative_path, sha256_hash, size_bytes, last_seen_utc)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(drive_id, relative_path) DO UPDATE SET
                    sha256_hash=excluded.sha256_hash,
                    size_bytes=excluded.size_bytes,
                    last_seen_utc=excluded.last_seen_utc
            """, (drive_id, relative_path, sha256_hash, size_bytes, now_utc))
            conn.commit()

    def record_scan_audit(self, drive_id, files_count):
        """Records a completed scan event in the audit table."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (drive_id, scan_timestamp_utc, files_scanned)
                VALUES (?, ?, ?)
            """, (drive_id, now_utc, files_count))
            conn.commit()

    def find_global_duplicates(self):
        """Finds files with identical SHA-256 hashes existing across different drives or paths."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.sha256_hash, f.size_bytes, GROUP_CONCAT(d.volume_label || ':' || f.relative_path, ' | ') as locations
                FROM file_index f
                JOIN drives d ON f.drive_id = d.drive_id
                WHERE f.sha256_hash != 'READ_ERROR'
                GROUP BY f.sha256_hash, f.size_bytes
                HAVING COUNT(*) > 1
                ORDER BY f.size_bytes DESC;
            """)
            return cursor.fetchall()


def calculate_sha256(file_path, chunk_size=8192):
    """Computes SHA-256 hash in binary chunks."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return "READ_ERROR"


def scan_and_index_drive(target_dir, volume_label, db_manager):
    """Scans target directory and syncs metadata into the SQLite database."""
    target_path = Path(target_dir).resolve()
    logger.info(f"Starting scan on Drive [{volume_label}] at path: {target_path}")
    
    drive_id = db_manager.register_or_get_drive(volume_label)
    processed_count = 0

    for root, _, files in os.walk(target_path):
        # Ignore system folders and internal logs
        if any(ignored in root for ignored in [".git", "logs", "backups"]):
            continue
            
        for file in files:
            full_path = Path(root) / file
            rel_path = str(full_path.relative_to(target_path))
            
            file_hash = calculate_sha256(full_path)
            file_size = full_path.stat().st_size if file_hash != "READ_ERROR" else 0
            
            db_manager.upsert_file_record(drive_id, rel_path, file_hash, file_size)
            processed_count += 1

    db_manager.record_scan_audit(drive_id, processed_count)
    logger.info(f"Scan completed for Drive [{volume_label}]. Total records synced: {processed_count}")


if __name__ == "__main__":
    # Initialize SQLite recovery database with WAL and indexing
    db = RecoveryDatabase(db_path="recovery_index.db")
    
    # 1. Scan primary working workspace
    scan_and_index_drive(
        target_dir="./",
        volume_label="PRIMARY_WORKSPACE_NVME",
        db_manager=db
    )

    # 2. Example: Find and display global duplicate files across indexed drives
    print("\n[*] Scanning for global duplicates across indexed drives...")
    duplicates = db.find_global_duplicates()
    if duplicates:
        print(f"[+] Found {len(duplicates)} sets of duplicate files:")
        for dup in duplicates:
            print(f"  - Size: {dup[1]} bytes | Locations: {dup[2]}")
    else:
        print("[-] No duplicates found.")
import os
import sqlite3
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# --- LOGGING CONFIGURATION ---
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "multi_drive_indexer.log"

logger = logging.getLogger("DriveIndexer")
logger.setLevel(logging.INFO)

# Rotate logs: Max 5 files, 2MB each
log_handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5)
log_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)

# Console Output Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)


class RecoveryDatabase:
    """SQLite Database manager for tracking assets across multiple storage drives."""
    
    def __init__(self, db_path="recovery_index.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        # Enable Write-Ahead Logging (WAL) mode for concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        """Creates tables, performance indexes, and audit logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Storage Drives Registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS drives (
                    drive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    volume_label TEXT NOT NULL UNIQUE,
                    drive_type TEXT,
                    created_at_utc TEXT NOT NULL
                )
            """)
            
            # Table 2: Multi-Drive File Index
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_index (
                    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_id INTEGER NOT NULL,
                    relative_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    FOREIGN KEY (drive_id) REFERENCES drives (drive_id),
                    UNIQUE(drive_id, relative_path)
                )
            """)
            
            # Performance Indexes for high-frequency lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_index(sha256_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_index(relative_path);")
            
            # Table 3: Scan Audit Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_id INTEGER NOT NULL,
                    scan_timestamp_utc TEXT NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    FOREIGN KEY (drive_id) REFERENCES drives (drive_id)
                )
            """)
            conn.commit()
            logger.info(f"Database initialized and optimized with WAL mode at: {self.db_path}")

    def register_or_get_drive(self, volume_label, drive_type="External/Local"):
        """Registers a storage drive or fetches its drive_id."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT drive_id FROM drives WHERE volume_label = ?", (volume_label,))
            row = cursor.fetchone()
            if row:
                return row[0]
            
            cursor.execute(
                "INSERT INTO drives (volume_label, drive_type, created_at_utc) VALUES (?, ?, ?)",
                (volume_label, drive_type, now_utc)
            )
            conn.commit()
            logger.info(f"Registered new storage drive: [{volume_label}]")
            return cursor.lastrowid

    def upsert_file_record(self, drive_id, relative_path, sha256_hash, size_bytes):
        """Inserts or updates a file metadata record."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO file_index (drive_id, relative_path, sha256_hash, size_bytes, last_seen_utc)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(drive_id, relative_path) DO UPDATE SET
                    sha256_hash=excluded.sha256_hash,
                    size_bytes=excluded.size_bytes,
                    last_seen_utc=excluded.last_seen_utc
            """, (drive_id, relative_path, sha256_hash, size_bytes, now_utc))
            conn.commit()

    def record_scan_audit(self, drive_id, files_count):
        """Records a completed scan event in the audit table."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_logs (drive_id, scan_timestamp_utc, files_scanned)
                VALUES (?, ?, ?)
            """, (drive_id, now_utc, files_count))
            conn.commit()

    def find_global_duplicates(self):
        """Finds files with identical SHA-256 hashes existing across different drives or paths."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT f.sha256_hash, f.size_bytes, GROUP_CONCAT(d.volume_label || ':' || f.relative_path, ' | ') as locations
                FROM file_index f
                JOIN drives d ON f.drive_id = d.drive_id
                WHERE f.sha256_hash != 'READ_ERROR'
                GROUP BY f.sha256_hash, f.size_bytes
                HAVING COUNT(*) > 1
                ORDER BY f.size_bytes DESC;
            """)
            return cursor.fetchall()


def calculate_sha256(file_path, chunk_size=8192):
    """Computes SHA-256 hash in binary chunks."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return "READ_ERROR"


def scan_and_index_drive(target_dir, volume_label, db_manager):
    """Scans target directory and syncs metadata into the SQLite database."""
    target_path = Path(target_dir).resolve()
    logger.info(f"Starting scan on Drive [{volume_label}] at path: {target_path}")
    
    drive_id = db_manager.register_or_get_drive(volume_label)
    processed_count = 0

    for root, _, files in os.walk(target_path):
        # Ignore system folders and internal logs
        if any(ignored in root for ignored in [".git", "logs", "backups"]):
            continue
            
        for file in files:
            full_path = Path(root) / file
            rel_path = str(full_path.relative_to(target_path))
            
            file_hash = calculate_sha256(full_path)
            file_size = full_path.stat().st_size if file_hash != "READ_ERROR" else 0
            
            db_manager.upsert_file_record(drive_id, rel_path, file_hash, file_size)
            processed_count += 1

    db_manager.record_scan_audit(drive_id, processed_count)
    logger.info(f"Scan completed for Drive [{volume_label}]. Total records synced: {processed_count}")


if __name__ == "__main__":
    # Initialize SQLite recovery database with WAL and indexing
    db = RecoveryDatabase(db_path="recovery_index.db")
    
    # 1. Scan primary working workspace
    scan_and_index_drive(
        target_dir="./",
        volume_label="PRIMARY_WORKSPACE_NVME",
        db_manager=db
    )

    # 2. Example: Find and display global duplicate files across indexed drives
    print("\n[*] Scanning for global duplicates across indexed drives...")
    duplicates = db.find_global_duplicates()
    if duplicates:
        print(f"[+] Found {len(duplicates)} sets of duplicate files:")
        for dup in duplicates:
            print(f"  - Size: {dup[1]} bytes | Locations: {dup[2]}")
    else:
        print("[-] No duplicates found.")
Here is the fully integrated, production-ready version of your multi_drive_indexer.py script. It combines the original multi-drive SQLite indexing architecture with WAL mode, performance indexes, the duplicate detection query method, and WAL/Index initialization directly inside the database startup routines.
Complete Integrated Multi-Drive Indexer (multi_drive_indexer.py)
import os
import sqlite3
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# --- LOGGING CONFIGURATION ---
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "multi_drive_indexer.log"

logger = logging.getLogger("DriveIndexer")
logger.setLevel(logging.INFO)

# Rotate logs: Max 5 files, 2MB each
log_handler = RotatingFileHandler(LOG_FILE, maxBytes=2_000_000, backupCount=5)
log_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)

# Console Output Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)


class RecoveryDatabase:
    """SQLite Database manager for tracking assets across multiple storage drives."""
    
    def __init__(self, db_path="recovery_index.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        # Enable Write-Ahead Logging (WAL) mode for concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        """Creates tables, performance indexes, and audit logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Table 1: Storage Drives Registry
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS drives (
                    drive_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    volume_label TEXT NOT NULL UNIQUE,
                    drive_type TEXT,
                    created_at_utc TEXT NOT NULL
                )
            """)
            
            # Table 2: Multi-Drive File Index
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS file_index (
                    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    drive_id INTEGER NOT NULL,
                    relative_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    last_seen_utc TEXT NOT NULL,
                    FOREIGN KEY (drive_id) REFERENCES drives (drive_id),
                    UNIQUE(drive_id, relative_path)
                )
            """)
            
            # Performance Indexes for high-frequency lookups
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON file_index(sha256_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_path ON file_index(relative_path);")
            
            # Table 3: Scan Audit Log
            cursor.
# coursera_andrew_ml_implementation
1. The code is to practise Andrew's ML course's code exercises
2. All the codes have passed course's code valiation. In general, 80% or more is achieved.

Brief introduction
* Week 2 - Linear regression
* Week 3 - Logistic regression
* Week 4 - Neural network
* Week 5 - Neural network2
* Week 6 - Bias & Variance trade off, and general ML validation framework
* Week 7 - SVM
* Week 8 - PCA
* Week 9 - Anomaly detection

Code running environment
[Octave](https://www.gnu.org/software/octave/index)

Reference
[course link](https://www.coursera.org/learn/machine-learning)
sincerely 
Robert Edward Evans 