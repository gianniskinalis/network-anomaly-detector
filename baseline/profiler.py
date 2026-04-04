import sqlite3
import os

DB_PATH = "data/baseline.db"

def init_db():
    """Create the database and flows table if they don't exist."""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip              TEXT,
            dst_ip              TEXT,
            src_port            INTEGER,
            dst_port            INTEGER,
            protocol            TEXT,
            duration            REAL,
            packet_count        INTEGER,
            total_bytes         INTEGER,
            avg_packet_size     REAL,
            avg_inter_arrival   REAL,
            unique_dst_ports    INTEGER,
            syn_count           INTEGER,
            timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print(f"[*] Database initialised")


def store_flows(feature_records):
    """Store extracted flow features into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for f in feature_records:
        cursor.execute("""
            INSERT INTO flows (
                src_ip, dst_ip, src_port, dst_port, protocol,
                duration, packet_count, total_bytes,
                avg_packet_size, avg_inter_arrival,
                unique_dst_ports, syn_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol"],
            f["duration"], f["packet_count"], f["total_bytes"],
            f["avg_packet_size"], f["avg_inter_arrival"],
            f["unique_dst_ports"], f["syn_count"]
        ))

    conn.commit()
    conn.close()
    print(f"[*] Stored {len(feature_records)} flows into database")


def load_flows():
    """Load all flows from the  database as a list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM flows")
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    conn.close()

    flows = [dict(zip(columns, row)) for row in rows]
    print(f"[*] Loaded {len(flows)} flows from database")
    return flows
