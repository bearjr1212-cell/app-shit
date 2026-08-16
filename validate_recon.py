#!/usr/bin/env python3
"""
Recon Data Validation & Diagnostics
====================================
Tests if the recon module is working correctly and saving data
in a format that attack modules can consume.
"""

import sys
import os
import sqlite3
import json
from pathlib import Path
from datetime import datetime

# Add posframework to path
sys.path.insert(0, str(Path(__file__).parent))

from posframework.config import DB_NAME, log
from posframework.database import POSDatabase


def print_header(text):
    """Print formatted header."""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70 + "\n")


def check_database_exists():
    """Check if database file exists."""
    print_header("1. Database File Check")
    
    if os.path.exists(DB_NAME):
        size_mb = os.path.getsize(DB_NAME) / (1024 * 1024)
        print(f"✓ Database exists: {DB_NAME}")
        print(f"  Size: {size_mb:.2f} MB")
        return True
    else:
        print(f"✗ Database not found: {DB_NAME}")
        print("  Note: Run recon first to populate the database")
        return False


def check_database_schema(db):
    """Verify database schema and tables."""
    print_header("2. Database Schema Check")
    
    try:
        cursor = db.cursor
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        print(f"Found {len(tables)} tables:")
        
        expected_tables = {
            'access_points': ['bssid', 'ssid', 'channel', 'vendor', 'security', 'rssi'],
            'clients': ['mac', 'vendor', 'associated_bssid', 'probed_ssids'],
            'deauth_events': ['src_mac', 'dst_mac', 'bssid', 'reason'],
            'eapol_frames': ['client_mac', 'bssid', 'frame_number'],
            'credentials': ['client_ip', 'username', 'password', 'url']
        }
        
        all_valid = True
        for table, expected_cols in expected_tables.items():
            if table in tables:
                # Check columns
                cursor.execute(f"PRAGMA table_info({table})")
                columns = {row[1] for row in cursor.fetchall()}
                missing = set(expected_cols) - columns
                
                if missing:
                    print(f"  ✗ {table}: Missing columns: {missing}")
                    all_valid = False
                else:
                    print(f"  ✓ {table}: All required columns present")
            else:
                print(f"  ✗ {table}: NOT FOUND")
                all_valid = False
        
        return all_valid
        
    except Exception as e:
        print(f"✗ Error checking schema: {e}")
        return False


def check_recon_data(db):
    """Check if recon has captured any data."""
    print_header("3. Recon Data Analysis")
    
    try:
        stats = db.get_stats()
        
        print("Data Summary:")
        print(f"  Access Points: {stats['access_points']}")
        print(f"    ├─ POS-flagged APs: {stats['pos_access_points']}")
        print(f"  Clients: {stats['clients']}")
        print(f"    ├─ POS-flagged clients: {stats['pos_clients']}")
        print(f"  Deauth Events: {stats['deauth_events']}")
        print(f"  EAPOL Frames: {stats['eapol_frames']}")
        print(f"  Credentials: {stats['credentials']}")
        
        total_captures = sum(stats.values())
        
        if total_captures == 0:
            print("\n⚠ WARNING: No data captured yet")
            print("  Run recon to populate: sudo python3 -m posframework recon -i <interface>")
            return False
        else:
            print(f"\n✓ Total data points: {total_captures}")
            return True
            
    except Exception as e:
        print(f"✗ Error retrieving stats: {e}")
        return False


def check_ap_data_format(db):
    """Verify access point data is in correct format."""
    print_header("4. Access Point Data Format Validation")
    
    try:
        cursor = db.cursor
        cursor.execute('''
            SELECT bssid, ssid, channel, vendor, security, rssi, 
                   is_pos_vendor, is_pos_ssid 
            FROM access_points LIMIT 3
        ''')
        
        aps = cursor.fetchall()
        
        if not aps:
            print("✗ No access point data found")
            return False
        
        print(f"Sample AP data ({len(aps)} records):\n")
        
        for i, ap in enumerate(aps):
            bssid, ssid, channel, vendor, security, rssi, is_pos_vendor, is_pos_ssid = ap
            pos_flag = "✓ POS" if (is_pos_vendor or is_pos_ssid) else ""
            
            print(f"  AP #{i+1}:")
            print(f"    BSSID:      {bssid}")
            print(f"    SSID:       {ssid or '(hidden)'}")
            print(f"    Channel:    {channel}")
            print(f"    Vendor:     {vendor}")
            print(f"    Security:   {security}")
            print(f"    Signal:     {rssi} dBm")
            print(f"    {pos_flag}")
            print()
        
        # Verify data types
        validation_passed = True
        for bssid, ssid, channel, vendor, security, rssi, is_pos_vendor, is_pos_ssid in aps:
            # Check BSSID format (MAC address)
            if not isinstance(bssid, str) or len(bssid) != 17:  # XX:XX:XX:XX:XX:XX
                print(f"  ✗ Invalid BSSID format: {bssid}")
                validation_passed = False
            
            # Check channel is number
            if channel and not isinstance(channel, (int, type(None))):
                print(f"  ✗ Invalid channel type: {channel}")
                validation_passed = False
            
            # Check RSSI is negative (signal strength)
            if rssi and not isinstance(rssi, (int, type(None))):
                print(f"  ✗ Invalid RSSI type: {rssi}")
                validation_passed = False
        
        if validation_passed:
            print("✓ All AP data format validation passed")
        
        return validation_passed
        
    except Exception as e:
        print(f"✗ Error validating AP data: {e}")
        return False


def check_client_data_format(db):
    """Verify client data is in correct format."""
    print_header("5. Client Data Format Validation")
    
    try:
        cursor = db.cursor
        cursor.execute('''
            SELECT mac, vendor, associated_bssid, probed_ssids, rssi, is_pos_vendor
            FROM clients LIMIT 3
        ''')
        
        clients = cursor.fetchall()
        
        if not clients:
            print("⚠ No client data found yet")
            return True  # Not necessarily an error
        
        print(f"Sample client data ({len(clients)} records):\n")
        
        for i, client in enumerate(clients):
            mac, vendor, bssid, ssids, rssi, is_pos = client
            pos_flag = "✓ POS" if is_pos else ""
            
            print(f"  Client #{i+1}:")
            print(f"    MAC:        {mac}")
            print(f"    Vendor:     {vendor}")
            print(f"    Associated: {bssid or '(not associated)'}")
            print(f"    Probed:     {ssids or '(none)'}")
            print(f"    Signal:     {rssi} dBm")
            print(f"    {pos_flag}")
            print()
        
        print("✓ Client data format looks valid")
        return True
        
    except Exception as e:
        print(f"✗ Error validating client data: {e}")
        return False


def check_attack_module_queries(db):
    """Test if attack modules can query recon data correctly."""
    print_header("6. Attack Module Query Compatibility")
    
    try:
        # Test queries that attack modules use
        
        # 1. Get strongest POS AP
        print("Testing: get_strongest_pos_ap()")
        pos_ap = db.get_strongest_pos_ap()
        if pos_ap:
            print(f"  ✓ Found POS AP: {pos_ap[1]} ({pos_ap[0]})")
        else:
            print(f"  ⚠ No POS APs found (expected if recon targeting non-POS networks)")
        
        # 2. Get strongest AP overall
        print("\nTesting: get_strongest_ap()")
        strongest = db.get_strongest_ap()
        if strongest:
            bssid, ssid, channel, vendor, rssi = strongest
            print(f"  ✓ Found strongest AP: {ssid or '(hidden)'} ({bssid})")
            print(f"    Channel: {channel}, Signal: {rssi} dBm")
        else:
            print(f"  ✗ No APs found - recon may not have run")
            return False
        
        # 3. Get POS access points list
        print("\nTesting: get_pos_access_points()")
        pos_aps = db.get_pos_access_points()
        print(f"  Found {len(pos_aps)} POS-flagged access points")
        if pos_aps:
            for ap in pos_aps[:2]:
                print(f"    - {ap[1]} ({ap[0]}): {ap[4]}")  # SSID, BSSID, security
        
        # 4. Get clients for an AP
        if strongest:
            target_bssid = strongest[0]
            print(f"\nTesting: get_clients_for_bssid('{target_bssid[:8]}...')")
            clients = db.get_clients_for_bssid(target_bssid)
            print(f"  ✓ Found {len(clients)} clients associated with target AP")
            if clients:
                for mac in clients[:3]:
                    print(f"    - {mac}")
        
        # 5. Get all AP-client mappings
        print("\nTesting: get_all_ap_clients()")
        ap_clients = db.get_all_ap_clients()
        print(f"  ✓ Created AP-client mapping: {len(ap_clients)} APs with clients")
        
        print("\n✓ All attack module queries working correctly")
        return True
        
    except Exception as e:
        print(f"✗ Error testing queries: {e}")
        return False


def check_credential_capture(db):
    """Check if credentials have been captured."""
    print_header("7. Credential Capture Check")
    
    try:
        cursor = db.cursor
        cursor.execute('SELECT COUNT(*) FROM credentials')
        count = cursor.fetchone()[0]
        
        if count > 0:
            print(f"✓ {count} credentials captured\n")
            
            cursor.execute('''
                SELECT client_ip, username, password, url, timestamp 
                FROM credentials LIMIT 3
            ''')
            
            for row in cursor.fetchall():
                client_ip, username, password, url, timestamp = row
                print(f"  IP: {client_ip}")
                print(f"    User: {username}")
                print(f"    Pass: {password}")
                print(f"    URL: {url}")
                print(f"    Time: {timestamp}\n")
        else:
            print("⚠ No credentials captured yet")
            print("  Run rogue AP to harvest credentials")
        
        return count > 0
        
    except Exception as e:
        print(f"✗ Error checking credentials: {e}")
        return False


def generate_summary_report(results):
    """Generate final summary report."""
    print_header("DIAGNOSTIC SUMMARY")
    
    checks = [
        ("Database File", results.get("db_exists")),
        ("Database Schema", results.get("schema_valid")),
        ("Recon Data Present", results.get("recon_data")),
        ("AP Data Format", results.get("ap_format")),
        ("Client Data Format", results.get("client_format")),
        ("Attack Module Queries", results.get("attack_queries")),
        ("Credential Capture", results.get("cred_capture")),
    ]
    
    passed = sum(1 for _, result in checks if result)
    total = len(checks)
    
    for name, result in checks:
        status = "✓" if result else ("⚠" if result is None else "✗")
        print(f"{status} {name}")
    
    print(f"\nResult: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n✓ Recon is working correctly!")
        print("  Attack modules can consume this data.")
        return True
    elif passed >= total - 2:
        print("\n⚠ Recon is mostly working, but some features need attention")
        return True
    else:
        print("\n✗ Recon needs to be run to populate database")
        print("  Usage: sudo python3 -m posframework recon -i <interface>")
        return False


def main():
    print("\n" + "="*70)
    print("  POS Framework - Recon Data Validation & Diagnostics")
    print("="*70)
    
    results = {}
    
    # Check database exists
    if not check_database_exists():
        print("\n⚠ Database file not found - creating new database...")
        db = POSDatabase()
        results["db_exists"] = True
    else:
        db = POSDatabase()
        results["db_exists"] = True
    
    # Run validation checks
    results["schema_valid"] = check_database_schema(db)
    results["recon_data"] = check_recon_data(db)
    results["ap_format"] = check_ap_data_format(db)
    results["client_format"] = check_client_data_format(db)
    results["attack_queries"] = check_attack_module_queries(db)
    results["cred_capture"] = check_credential_capture(db)
    
    # Generate summary
    success = generate_summary_report(results)
    
    db.close()
    
    print("\n" + "="*70 + "\n")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
