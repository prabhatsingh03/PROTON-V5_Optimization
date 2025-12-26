#!/usr/bin/env python3
"""
Create all Razorpay plans (Basic, Plus, Pro) and store them in the MySQL database.
This script uses the configured MySQL connection from config.py.
"""

import os
import sys
import mysql.connector
from dotenv import load_dotenv
import razorpay

# Ensure we can import from local directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import (
    MYSQL_HOST,
    MYSQL_PORT,
    MYSQL_USER,
    MYSQL_PASSWORD,
    MYSQL_PRIMARY_DATABASE,
    MYSQL_CHARSET
)

load_dotenv()

RAZORPAY_KEY_ID = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    print("[ERROR] RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET must be set in .env file")
    exit(1)

# Initialize Razorpay client
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Plan configurations (amounts in paise)
PLANS = {
    'basic': {
        'period': 'monthly',
        'interval': 1,
        'item': {
            'name': 'PROTON Basic Plan',
            'amount': 170000,  # Rs.1,700
            'currency': 'INR',
            'description': '1 project, up to 5 admins (Rs.500/extra admin), 20 files/project, 10 AI prompts/week'
        }
    },
    'plus': {
        'period': 'monthly',
        'interval': 1,
        'item': {
            'name': 'PROTON Plus Plan',
            'amount': 260000,  # Rs.2,600
            'currency': 'INR',
            'description': '10 projects, up to 10 admins (Rs.500/extra admin), 100 files/project, 100 AI prompts/week, S-Curve dashboards'
        }
    },
    'pro': {
        'period': 'monthly',
        'interval': 1,
        'item': {
            'name': 'PROTON Pro Plan',
            'amount': 430000,  # Rs.4,300
            'currency': 'INR',
            'description': 'Unlimited projects/admins/files/prompts (custom pricing beyond 100 users), SSO, API access, audit logs'
        }
    }
}

print("=" * 70)
print("Creating Razorpay Plans for PROTON (MySQL Backend)")
print("=" * 70)
print(f"\nKey ID: {RAZORPAY_KEY_ID[:15]}...")
print("[OK] Razorpay client initialized\n")

created_plans = {}
failed_plans = []

# Create each plan
for plan_type, plan_data in PLANS.items():
    print("-" * 70)
    print(f"Creating {plan_type.upper()} plan...")
    print(f"  Name: {plan_data['item']['name']}")
    print(f"  Amount: Rs.{plan_data['item']['amount']/100} ({plan_data['item']['amount']} paise)")
    print("-" * 70)
    
    try:
        result = client.plan.create(plan_data)
        plan_id = result.get('id')
        created_plans[plan_type] = plan_id
        print(f"[OK] SUCCESS! Plan ID: {plan_id}\n")
    except razorpay.errors.BadRequestError as e:
        error_msg = str(e)
        print(f"[ERROR] {error_msg}")
        # Check if plan already exists
        if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
            print(f"[WARNING] Plan might already exist. Check Razorpay Dashboard.")
        failed_plans.append((plan_type, error_msg))
        print()
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        failed_plans.append((plan_type, str(e)))
        print()

# Store in database
if created_plans:
    print("=" * 70)
    print("Storing Plan IDs in MySQL database...")
    print("=" * 70)
    
    conn = None
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_PRIMARY_DATABASE,
            charset=MYSQL_CHARSET
        )
        cur = conn.cursor()
        
        # Create table if not exists
        cur.execute("CREATE TABLE IF NOT EXISTS razorpay_plans (plan_type VARCHAR(191) PRIMARY KEY, razorpay_plan_id TEXT)")
        
        for plan_type, plan_id in created_plans.items():
            # Use MySQL upsert syntax
            query = """
                INSERT INTO razorpay_plans (plan_type, razorpay_plan_id) 
                VALUES (%s, %s) 
                ON DUPLICATE KEY UPDATE razorpay_plan_id = VALUES(razorpay_plan_id)
            """
            cur.execute(query, (plan_type, plan_id))
            print(f"[OK] Stored {plan_type}: {plan_id}")
        
        conn.commit()
        print("\n[OK] All plan IDs stored in database!")
        
    except Exception as e:
        print(f"\n[ERROR] Error storing in database: {e}")
        print("\nYou can manually store them using:")
        for plan_type, plan_id in created_plans.items():
            print(f"  INSERT INTO razorpay_plans (plan_type, razorpay_plan_id) VALUES ('{plan_type}', '{plan_id}');")
    finally:
        if conn and conn.is_connected():
            if cur:
                cur.close()
            conn.close()

# Summary
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"\n[OK] Successfully created/synced: {len(created_plans)} plan(s)")
for plan_type, plan_id in created_plans.items():
    print(f"   - {plan_type}: {plan_id}")

if failed_plans:
    print(f"\n[ERROR] Failed/Skipped: {len(failed_plans)} plan(s)")
    for plan_type, error in failed_plans:
        print(f"   - {plan_type}: {error}")

if created_plans:
    print("\n" + "=" * 70)
    print("[OK] NEXT STEPS:")
    print("=" * 70)
    print("1. Restart your Flask application")
    print("2. Test subscription creation")
    print("3. Verify plans in Razorpay Dashboard:")
    print("   https://dashboard.razorpay.com/app/plans")
    print("\n" + "=" * 70)
