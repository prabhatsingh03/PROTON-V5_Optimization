import os
import sys
import mysql.connector
from dotenv import load_dotenv
import razorpay
from mysql.connector import Error

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

def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_PRIMARY_DATABASE,
            charset=MYSQL_CHARSET
        )
        return conn
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def sync_plans():
    # Initialize Razorpay client
    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    
    print("=" * 70)
    print("Fetching ALL Plans from Razorpay...")
    print("=" * 70)

    try:
        # Fetch all plans (default limit is usually 10, handle pagination if needed, but for now fetch all)
        # Razorpay .all() returns a dict with 'items' list
        response = client.plan.all({'count': 100}) 
        plans = response.get('items', [])
        
        print(f"Found {len(plans)} plans on Razorpay.\n")

        conn = get_db_connection()
        if not conn:
            return

        cursor = conn.cursor()
        
        # Ensure table exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS razorpay_plans (
                plan_type VARCHAR(191), 
                razorpay_plan_id VARCHAR(191) PRIMARY KEY,
                name VARCHAR(255),
                amount INTEGER,
                interval_type VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Note: Previous script created table with (plan_type PK, razorpay_plan_id). 
        # This might conflict. We should check schema or alter it.
        # For safety, let's stick to storing simplified mapping if possible, 
        # BUT the user wants to "Save to Database". 
        # Let's inspect the existing table first or be robust.
        
        # We will attempt to add columns if they accept it, or just work with what we have.
        # Ideally, we want to capture: ID, Name, Amount.
        
        # Let's just UPSERT based on Plan ID.
        
        for plan in plans:
            p_id = plan['id']
            p_name = plan['item']['name']
            p_amount = plan['item']['amount']
            p_period = plan['period']
            
            print(f"Processing: {p_name} ({p_id}) - Rs. {p_amount/100}")
            
            # Heuristic to determine 'plan_type' (basic, plus, pro) if matching name
            p_type = 'custom'
            if 'basic' in p_name.lower(): p_type = 'basic'
            elif 'plus' in p_name.lower(): p_type = 'plus'
            elif 'pro' in p_name.lower(): p_type = 'pro'
            
            # Check if exists
            cursor.execute("SELECT razorpay_plan_id FROM razorpay_plans WHERE razorpay_plan_id = %s", (p_id,))
            result = cursor.fetchone()
            
            if result:
                print(f"  -> Already exists in DB. Skipping.")
                # Optional: Update functionality
            else:
                try:
                    # Try inserting with the new schema (if we created it)
                    # If table was created by previous script, it only has plan_type and razorpay_plan_id. 
                    # We should handle that.
                    
                    # Check column names
                    cursor.execute("SHOW COLUMNS FROM razorpay_plans")
                    columns = [column[0] for column in cursor.fetchall()]
                    
                    if 'name' in columns:
                        query = """
                            INSERT INTO razorpay_plans (plan_type, razorpay_plan_id, name, amount, interval_type)
                            VALUES (%s, %s, %s, %s, %s)
                        """
                        cursor.execute(query, (p_type, p_id, p_name, p_amount, p_period))
                    else:
                        # Fallback to old schema
                        # But wait, existing schema PK is plan_type. 
                        # If we have multiple 'basic' plans, this will fail.
                        # We should probably ALTER table or handle it.
                        print("  [WARNING] Table schema uses 'plan_type' as PK. Creating unique variant.")
                        
                        unique_p_type = f"{p_type}_{p_id[-4:]}" # Hack to allow duplicates if PK is constrained
                        
                        # Check if plan_type already taken
                        cursor.execute("SELECT plan_type FROM razorpay_plans WHERE plan_type = %s", (p_type,))
                        if cursor.fetchone():
                             # If basic exists, use unique
                             query = "INSERT INTO razorpay_plans (plan_type, razorpay_plan_id) VALUES (%s, %s)"
                             cursor.execute(query, (unique_p_type, p_id))
                        else:
                             query = "INSERT INTO razorpay_plans (plan_type, razorpay_plan_id) VALUES (%s, %s)"
                             cursor.execute(query, (p_type, p_id))
                             
                    print(f"  -> SAVED to Database.")
                    conn.commit()
                except Error as err:
                    print(f"  [ERROR] DB Insert failed: {err}")

        print("\nSync Complete.")

    except Exception as e:
        print(f"\n[ERROR] Failed to fetch/sync plans: {e}")
    finally:
        if 'conn' in locals() and conn and conn.is_connected():
            conn.close()

if __name__ == "__main__":
    sync_plans()
