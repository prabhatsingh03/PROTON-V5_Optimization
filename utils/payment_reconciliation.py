"""
Payment Reconciliation System

Compares Razorpay API data with local database to identify discrepancies.
Helps ensure data integrity and catch missing or mismatched transactions.
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from utils.db_utils import execute_primary_query

def reconcile_payments(
    org_id: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    razorpay_client=None
) -> Dict:
    """
    Reconcile payments between Razorpay API and local database.
    
    Args:
        org_id: Organization ID to reconcile (None for all)
        start_date: Start date for reconciliation (YYYY-MM-DD)
        end_date: End date for reconciliation (YYYY-MM-DD)
        razorpay_client: Razorpay client instance
        
    Returns:
        Dict with reconciliation results including:
        - matched: Payments found in both systems
        - missing_in_db: Payments in Razorpay but not in DB
        - missing_in_razorpay: Payments in DB but not in Razorpay
        - mismatched: Payments with different amounts/statuses
        - summary: Summary statistics
    """
    if not razorpay_client:
        return {
            "status": "error",
            "message": "Razorpay client not available"
        }
    
    # Default to last 30 days if dates not provided
    if not end_date:
        end_date = datetime.now().strftime('%Y-%m-%d')
    if not start_date:
        start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    
    results = {
        "matched": [],
        "missing_in_db": [],
        "missing_in_razorpay": [],
        "mismatched": [],
        "summary": {
            "total_razorpay": 0,
            "total_db": 0,
            "matched_count": 0,
            "discrepancies": 0
        }
    }
    
    try:
        # Get payments from database
        if org_id:
            db_query = """
                SELECT razorpay_payment_id, amount, status, created_at, org_id
                FROM billing_transactions
                WHERE razorpay_payment_id IS NOT NULL
                AND org_id = ?
                AND DATE(created_at) BETWEEN ? AND ?
            """
            db_params = (org_id, start_date, end_date)
        else:
            db_query = """
                SELECT razorpay_payment_id, amount, status, created_at, org_id
                FROM billing_transactions
                WHERE razorpay_payment_id IS NOT NULL
                AND DATE(created_at) BETWEEN ? AND ?
            """
            db_params = (start_date, end_date)
        
        db_payments = execute_primary_query(db_query, db_params, fetch_all=True)
        db_payment_map = {}
        for row in db_payments or []:
            payment_id = row[0]
            db_payment_map[payment_id] = {
                "payment_id": payment_id,
                "amount": float(row[1]),
                "status": row[2],
                "created_at": row[3],
                "org_id": row[4]
            }
        
        results["summary"]["total_db"] = len(db_payment_map)
        
        # Get payments from Razorpay API with proper pagination
        razorpay_payments = {}
        try:
            # Fetch payments from Razorpay with pagination
            from_timestamp = int(datetime.strptime(start_date, '%Y-%m-%d').timestamp())
            to_timestamp = int(datetime.strptime(end_date, '%Y-%m-%d').timestamp())
            count_per_page = 100
            skip = 0
            has_more = True
            
            while has_more:
                payments = razorpay_client.payment.all({
                    "from": from_timestamp,
                    "to": to_timestamp,
                    "count": count_per_page,
                    "skip": skip
                }, timeout=30)  # Add timeout to prevent hanging
                
                items = payments.get('items', [])
                if not items:
                    has_more = False
                    break
                
                for payment in items:
                    payment_id = payment.get('id')
                    if payment_id:
                        razorpay_payments[payment_id] = {
                            "payment_id": payment_id,
                            "amount": payment.get('amount', 0) / 100.0,  # Convert paise to rupees
                            "status": payment.get('status', 'unknown'),
                            "created_at": datetime.fromtimestamp(payment.get('created_at', 0)).strftime('%Y-%m-%d %H:%M:%S'),
                            "order_id": payment.get('order_id'),
                            "subscription_id": payment.get('subscription_id')
                        }
                
                # Check if there are more pages
                # Razorpay returns items array - if length is less than count, we've reached the end
                if len(items) < count_per_page:
                    has_more = False
                else:
                    skip += count_per_page
                    
                # Safety limit to prevent infinite loops (max 10,000 payments)
                if skip >= 10000:
                    break
        except Exception as e:
            return {
                "status": "error",
                "message": f"Error fetching Razorpay payments: {str(e)}"
            }
        
        results["summary"]["total_razorpay"] = len(razorpay_payments)
        
        # Compare payments
        all_payment_ids = set(list(db_payment_map.keys()) + list(razorpay_payments.keys()))
        
        for payment_id in all_payment_ids:
            db_payment = db_payment_map.get(payment_id)
            rz_payment = razorpay_payments.get(payment_id)
            
            if db_payment and rz_payment:
                # Both exist - check for mismatches
                amount_diff = abs(db_payment["amount"] - rz_payment["amount"])
                status_match = db_payment["status"] == "success" and rz_payment["status"] == "authorized"
                
                if amount_diff > 0.01 or not status_match:  # Allow 1 paise tolerance
                    results["mismatched"].append({
                        "payment_id": payment_id,
                        "db_amount": db_payment["amount"],
                        "rz_amount": rz_payment["amount"],
                        "db_status": db_payment["status"],
                        "rz_status": rz_payment["status"],
                        "org_id": db_payment.get("org_id")
                    })
                    results["summary"]["discrepancies"] += 1
                else:
                    results["matched"].append({
                        "payment_id": payment_id,
                        "amount": db_payment["amount"],
                        "status": db_payment["status"],
                        "org_id": db_payment.get("org_id")
                    })
                    results["summary"]["matched_count"] += 1
            elif db_payment and not rz_payment:
                # In DB but not in Razorpay
                results["missing_in_razorpay"].append({
                    "payment_id": payment_id,
                    "amount": db_payment["amount"],
                    "status": db_payment["status"],
                    "org_id": db_payment.get("org_id")
                })
                results["summary"]["discrepancies"] += 1
            elif rz_payment and not db_payment:
                # In Razorpay but not in DB
                results["missing_in_db"].append({
                    "payment_id": payment_id,
                    "amount": rz_payment["amount"],
                    "status": rz_payment["status"],
                    "subscription_id": rz_payment.get("subscription_id")
                })
                results["summary"]["discrepancies"] += 1
        
        results["status"] = "success"
        return results
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Reconciliation error: {str(e)}"
        }

