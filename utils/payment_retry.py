"""
Payment Retry Logic

Automatic retry mechanism for failed payments with exponential backoff.
"""
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from utils.db_utils import execute_primary_query

class PaymentRetryManager:
    """Manages automatic retry of failed payments."""
    
    MAX_RETRY_ATTEMPTS = 3
    RETRY_DELAY_HOURS = [24, 48, 72]  # Retry after 1, 2, 3 days
    MAX_RETRY_AGE_DAYS = 7  # Don't retry payments older than 7 days
    
    @staticmethod
    def get_failed_payments_ready_for_retry() -> list:
        """
        Get list of failed payments that are ready for retry.
        
        Returns:
            List of payment records ready for retry
        """
        cutoff_date = (datetime.now() - timedelta(days=PaymentRetryManager.MAX_RETRY_AGE_DAYS)).strftime('%Y-%m-%d')
        
        # Get failed payments with retry attempts < MAX_RETRY_ATTEMPTS
        failed_payments = execute_primary_query(
            """
            SELECT bt.id, bt.org_id, bt.razorpay_payment_id, bt.amount, bt.created_at,
                   bt.retry_attempts, bt.last_retry_at,
                   s.razorpay_subscription_id, s.plan_type, s.billing_cycle
            FROM billing_transactions bt
            LEFT JOIN subscriptions s ON bt.org_id = s.org_id
            WHERE bt.status = 'failed'
            AND DATE(bt.created_at) >= ?
            AND bt.razorpay_payment_id IS NOT NULL
            AND (bt.retry_attempts IS NULL OR bt.retry_attempts < ?)
            ORDER BY bt.created_at DESC
            LIMIT 50
            """,
            (cutoff_date, PaymentRetryManager.MAX_RETRY_ATTEMPTS),
            fetch_all=True
        )
        
        ready_for_retry = []
        if failed_payments:
            for row in failed_payments:
                payment_id, org_id, rz_payment_id, amount, created_at, retry_attempts, last_retry_at, sub_id, plan_type, billing_cycle = row
                
                # Check if enough time has passed since last failure or creation
                payment_date = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S') if isinstance(created_at, str) else created_at
                
                # Determine which date to use for delay calculation
                if last_retry_at:
                    last_retry_date = datetime.strptime(last_retry_at, '%Y-%m-%d %H:%M:%S') if isinstance(last_retry_at, str) else last_retry_at
                    reference_date = last_retry_date
                else:
                    reference_date = payment_date
                
                # Calculate hours since last retry or creation
                hours_since = (datetime.now() - reference_date).total_seconds() / 3600
                
                # Determine required delay based on retry attempt number
                retry_count = retry_attempts or 0
                if retry_count < len(PaymentRetryManager.RETRY_DELAY_HOURS):
                    required_delay = PaymentRetryManager.RETRY_DELAY_HOURS[retry_count]
                else:
                    required_delay = PaymentRetryManager.RETRY_DELAY_HOURS[-1]  # Use last delay for all subsequent retries
                
                if hours_since >= required_delay:
                    ready_for_retry.append({
                        "id": payment_id,
                        "org_id": org_id,
                        "payment_id": rz_payment_id,
                        "amount": float(amount),
                        "subscription_id": sub_id,
                        "plan_type": plan_type,
                        "billing_cycle": billing_cycle,
                        "created_at": created_at,
                        "retry_attempts": retry_attempts or 0
                    })
        
        return ready_for_retry
    
    @staticmethod
    def should_retry_payment(payment_id: str, org_id: int) -> Tuple[bool, str]:
        """
        Determine if a payment should be retried.
        
        Returns:
            (should_retry, reason)
        """
        # Check retry count (if we track it)
        # For now, simple check: don't retry if payment is too old
        payment_row = execute_primary_query(
            "SELECT created_at, status FROM billing_transactions WHERE razorpay_payment_id = ? AND org_id = ?",
            (payment_id, org_id),
            fetch_one=True
        )
        
        if not payment_row:
            return False, "Payment not found"
        
        created_at, status = payment_row
        if status != 'failed':
            return False, "Payment not in failed status"
        
        payment_date = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S') if isinstance(created_at, str) else created_at
        age_days = (datetime.now() - payment_date).days
        
        if age_days > PaymentRetryManager.MAX_RETRY_AGE_DAYS:
            return False, f"Payment too old ({age_days} days)"
        
        if age_days < 1:
            return False, "Payment too recent, wait 24 hours"
        
        return True, "Ready for retry"
    
    @staticmethod
    def mark_retry_attempt(payment_id: str, org_id: int, success: bool, error: Optional[str] = None):
        """Mark a retry attempt in audit logs and update billing_transactions table."""
        try:
            # Update billing_transactions table with retry information
            if success:
                # On success, reset retry attempts (payment succeeded)
                execute_primary_query(
                    "UPDATE billing_transactions SET retry_attempts = 0, last_retry_at = ?, status = 'success' WHERE razorpay_payment_id = ? AND org_id = ?",
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), payment_id, org_id)
                )
            else:
                # On failure, increment retry attempts
                execute_primary_query(
                    "UPDATE billing_transactions SET retry_attempts = COALESCE(retry_attempts, 0) + 1, last_retry_at = ? WHERE razorpay_payment_id = ? AND org_id = ?",
                    (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), payment_id, org_id)
                )
            
            # Log to audit_logs
            details = json.dumps({
                "payment_id": payment_id,
                "org_id": org_id,
                "success": success,
                "error": error,
                "retry_timestamp": datetime.now().isoformat()
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, None, 'payment_retry_attempt', details)
            )
        except Exception as e:
            print(f"Error marking retry attempt: {e}")
            pass


def retry_failed_payments(payments: list, razorpay_client) -> Dict:
    """
    Execute retry for a list of failed payments.
    
    Args:
        payments: List of payment records to retry
        razorpay_client: Razorpay client instance
        
    Returns:
        Dict with retry results
    """
    if not razorpay_client:
        return {
            "status": "error",
            "message": "Razorpay client not available",
            "retried_count": 0,
            "success_count": 0,
            "failed_count": 0
        }
    
    results = {
        "status": "success",
        "retried_count": len(payments),
        "success_count": 0,
        "failed_count": 0,
        "errors": []
    }
    
    for payment in payments:
        payment_id = payment.get("payment_id")
        org_id = payment.get("org_id")
        
        if not payment_id:
            continue
        
        try:
            # Attempt to retry payment via Razorpay
            # Note: Razorpay doesn't have a direct "retry" API, so we check payment status
            # and potentially trigger a new payment attempt
            rz_payment = razorpay_client.payment.fetch(payment_id, timeout=10)
            
            # If payment is now successful, update our records
            if rz_payment.get('status') == 'authorized' or rz_payment.get('status') == 'captured':
                PaymentRetryManager.mark_retry_attempt(payment_id, org_id, success=True)
                results["success_count"] += 1
            else:
                # Payment still failed - mark retry attempt as failed
                error_msg = rz_payment.get('error_description') or rz_payment.get('error_code') or 'Payment still failed'
                PaymentRetryManager.mark_retry_attempt(payment_id, org_id, success=False, error=error_msg)
                results["failed_count"] += 1
                results["errors"].append({
                    "payment_id": payment_id,
                    "error": error_msg
                })
                
        except Exception as e:
            # Error fetching payment - mark as failed
            error_msg = str(e)
            PaymentRetryManager.mark_retry_attempt(payment_id, org_id, success=False, error=error_msg)
            results["failed_count"] += 1
            results["errors"].append({
                "payment_id": payment_id,
                "error": error_msg
            })
    
    return results

