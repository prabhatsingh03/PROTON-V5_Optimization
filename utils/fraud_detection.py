"""
Fraud Detection System

Basic fraud detection rules for payment transactions.
Detects suspicious patterns and flags potential fraud attempts.
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from utils.db_utils import execute_primary_query

class FraudDetector:
    """Detects potential fraud in payment transactions."""
    
    # Risk thresholds
    MAX_AMOUNT_DEVIATION_PERCENT = 10  # 10% deviation from expected
    MAX_RAPID_PAYMENTS = 5  # Max payments in 1 hour
    MAX_FAILED_ATTEMPTS = 3  # Max failed payment attempts in 1 hour
    
    @staticmethod
    def check_amount_anomaly(
        expected_amount: float,
        actual_amount: float,
        org_id: int
    ) -> Tuple[bool, str]:
        """
        Check if payment amount deviates significantly from expected.
        
        Returns:
            (is_fraud, reason)
        """
        if expected_amount == 0:
            return False, ""
        
        deviation = abs(actual_amount - expected_amount) / expected_amount * 100
        
        if deviation > FraudDetector.MAX_AMOUNT_DEVIATION_PERCENT:
            return True, f"Amount deviation {deviation:.2f}% exceeds threshold"
        
        return False, ""
    
    @staticmethod
    def check_rapid_payments(
        org_id: int,
        payment_id: str,
        time_window_hours: int = 1
    ) -> Tuple[bool, str]:
        """
        Check for rapid payment attempts (potential card testing).
        
        Returns:
            (is_fraud, reason)
        """
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        
        count_row = execute_primary_query(
            """
            SELECT COUNT(*) FROM billing_transactions
            WHERE org_id = ?
            AND created_at >= ?
            AND razorpay_payment_id != ?
            """,
            (org_id, cutoff_time.strftime('%Y-%m-%d %H:%M:%S'), payment_id),
            fetch_one=True
        )
        
        count = count_row[0] if count_row else 0
        
        if count >= FraudDetector.MAX_RAPID_PAYMENTS:
            return True, f"Rapid payment attempts: {count} in {time_window_hours} hour(s)"
        
        return False, ""
    
    @staticmethod
    def check_failed_attempts_pattern(
        org_id: int,
        time_window_hours: int = 1
    ) -> Tuple[bool, str]:
        """
        Check for pattern of failed payment attempts.
        
        Returns:
            (is_fraud, reason)
        """
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        
        count_row = execute_primary_query(
            """
            SELECT COUNT(*) FROM billing_transactions
            WHERE org_id = ?
            AND status = 'failed'
            AND created_at >= ?
            """,
            (org_id, cutoff_time.strftime('%Y-%m-%d %H:%M:%S')),
            fetch_one=True
        )
        
        count = count_row[0] if count_row else 0
        
        if count >= FraudDetector.MAX_FAILED_ATTEMPTS:
            return True, f"Multiple failed attempts: {count} in {time_window_hours} hour(s)"
        
        return False, ""
    
    @staticmethod
    def check_cross_org_verification_attempts(
        user_id: int,
        org_id: int,
        time_window_hours: int = 1
    ) -> Tuple[bool, str]:
        """
        Check for attempts to verify payments for different organizations.
        
        Returns:
            (is_fraud, reason)
        """
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        
        count_row = execute_primary_query(
            """
            SELECT COUNT(*) FROM audit_logs
            WHERE user_id = ?
            AND action = 'subscription_cross_org_verification_attempt'
            AND timestamp >= ?
            """,
            (user_id, cutoff_time.strftime('%Y-%m-%d %H:%M:%S')),
            fetch_one=True
        )
        
        count = count_row[0] if count_row else 0
        
        if count > 0:
            return True, f"Cross-org verification attempts detected: {count}"
        
        return False, ""
    
    @staticmethod
    def analyze_payment(
        org_id: int,
        user_id: Optional[int],
        payment_id: str,
        expected_amount: float,
        actual_amount: float
    ) -> Dict:
        """
        Comprehensive fraud analysis for a payment.
        
        Returns:
            Dict with fraud_score (0-100) and risk_factors list
        """
        risk_factors = []
        fraud_score = 0
        
        # Check amount anomaly
        is_fraud, reason = FraudDetector.check_amount_anomaly(
            expected_amount, actual_amount, org_id
        )
        if is_fraud:
            risk_factors.append({"type": "amount_anomaly", "reason": reason})
            fraud_score += 30
        
        # Check rapid payments
        is_fraud, reason = FraudDetector.check_rapid_payments(org_id, payment_id)
        if is_fraud:
            risk_factors.append({"type": "rapid_payments", "reason": reason})
            fraud_score += 25
        
        # Check failed attempts pattern
        is_fraud, reason = FraudDetector.check_failed_attempts_pattern(org_id)
        if is_fraud:
            risk_factors.append({"type": "failed_attempts", "reason": reason})
            fraud_score += 20
        
        # Check cross-org attempts
        if user_id:
            is_fraud, reason = FraudDetector.check_cross_org_verification_attempts(
                user_id, org_id
            )
            if is_fraud:
                risk_factors.append({"type": "cross_org_attempts", "reason": reason})
                fraud_score += 25
        
        return {
            "fraud_score": min(fraud_score, 100),
            "risk_level": "high" if fraud_score >= 50 else "medium" if fraud_score >= 25 else "low",
            "risk_factors": risk_factors,
            "recommendation": "block" if fraud_score >= 50 else "review" if fraud_score >= 25 else "allow"
        }

