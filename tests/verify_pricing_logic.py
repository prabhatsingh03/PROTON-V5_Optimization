"""
Verify Subscription Pricing Logic
Test script to validate the `calculate_subscription_amount` function in app.py.
"""
import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path to allow importing app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock environment variables to avoid import errors or unwanted behavior in app.py
os.environ['SUPERADMIN_SECRET_KEY'] = 'test_key'
os.environ['JWT_SECRET_KEY'] = 'test_jwt_key'

try:
    from app import calculate_subscription_amount
except ImportError:
    print("Could not import app.py directly. Mocks might be needed for dependencies.")
    # Fallback or exit? For now, let's assume it imports or we'll see the error.

class TestPricingLogic(unittest.TestCase):
    
    def setUp(self):
        # We need to ensure RAZORPAY_PLANS is populated if it's used directly
        # or mock get_plan_limits.
        pass

    @patch('app.get_plan_limits')
    @patch('app.RAZORPAY_PLANS')
    def test_basic_plan_pricing(self, mock_plans, mock_get_limits):
        """Test Basic plan pricing logic."""
        # Setup Mocks
        mock_plans.get.return_value = {'amount': 170000} # 1700 INR in paise
        mock_get_limits.return_value = {'max_users': 5}
        
        # 1. Within limit (3 users) -> Base Price
        # Basic = 1700
        price = calculate_subscription_amount('basic', 3, 'monthly')
        self.assertEqual(price, 170000, "Basic plan within limit should be base price")
        
        # 2. At limit (5 users) -> Base Price
        price = calculate_subscription_amount('basic', 5, 'monthly')
        self.assertEqual(price, 170000, "Basic plan at limit should be base price")
        
        # 3. Over limit (6 users) -> Base + 1 extra (500)
        # 1700 + 500 = 2200
        price = calculate_subscription_amount('basic', 6, 'monthly')
        self.assertEqual(price, 220000, "Basic plan (1 extra user) should be 2200")
        
        # 4. Yearly (multiplier 12)
        # 1700 * 12 = 20400
        price = calculate_subscription_amount('basic', 5, 'yearly')
        self.assertEqual(price, 170000 * 12, "Basic plan yearly should be base * 12")

    @patch('app.get_plan_limits')
    @patch('app.RAZORPAY_PLANS')
    def test_plus_plan_pricing(self, mock_plans, mock_get_limits):
        """Test Plus plan pricing logic."""
        mock_plans.get.return_value = {'amount': 260000} # 2600 INR
        mock_get_limits.return_value = {'max_users': 10}
        
        # 1. Within limit (8 users)
        price = calculate_subscription_amount('plus', 8, 'monthly')
        self.assertEqual(price, 260000)
        
        # 2. Over limit (12 users) -> Base + 2 extra (1000)
        # 2600 + 1000 = 3600
        price = calculate_subscription_amount('plus', 12, 'monthly')
        self.assertEqual(price, 360000)

    @patch('app.get_plan_limits')
    @patch('app.RAZORPAY_PLANS')
    def test_pro_plan_pricing(self, mock_plans, mock_get_limits):
        """Test Pro plan pricing logic."""
        mock_plans.get.return_value = {'amount': 430000} # 4300 INR
        mock_get_limits.return_value = {'max_users': 100} # Should be ignored for logic but good to align
        
        # 1. Within limit (50 users)
        price = calculate_subscription_amount('pro', 50, 'monthly')
        self.assertEqual(price, 430000)
        
        # 2. At limit (100 users)
        price = calculate_subscription_amount('pro', 100, 'monthly')
        self.assertEqual(price, 430000)
        
        # 3. Over limit (105 users) -> Base + 5 extra (2500)
        # 4300 + 2500 = 6800
        price = calculate_subscription_amount('pro', 105, 'monthly')
        self.assertEqual(price, 680000)

if __name__ == '__main__':
    unittest.main()
