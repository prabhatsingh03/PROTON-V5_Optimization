#!/usr/bin/env python3
"""
PROTON Load Testing Script
Tests concurrent user capacity for the Flask application.

Usage:
    python load_test.py --users 50 --duration 60 --endpoint /api/projects
    python load_test.py --users 100 --duration 120 --endpoint /dashboard
    python load_test.py --users 200 --ramp-up 10 --endpoint /api/org/usage

Note:
    Admin authentication now uses a two-step OTP flow. Provide the OTP via the
    --otp flag or enter it interactively when prompted so the script can call
    /api/auth/verify-otp before running authenticated requests.
"""

import argparse
import time
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import statistics
import json
from datetime import datetime

# Configuration
BASE_URL = "http://127.0.0.1:5125"
DEFAULT_ENDPOINTS = [
    "/dashboard",
    "/api/health",
    "/api/projects",
    "/api/org/usage",
    "/api/org/trial-status"
]

class LoadTester:
    def __init__(self, base_url, endpoint, auth_token=None):
        self.base_url = base_url.rstrip('/')
        self.endpoint = endpoint
        self.auth_token = auth_token
        self.results = {
            'success': [],
            'failed': [],
            'errors': defaultdict(int),
            'response_times': [],
            'status_codes': defaultdict(int)
        }
        self.lock = threading.Lock()
    
    def make_request(self, user_id):
        """Make a single HTTP request."""
        url = f"{self.base_url}{self.endpoint}"
        headers = {}
        
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        start_time = time.time()
        try:
            if self.endpoint.startswith('/api/'):
                response = requests.get(url, headers=headers, timeout=30)
            else:
                response = requests.get(url, headers=headers, timeout=30)
            
            elapsed = time.time() - start_time
            status_code = response.status_code
            
            with self.lock:
                self.results['status_codes'][status_code] += 1
                self.results['response_times'].append(elapsed)
                
                if 200 <= status_code < 400:
                    self.results['success'].append({
                        'user_id': user_id,
                        'status_code': status_code,
                        'response_time': elapsed,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    self.results['failed'].append({
                        'user_id': user_id,
                        'status_code': status_code,
                        'response_time': elapsed,
                        'error': response.text[:200] if response.text else 'No error message'
                    })
                    self.results['errors'][f'HTTP_{status_code}'] += 1
                    
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            with self.lock:
                self.results['failed'].append({
                    'user_id': user_id,
                    'status_code': 0,
                    'response_time': elapsed,
                    'error': 'Request Timeout'
                })
                self.results['errors']['Timeout'] += 1
        except requests.exceptions.ConnectionError:
            elapsed = time.time() - start_time
            with self.lock:
                self.results['failed'].append({
                    'user_id': user_id,
                    'status_code': 0,
                    'response_time': elapsed,
                    'error': 'Connection Error - Server may be down or overloaded'
                })
                self.results['errors']['ConnectionError'] += 1
        except Exception as e:
            elapsed = time.time() - start_time
            with self.lock:
                self.results['failed'].append({
                    'user_id': user_id,
                    'status_code': 0,
                    'response_time': elapsed,
                    'error': str(e)
                })
                self.results['errors'][type(e).__name__] += 1
    
    def run_test(self, num_users, duration=None, ramp_up=0):
        """Run load test with specified number of concurrent users."""
        print(f"\n{'='*60}")
        print(f"LOAD TEST STARTED")
        print(f"{'='*60}")
        print(f"Endpoint: {self.endpoint}")
        print(f"Base URL: {self.base_url}")
        print(f"Concurrent Users: {num_users}")
        if duration:
            print(f"Duration: {duration} seconds")
        if ramp_up:
            print(f"Ramp-up Time: {ramp_up} seconds")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        end_time = start_time + duration if duration else None
        
        # Ramp-up logic
        if ramp_up > 0:
            users_per_second = num_users / ramp_up
            print(f"Ramping up: {users_per_second:.2f} users/second\n")
        
        with ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = []
            user_id = 0
            
            while True:
                # Check if we should stop
                if end_time and time.time() >= end_time:
                    break
                
                # Ramp-up: gradually increase users
                if ramp_up > 0 and user_id < num_users:
                    if user_id > 0:
                        time.sleep(1.0 / users_per_second)
                elif not ramp_up and user_id >= num_users:
                    # All users started, wait for duration or completion
                    if duration:
                        if time.time() >= end_time:
                            break
                        time.sleep(1)
                    else:
                        # No duration specified, wait for all to complete
                        break
                
                if user_id < num_users or (duration and time.time() < end_time):
                    future = executor.submit(self.make_request, user_id)
                    futures.append(future)
                    user_id += 1
                
                # Check completed futures periodically
                if len(futures) > 100:  # Limit futures list size
                    completed = [f for f in futures if f.done()]
                    futures = [f for f in futures if not f.done()]
            
            # Wait for all remaining requests to complete
            print("\nWaiting for all requests to complete...")
            for future in as_completed(futures, timeout=300):
                try:
                    future.result()
                except Exception as e:
                    print(f"Future error: {e}")
        
        total_time = time.time() - start_time
        self.print_results(total_time)
        return self.results
    
    def print_results(self, total_time):
        """Print test results summary."""
        total_requests = len(self.results['success']) + len(self.results['failed'])
        success_count = len(self.results['success'])
        failed_count = len(self.results['failed'])
        success_rate = (success_count / total_requests * 100) if total_requests > 0 else 0
        
        print(f"\n{'='*60}")
        print(f"LOAD TEST RESULTS")
        print(f"{'='*60}")
        print(f"Total Test Duration: {total_time:.2f} seconds")
        print(f"Total Requests: {total_requests}")
        print(f"Successful: {success_count} ({success_rate:.2f}%)")
        print(f"Failed: {failed_count} ({100 - success_rate:.2f}%)")
        
        if self.results['response_times']:
            response_times = self.results['response_times']
            print(f"\nResponse Time Statistics:")
            print(f"  Average: {statistics.mean(response_times):.3f}s")
            print(f"  Median: {statistics.median(response_times):.3f}s")
            print(f"  Min: {min(response_times):.3f}s")
            print(f"  Max: {max(response_times):.3f}s")
            if len(response_times) > 1:
                print(f"  Std Dev: {statistics.stdev(response_times):.3f}s")
            
            # Percentiles
            sorted_times = sorted(response_times)
            p50 = sorted_times[int(len(sorted_times) * 0.50)]
            p95 = sorted_times[int(len(sorted_times) * 0.95)]
            p99 = sorted_times[int(len(sorted_times) * 0.99)]
            print(f"\nResponse Time Percentiles:")
            print(f"  50th (Median): {p50:.3f}s")
            print(f"  95th: {p95:.3f}s")
            print(f"  99th: {p99:.3f}s")
        
        print(f"\nStatus Code Distribution:")
        for code, count in sorted(self.results['status_codes'].items()):
            percentage = (count / total_requests * 100) if total_requests > 0 else 0
            print(f"  {code}: {count} ({percentage:.2f}%)")
        
        if self.results['errors']:
            print(f"\nError Summary:")
            for error_type, count in self.results['errors'].items():
                print(f"  {error_type}: {count}")
        
        # Requests per second
        rps = total_requests / total_time if total_time > 0 else 0
        print(f"\nThroughput: {rps:.2f} requests/second")
        
        print(f"{'='*60}\n")
        
        # Recommendations
        if success_rate < 95:
            print("⚠️  WARNING: Success rate below 95% - Application may be overloaded")
        if self.results['response_times'] and statistics.mean(self.results['response_times']) > 2.0:
            print("⚠️  WARNING: Average response time exceeds 2 seconds")
        if failed_count > 0 and 'ConnectionError' in self.results['errors']:
            print("⚠️  WARNING: Connection errors detected - Server may be crashing or overloaded")
        
        if success_rate >= 99 and self.results['response_times']:
            avg_time = statistics.mean(self.results['response_times'])
            if avg_time < 1.0:
                print("✅ Application is performing well under this load!")

def get_auth_token(base_url, email, password, otp_code=None):
    """Get authentication token for protected endpoints using the OTP flow."""
    base = base_url.rstrip('/')
    payload = {
        "type": "admin",
        "email": email,
        "password": password
    }
    try:
        response = requests.post(f"{base}/api/login", json=payload, timeout=10)
    except Exception as e:
        print(f"Warning: Could not reach login endpoint: {e}")
        return None

    try:
        data = response.json()
    except ValueError:
        print(f"Warning: Unexpected login response: {response.text}")
        return None

    if response.status_code != 200:
        print(f"Authentication failed: {data.get('message', 'Unexpected response')} (HTTP {response.status_code})")
        return None

    status = data.get('status')
    if status == 'otp_sent':
        print("OTP sent to your email. Complete verification to continue.")
        code = otp_code
        if not code:
            try:
                code = input("Enter the 6-digit OTP: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAuthentication cancelled.")
                return None
        if not code:
            print("No OTP provided; cannot complete authentication.")
            return None

        verify_payload = {"email": email, "otp_code": code}
        try:
            verify_resp = requests.post(f"{base}/api/auth/verify-otp", json=verify_payload, timeout=10)
            verify_data = verify_resp.json()
        except Exception as e:
            print(f"Warning: OTP verification failed: {e}")
            return None

        if verify_resp.status_code == 200 and verify_data.get('status') == 'success':
            return verify_data.get('access_token')

        print(f"OTP verification error: {verify_data.get('message', 'Unknown error')} (HTTP {verify_resp.status_code})")
        return None

    if status == 'success':
        return data.get('access_token')

    print(f"Authentication failed: {data.get('message', 'Unknown error')}")
    return None

def main():
    parser = argparse.ArgumentParser(description='Load test PROTON Flask application')
    parser.add_argument('--url', default=BASE_URL, help='Base URL of the application')
    parser.add_argument('--endpoint', default='/api/health', help='Endpoint to test')
    parser.add_argument('--users', type=int, default=50, help='Number of concurrent users')
    parser.add_argument('--duration', type=int, default=None, help='Test duration in seconds')
    parser.add_argument('--ramp-up', type=int, default=0, help='Ramp-up time in seconds (gradually increase users)')
    parser.add_argument('--email', help='Email for authentication (optional)')
    parser.add_argument('--password', help='Password for authentication (optional)')
    parser.add_argument('--otp', help='6-digit OTP for admin authentication (optional)')
    parser.add_argument('--output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Get auth token if credentials provided
    auth_token = None
    if args.email and args.password:
        print("Authenticating...")
        auth_token = get_auth_token(args.url, args.email, args.password, args.otp)
        if auth_token:
            print("✓ Authentication successful")
        else:
            print("✗ Authentication failed - testing without auth")
    
    # Run load test
    tester = LoadTester(args.url, args.endpoint, auth_token)
    results = tester.run_test(args.users, args.duration, args.ramp_up)
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results saved to {args.output}")

if __name__ == '__main__':
    main()

