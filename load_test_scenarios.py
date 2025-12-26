#!/usr/bin/env python3
"""
Predefined Load Test Scenarios for PROTON
Run different test scenarios to find the application's limits.
"""

import subprocess
import sys
import time

BASE_URL = "http://127.0.0.1:5125"

SCENARIOS = {
    "light": {
        "name": "Light Load (10 users)",
        "users": 10,
        "duration": 30,
        "endpoint": "/api/health",
        "description": "Test with 10 concurrent users for 30 seconds"
    },
    "medium": {
        "name": "Medium Load (50 users)",
        "users": 50,
        "duration": 60,
        "endpoint": "/api/health",
        "description": "Test with 50 concurrent users for 60 seconds"
    },
    "heavy": {
        "name": "Heavy Load (100 users)",
        "users": 100,
        "duration": 120,
        "endpoint": "/api/health",
        "description": "Test with 100 concurrent users for 120 seconds"
    },
    "stress": {
        "name": "Stress Test (200 users)",
        "users": 200,
        "duration": 180,
        "endpoint": "/api/health",
        "ramp_up": 30,
        "description": "Stress test with 200 users, 30s ramp-up"
    },
    "dashboard": {
        "name": "Dashboard Load (50 users)",
        "users": 50,
        "duration": 60,
        "endpoint": "/dashboard",
        "description": "Test dashboard page with 50 concurrent users"
    },
    "api_projects": {
        "name": "API Projects (100 users)",
        "users": 100,
        "duration": 120,
        "endpoint": "/api/projects",
        "description": "Test projects API with 100 concurrent users (requires auth)"
    },
    "api_usage": {
        "name": "API Usage Stats (75 users)",
        "users": 75,
        "duration": 90,
        "endpoint": "/api/org/usage",
        "description": "Test usage stats API with 75 concurrent users (requires auth)"
    },
    "spike": {
        "name": "Spike Test (500 users, 10s)",
        "users": 500,
        "duration": 10,
        "endpoint": "/api/health",
        "description": "Sudden spike of 500 users for 10 seconds"
    }
}

def run_scenario(scenario_key):
    """Run a specific test scenario."""
    if scenario_key not in SCENARIOS:
        print(f"Unknown scenario: {scenario_key}")
        print(f"Available scenarios: {', '.join(SCENARIOS.keys())}")
        return
    
    scenario = SCENARIOS[scenario_key]
    print(f"\n{'='*70}")
    print(f"Running: {scenario['name']}")
    print(f"Description: {scenario['description']}")
    print(f"{'='*70}\n")
    
    cmd = [
        sys.executable, "load_test.py",
        "--url", BASE_URL,
        "--endpoint", scenario['endpoint'],
        "--users", str(scenario['users']),
        "--duration", str(scenario['duration'])
    ]
    
    if 'ramp_up' in scenario:
        cmd.extend(["--ramp-up", str(scenario['ramp_up'])])
    
    if 'email' in scenario and 'password' in scenario:
        cmd.extend(["--email", scenario['email'], "--password", scenario['password']])
    
    if 'output' in scenario:
        cmd.extend(["--output", scenario['output']])
    
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except subprocess.CalledProcessError as e:
        print(f"\nTest failed with error code: {e.returncode}")

def list_scenarios():
    """List all available test scenarios."""
    print("\nAvailable Load Test Scenarios:\n")
    for key, scenario in SCENARIOS.items():
        print(f"  {key:15} - {scenario['name']}")
        print(f"                 {scenario['description']}")
        print()

def main():
    if len(sys.argv) < 2:
        print("PROTON Load Test Scenarios")
        print("=" * 70)
        list_scenarios()
        print("Usage:")
        print("  python load_test_scenarios.py <scenario_name>")
        print("  python load_test_scenarios.py list")
        print("\nExample:")
        print("  python load_test_scenarios.py light")
        print("  python load_test_scenarios.py stress")
        return
    
    command = sys.argv[1].lower()
    
    if command == "list":
        list_scenarios()
    elif command == "all":
        print("Running all scenarios sequentially...\n")
        for key in SCENARIOS.keys():
            run_scenario(key)
            print("\nWaiting 10 seconds before next scenario...\n")
            time.sleep(10)
    else:
        run_scenario(command)

if __name__ == '__main__':
    main()

