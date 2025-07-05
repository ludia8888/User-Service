#!/bin/bash

echo "=== Load Test Runner for User Service ==="
echo

# Check if locust is installed
if ! command -v locust &> /dev/null; then
    echo "Locust is not installed. Installing..."
    pip install locust
fi

# Check if the service is running
echo "Checking if User Service is running..."
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "Error: User Service is not running at http://localhost:8000"
    echo "Please start the service first using: ./run_e2e_tests.sh"
    exit 1
fi

echo "User Service is running. Starting load tests..."
echo

# Run different load test scenarios
echo "=== Scenario 1: Normal Load (10 users, spawn rate 2/sec) ==="
locust -f tests/locustfile.py \
    --headless \
    --users 10 \
    --spawn-rate 2 \
    --run-time 60s \
    --host http://localhost:8000 \
    --html tests/load_test_report_normal.html

echo
echo "=== Scenario 2: High Load (50 users, spawn rate 5/sec) ==="
locust -f tests/locustfile.py \
    --headless \
    --users 50 \
    --spawn-rate 5 \
    --run-time 60s \
    --host http://localhost:8000 \
    --html tests/load_test_report_high.html

echo
echo "=== Scenario 3: Stress Test (100 users, spawn rate 10/sec) ==="
locust -f tests/locustfile.py \
    --headless \
    --users 100 \
    --spawn-rate 10 \
    --run-time 60s \
    --host http://localhost:8000 \
    --html tests/load_test_report_stress.html

echo
echo "=== Scenario 4: Rate Limit Test (20 users making rapid requests) ==="
locust -f tests/locustfile.py \
    --headless \
    --users 20 \
    --spawn-rate 20 \
    --run-time 30s \
    --host http://localhost:8000 \
    --html tests/load_test_report_rate_limit.html \
    RateLimitTest

echo
echo "Load tests completed!"
echo "Reports generated:"
echo "  - tests/load_test_report_normal.html"
echo "  - tests/load_test_report_high.html"
echo "  - tests/load_test_report_stress.html"
echo "  - tests/load_test_report_rate_limit.html"