#!/bin/bash

echo "=== E2E Test Runner for User Service ==="
echo

# Check if docker containers are running
echo "Checking Docker containers..."
if ! docker-compose -f docker-compose.test.yml ps | grep -q "Up"; then
    echo "Starting test containers..."
    docker-compose -f docker-compose.test.yml up -d
    echo "Waiting for containers to be ready..."
    sleep 5
else
    echo "Test containers are already running."
fi

# Check if the service is running
echo
echo "Checking if User Service is running..."
if ! curl -s http://localhost:8000/health > /dev/null; then
    echo "User Service is not running. Starting it..."
    
    # Export test environment variables
    export DATABASE_URL="postgresql+asyncpg://test_user:test_password@localhost:5433/test_user_service"
    export REDIS_URL="redis://localhost:6380"
    export JWT_SECRET="e2e-test-secret-key-for-testing-purposes-only-minimum-32-characters"
    export DEBUG="true"
    export RATE_LIMIT_ENABLED="true"
    
    # Start the service in background
    echo "Starting User Service..."
    cd src && python main.py &
    SERVICE_PID=$!
    echo "Service started with PID: $SERVICE_PID"
    
    # Wait for service to be ready
    echo "Waiting for service to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/health > /dev/null; then
            echo "Service is ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "Service failed to start in 30 seconds"
            exit 1
        fi
        sleep 1
    done
else
    echo "User Service is already running."
fi

# Run E2E tests
echo
echo "Running E2E tests..."
pytest tests/test_e2e.py -v

# Store test result
TEST_RESULT=$?

# Cleanup (optional - comment out if you want to keep service running)
if [ ! -z "$SERVICE_PID" ]; then
    echo
    echo "Stopping User Service..."
    kill $SERVICE_PID 2>/dev/null
fi

echo
echo "E2E tests completed with exit code: $TEST_RESULT"
exit $TEST_RESULT