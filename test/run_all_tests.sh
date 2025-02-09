#!/bin/bash
echo "Running all tests..."

# Run configuration tests first
./test/test_config.sh
config_result=$?

# If config tests pass, run functional tests
if [ $config_result -eq 0 ]; then
    ./test/test_secrets.sh
    secrets_result=$?
    
    ./test/test_webhook.sh
    webhook_result=$?
    
    # Exit with failure if any test suite failed
    if [ $secrets_result -ne 0 ] || [ $webhook_result -ne 0 ]; then
        exit 1
    fi
else
    echo "Configuration tests failed. Skipping functional tests."
    exit 1
fi

echo "All tests completed successfully!"