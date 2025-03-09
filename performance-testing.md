# GHAS Performance Testing Guide

## Overview

This document provides instructions for using the GHAS (GitHub Advanced Security) Performance Testing script to evaluate the performance of the Secrets Detector's push protection endpoint. The Python script simulates multiple concurrent users sending different types of payloads to measure transaction throughput and response times with high precision.

## Requirements

- Python 3.7+ 
- Required Python packages:
  - aiohttp
  - pandas
  - matplotlib
  - jinja2

## Installation

1. Download the performance testing script:

```bash
curl -o ghas_performance_test.py https://raw.githubusercontent.com/S-Corkum/secerts-detector/main/tools/ghas_performance_test.py
```

2. Install required dependencies:

```bash
pip install aiohttp pandas matplotlib jinja2
```

## Basic Usage

Run the script with default parameters:

```bash
python ghas_performance_test.py
```

By default, this will:
- Target `http://localhost:3000/api/v1/push-protection`
- Run 10 concurrent users
- Test for 60 seconds with a 5-second ramp-up period
- Generate a mix of clean (30%), dummy secret (30%), and real secret (40%) payloads

## Command-line Options

The script supports various command-line options to customize the test:

| Option | Description | Default |
|--------|-------------|---------|
| `-H, --host HOST` | Target host | `localhost` |
| `-p, --port PORT` | Target port | `3000` |
| `-e, --endpoint ENDPOINT` | Target endpoint | `/api/v1/push-protection` |
| `-s, --secure` | Use HTTPS instead of HTTP | HTTP |
| `-c, --concurrency N` | Number of concurrent users | `10` |
| `-d, --duration N` | Test duration in seconds | `60` |
| `-r, --ramp-up N` | Ramp-up time in seconds | `5` |
| `-t, --timeout N` | Request timeout in seconds | `10` |
| `--clean N` | Percentage of clean payloads | `30` |
| `--dummy N` | Percentage of payloads with dummy secrets | `30` |
| `--real N` | Percentage of payloads with real secrets | `40` |
| `-o, --output DIR` | Output directory for reports | `./performance-reports` |

### Examples

Test against a production server with HTTPS:
```bash
python ghas_performance_test.py --host api.example.com --secure
```

Run a high-load test:
```bash
python ghas_performance_test.py --concurrency 100 --duration 300
```

Focus on edge cases with mostly real secrets:
```bash
python ghas_performance_test.py --clean 10 --dummy 10 --real 80
```

## Understanding Test Payloads

The script generates three types of test payloads:

1. **Clean Payloads**: Normal content without any secrets. These should be allowed by the GHAS endpoint.
   
2. **Dummy Secret Payloads**: Content that contains secrets clearly marked as "TEST" or "DUMMY". These should be detected but allowed.

3. **Real Secret Payloads**: Content with authentic-looking secrets (like AWS keys, private keys, etc.). These should be detected and blocked.

You can adjust the distribution of these payloads using the `--clean`, `--dummy`, and `--real` options.

## Test Execution

When you run the script, it:

1. Creates asynchronous HTTP sessions for high concurrency
2. Gradually ramps up simulated users based on your settings
3. Sends continuous requests during the test duration
4. Records response times and results with microsecond precision
5. Analyzes the results and generates comprehensive reports

## Understanding Results

After the test completes, the script generates:

1. **CSV data**: Raw test results in CSV format for further analysis
2. **Text summary**: Key metrics like TPS, response times, and result distribution
3. **HTML report**: Visual representation of test results with tables and charts
4. **Response time graphs**: Visual plots showing response time distribution and trends

### Key Metrics

- **Transactions Per Second (TPS)**: The number of requests the system can handle per second
- **Response Time Statistics**: Min, max, average, and percentiles (p50, p90, p95, p99)
- **Result Distribution**: The breakdown of allowed vs. blocked requests
- **Error Rate**: Percentage of requests that resulted in errors

## Advantages Over the Bash Script

This Python implementation offers several advantages over the previous Bash script:

1. **True Concurrency**: Uses async I/O for efficient, non-blocking concurrent requests
2. **Accurate Timing**: Measures response times with microsecond precision
3. **Robust Statistical Analysis**: Uses pandas for reliable data processing and statistics
4. **Advanced Visualization**: Generates detailed graphs of performance metrics
5. **Reliable Percentile Calculation**: Properly calculates percentiles using robust statistical methods
6. **Low Overhead**: Minimal impact from the testing tool itself, giving more accurate results

## Example Test Scenarios

### Baseline Performance Test

```bash
python ghas_performance_test.py --concurrency 5 --duration 60
```

This provides a baseline of performance under moderate load.

### Peak Load Test

```bash
python ghas_performance_test.py --concurrency 50 --duration 180 --ramp-up 30
```

This simulates a high-load scenario to identify the system's breaking point.

### Endurance Test

```bash
python ghas_performance_test.py --concurrency 20 --duration 1800
```

This tests the system's stability over a longer period (30 minutes).

### Worst-Case Scenario

```bash
python ghas_performance_test.py --clean 5 --dummy 5 --real 90 --concurrency 30
```

This tests performance when most payloads contain real secrets (requiring more intensive validation).

## Tips for Optimizing Performance

Based on test results, you might consider:

1. **CPU Optimization**: If CPU usage is high, look for ways to make the validation algorithms more efficient.

2. **Memory Optimization**: Watch for memory leaks during extended tests.

3. **Database Optimization**: Ensure database connections are properly pooled and queries are optimized.

4. **Parallelization**: Consider increasing worker processes for the validation service.

5. **Caching**: Implement caching for frequently validated patterns.

## Troubleshooting

### No module named error
- Ensure you've installed all required packages: `pip install aiohttp pandas matplotlib jinja2`

### Connection refused errors
- Verify the Secrets Detector services are running
- Check the host and port settings
- Ensure there are no firewall rules blocking the connection

### Memory issues with large tests
- For very large tests, you might need to increase your system's memory limits
- Consider running with a smaller concurrency value

## Extending the Script

You can customize the script by:

1. Adding more payload types in the Python code
2. Modifying the request parameters or headers
3. Implementing custom analysis functions
4. Integrating with external monitoring systems
5. Adding distributed testing capabilities across multiple machines

## Final Notes

- Always run performance tests in a controlled environment that won't impact production systems.
- Start with low concurrency and gradually increase to avoid overwhelming the system.
- Compare results between test runs to identify performance regressions.
- Use the test results to establish performance SLAs for your deployment.