#!/bin/bash

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to get millisecond timestamps in a compatible way
get_time_ms() {
    if date +%s%3N 2>/dev/null | grep -q N; then
        # If %3N doesn't work, use seconds and convert
        local sec=$(date +%s)
        local ms=$(date +%N | cut -b1-3)
        echo $((sec * 1000 + ms))
    else
        # If %3N works, use it directly
        date +%s%3N
    fi
}

# Configuration variables - can be overridden with command line arguments
HOST="localhost"
PORT="3000"
ENDPOINT="/api/v1/push-protection"
PROTOCOL="http"
CONCURRENCY=10
DURATION=60
RAMP_UP=5
REQUEST_TIMEOUT=10
TEST_CLEAN_PERCENTAGE=30
TEST_DUMMY_SECRET_PERCENTAGE=30
TEST_REAL_SECRET_PERCENTAGE=40
REPORT_DIR="./performance-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Function to display script usage
show_usage() {
    echo -e "${BOLD}Usage:${NC} $0 [options]"
    echo -e "${BOLD}Options:${NC}"
    echo "  -h, --host HOST            Target host (default: $HOST)"
    echo "  -p, --port PORT            Target port (default: $PORT)"
    echo "  -e, --endpoint ENDPOINT    Target endpoint (default: $ENDPOINT)"
    echo "  -s, --secure               Use HTTPS instead of HTTP"
    echo "  -c, --concurrency N        Number of concurrent users (default: $CONCURRENCY)"
    echo "  -d, --duration N           Test duration in seconds (default: $DURATION)"
    echo "  -r, --ramp-up N            Ramp-up time in seconds (default: $RAMP_UP)"
    echo "  -t, --timeout N            Request timeout in seconds (default: $REQUEST_TIMEOUT)"
    echo "  --clean N                  Percentage of clean payloads (default: $TEST_CLEAN_PERCENTAGE)"
    echo "  --dummy N                  Percentage of payloads with dummy secrets (default: $TEST_DUMMY_SECRET_PERCENTAGE)"
    echo "  --real N                   Percentage of payloads with real secrets (default: $TEST_REAL_SECRET_PERCENTAGE)"
    echo "  -o, --output DIR           Output directory for reports (default: $REPORT_DIR)"
    echo "  --help                     Display this help message"
    echo ""
    echo -e "${BOLD}Example:${NC}"
    echo "  $0 -c 20 -d 120 --secure --host example.com"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -e|--endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        -s|--secure)
            PROTOCOL="https"
            shift
            ;;
        -c|--concurrency)
            CONCURRENCY="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -r|--ramp-up)
            RAMP_UP="$2"
            shift 2
            ;;
        -t|--timeout)
            REQUEST_TIMEOUT="$2"
            shift 2
            ;;
        --clean)
            TEST_CLEAN_PERCENTAGE="$2"
            shift 2
            ;;
        --dummy)
            TEST_DUMMY_SECRET_PERCENTAGE="$2"
            shift 2
            ;;
        --real)
            TEST_REAL_SECRET_PERCENTAGE="$2"
            shift 2
            ;;
        -o|--output)
            REPORT_DIR="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Check payload percentages
TOTAL_PERCENTAGE=$((TEST_CLEAN_PERCENTAGE + TEST_DUMMY_SECRET_PERCENTAGE + TEST_REAL_SECRET_PERCENTAGE))
if [ $TOTAL_PERCENTAGE -ne 100 ]; then
    echo -e "${RED}Error: Payload percentages must sum to 100 (currently $TOTAL_PERCENTAGE)${NC}"
    echo "Clean: $TEST_CLEAN_PERCENTAGE%, Dummy secrets: $TEST_DUMMY_SECRET_PERCENTAGE%, Real secrets: $TEST_REAL_SECRET_PERCENTAGE%"
    exit 1
fi

# Define target URL
TARGET_URL="${PROTOCOL}://${HOST}:${PORT}${ENDPOINT}"
echo -e "${BLUE}Target URL: ${BOLD}${TARGET_URL}${NC}"

# Create output directory if it doesn't exist
OUTPUT_DIR="${REPORT_DIR}/${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
echo -e "${BLUE}Reports will be saved to: ${BOLD}${OUTPUT_DIR}${NC}"

# Generate payload files
PAYLOADS_DIR="${OUTPUT_DIR}/payloads"
mkdir -p "$PAYLOADS_DIR"

echo -e "${BLUE}Generating test payloads focusing on certificates and private keys...${NC}"

# 1. Clean payload (no secrets)
cat > "${PAYLOADS_DIR}/clean.json" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "# Configuration\nlog_level: debug\nport: 8080\nhost: 'localhost'\nretry_attempts: 3\nallowed_users: ['admin', 'developer']\ndatabase_url: 'postgres://user:placeholder@localhost:5432/mydb'\n\n# No certificates or private keys in this file",
  "content_type": "file",
  "filename": "config.yaml",
  "ref": "refs/heads/main"
}
EOF

# 2. Dummy/test secret payload (with test certificates and keys)
cat > "${PAYLOADS_DIR}/dummy-secret.json" << 'EOF'
{
  "repository": {
    "owner": "test-org", 
    "name": "test-repo"
  },
  "content": "// This file contains TEST/DUMMY certificates and private keys\n\n// TEST CERTIFICATE\n-----BEGIN CERTIFICATE-----\nTEST_CERTIFICATE_FOR_DEVELOPMENT_ONLY\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\n-----END CERTIFICATE-----\n\n// DUMMY PRIVATE KEY\n-----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_KEY_DO_NOT_USE\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi\nzRTmsea44zy0xM8+BjZ7pEr587gO6Ov3KoKZCV4xcFhvJ/9yWgRWoCYMvpOIxW/G\nWufmRObVReT7bhYYZquJcpOBgNJ7elPwKxi7mZ18Dedlf+fowwx3L5+agq2SZ4AV\n4ftNWl3R9uz5SiuGGkdQ14G4AMzEabV6hf53VZ1bvPM48bLZ2BzJRjrdcWFmCUla\n-----END PRIVATE KEY-----",
  "content_type": "file",
  "filename": "test-certs-and-keys.js",
  "ref": "refs/heads/feature/test-keys"
}
EOF

# 3. Real secret payload (with legitimate-looking certificates and keys)
cat > "${PAYLOADS_DIR}/real-secret.json" << 'EOF'
{
  "repository": {
    "owner": "test-org",
    "name": "test-repo"
  },
  "content": "# Sensitive Configuration File\n\n# Production Certificate\n-----BEGIN CERTIFICATE-----\nMIIFHTCCAwWgAwIBAgIUUGihu0CQ3okROlCakzXXIODzMqUwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAwwTU2VjcmV0cy1EZXRlY3Rvci1DQTAeFw0yNTAzMDgyMDU3\nNDFaFw0yNjAzMDgyMDU3NDFaMB4xHDAaBgNVBAMME1NlY3JldHMtRGV0ZWN0b3It\nQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDPTNL0QNlOaymOGVSO\nfmkOSlmxFK1HhprMzdm+EWSMeWj/r8TrGQrgQoLsZU8cW94jkmjcNfU9C+xfUR9G\nJoAwEfCMmr/wHNETH8XCVbgIkqw8AHgpn4gS2NhhhoxsQ/PnzhHS3juNeWB4hcmQ\nayuudLsUad+bWQPn7+JS4n3JZQ1ikfjd+a5W+FDAzcdOLvK1QTnb3s74zDRzYQz0\n-----END CERTIFICATE-----\n\n# Private Key (DO NOT SHARE)\n-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDDCyQTg9KwEAgq\n8R87wvDBBD2OKOkNaykfoxloSU5Jnx6XThV3Nf3eipmBKw+kTkfEGSalw8c0qSU2\npTcm6yL8/lXbNydc7pXBq5fI24+eXJ33rg4+GV6z80m9Fxs+6ChPTqi7Rn+UpCd+\nVEQGTQgxV8uDvgNAughWFJsYcliNjB91rHhsmx0W567i8qi6EyofGMxQ4wvbYoQy\n1N9Gmq1wixdFDmVSKlD1CASUdtKIf3IWb0PKwjYxoiMznyPpIjD1KfC9WF2dvirf\nyrZk3F2fgSN5pEv51f6u6pKbSnCaNcOqr+/7SwAN7Lj3iMRYxhah8uCLu76a2Ant\n5yRqlcPNAgMBAAECggEAJqCX+Dpw+TfvmiuPQztoCV3w3+znvOXWauLXBxGPjOKT\nwSTweN/LQ63g2VVBH4n2ShauEgG8O8hs643cZpuGXiLzt3rMk6nXpFe6s4eSQat3\niIQi43cMS6i415dSKMr7IrvCDHbZkQNSpAEFyNasMvN/hXuV8tV1DbE+hyCsO3nm\nRdjU2LMOCmcJXoSrNIoEFXuvPJ5DvuxbI3gI4iabDxIlsrSF26QdSYF6FgwYZP+r\nDIGbw4a3dcY6hgCc6uUcjSX3Xh/E2y5dwP5u8Hsyn+3kOrVmtEcIoypdF7EtnUJA\n-----END PRIVATE KEY-----",
  "content_type": "file",
  "filename": "credentials.txt",
  "ref": "refs/heads/main"
}
EOF

# Create a payload selection script based on percentages
cat > "${OUTPUT_DIR}/select_payload.sh" << EOF
#!/bin/bash
# Weighted random payload selection

RANDOM=\$\$  # Seed with PID
RAND=\$((\$RANDOM % 100 + 1))

if [ \$RAND -le $TEST_CLEAN_PERCENTAGE ]; then
    echo "${PAYLOADS_DIR}/clean.json"
elif [ \$RAND -le $((TEST_CLEAN_PERCENTAGE + TEST_DUMMY_SECRET_PERCENTAGE)) ]; then
    echo "${PAYLOADS_DIR}/dummy-secret.json"
else
    echo "${PAYLOADS_DIR}/real-secret.json"
fi
EOF

chmod +x "${OUTPUT_DIR}/select_payload.sh"

# Create test script
cat > "${OUTPUT_DIR}/run_test.sh" << 'EOF'
#!/bin/bash

# Function to get millisecond timestamps in a compatible way
get_time_ms() {
    # Use native %N if available, otherwise use seconds only
    if date +%N >/dev/null 2>&1; then
        echo $(($(date +%s) * 1000 + $(date +%N | cut -b1-3)))
    else
        # Fallback to seconds only with fake milliseconds
        echo $(($(date +%s) * 1000))
    fi
}

    # Function to send a single request and measure its time
send_request() {
    local url=$1
    local payload_file=$2
    local timeout=$3
    local temp_file=$(mktemp)
    local timing_file=$(mktemp)
    
    # Use curl's built-in timing capabilities for accurate measurements
    local http_code=$(curl -s -o "$temp_file" \
        -w "%{http_code},%{time_total},%{time_connect},%{time_starttransfer}" \
        -H "Content-Type: application/json" \
        -X POST \
        --data @"$payload_file" \
        --max-time "$timeout" \
        "$url" 2>"$timing_file")
    
    # Parse the curl timing data
    local timing=$(cat "$timing_file" 2>/dev/null)
    local curl_data=(${http_code//,/ })
    
    # Extract values from curl's response
    http_code=${curl_data[0]}
    local time_total=${curl_data[1]:-0}
    local time_connect=${curl_data[2]:-0}
    local time_starttransfer=${curl_data[3]:-0}
    
    # Convert time_total from seconds to milliseconds and ensure it's numeric
    local response_time=0
    if [[ "$time_total" =~ ^[0-9]*\.?[0-9]+$ ]]; then
        # Valid numeric value, convert to milliseconds
        response_time=$(echo "$time_total * 1000" | bc)
    fi
    
    # Clean up temporary files
    rm -f "$temp_file" "$timing_file"
    
    # Extract response details
    local is_allowed=$(grep -o '"allow":[^,}]*' "$temp_file" | cut -d ":" -f2)
    local has_blocking=$(grep -o '"blocking_findings":\[[^]]*\]' "$temp_file" | grep -c "[^[]")
    local has_non_blocking=$(grep -o '"non_blocking_findings":\[[^]]*\]' "$temp_file" | grep -c "[^[]")
    
    # Determine request result
    local result=""
    if [[ "$http_code" == "200" ]]; then
        if [[ "$is_allowed" == "true" ]]; then
            result="ALLOWED"
        else
            result="BLOCKED"
        fi
    else
        result="ERROR_${http_code}"
    fi
    
    # Clean up temp file
    rm "$temp_file"
    
    # Return CSV: timestamp,response_time_ms,http_code,result,payload_file
    echo "$(get_time_ms),$response_time,$http_code,$result,$payload_file,$is_allowed,$has_blocking,$has_non_blocking"
}

export -f send_request

# Main test execution
main() {
    local url=$1
    local duration=$2
    local concurrency=$3
    local ramp_up=$4
    local timeout=$5
    local payload_selector=$6
    local output_csv=$7
    
    # Initialize CSV header
    echo "timestamp,response_time,http_code,result,payload_file,is_allowed,blocking_findings,non_blocking_findings" > "$output_csv"
    
    # Calculate how many users to add in each ramp-up step
    local ramp_step=$((concurrency / ramp_up))
    [ $ramp_step -lt 1 ] && ramp_step=1
    
    # Get start time
    local start_time=$(date +%s)
    
    # Ramp up phase
    local current_concurrency=0
    while [ $current_concurrency -lt $concurrency ]; do
        local new_concurrency=$((current_concurrency + ramp_step))
        [ $new_concurrency -gt $concurrency ] && new_concurrency=$concurrency
        local users_to_add=$((new_concurrency - current_concurrency))
        
        for ((i=1; i<=users_to_add; i++)); do
            (
                # Calculate remaining test time
                local now=$(date +%s)
                local elapsed=$((now - start_time))
                local remaining=$((duration - elapsed))
                
                # If we still have time left to test
                if [ $remaining -gt 0 ]; then
                    # Generate requests until time is up
                    while true; do
                        # Check if we're out of time
                        now=$(date +%s)
                        elapsed=$((now - start_time))
                        if [ $elapsed -ge $duration ]; then
                            break
                        fi
                        
                        # Select a payload file
                        payload_file=$($payload_selector)
                        
                        # Send a request
                        result=$(send_request "$url" "$payload_file" "$timeout")
                        echo "$result" >> "$output_csv"
                        
                        # Small sleep to prevent overwhelming
                        sleep 0.05
                    done
                fi
            ) &
        done
        
        current_concurrency=$new_concurrency
        echo "Ramped up to $current_concurrency concurrent users"
        
        # Wait for a second between ramp steps
        if [ $current_concurrency -lt $concurrency ]; then
            sleep 1
        fi
    done
    
    # Wait for the duration to complete
    local now=$(date +%s)
    local elapsed=$((now - start_time))
    local to_wait=$((duration - elapsed))
    
    if [ $to_wait -gt 0 ]; then
        echo "All users started. Waiting for $to_wait more seconds to complete the test..."
        sleep $to_wait
    fi
    
    # Give a little extra time for in-flight requests to complete
    sleep 2
    
    # Make sure we kill any lingering processes
    kill $(jobs -p) 2>/dev/null
    
    echo "Test completed!"
}

# Execute the test with provided parameters
main "$1" "$2" "$3" "$4" "$5" "$6" "$7"
EOF

chmod +x "${OUTPUT_DIR}/run_test.sh"

# Create analysis script
cat > "${OUTPUT_DIR}/analyze_results.sh" << 'EOF'
#!/bin/bash

# Function to get millisecond timestamps in a compatible way
get_time_ms() {
    # Use native %N if available, otherwise use seconds only
    if date +%N >/dev/null 2>&1; then
        echo $(($(date +%s) * 1000 + $(date +%N | cut -b1-3)))
    else
        # Fallback to seconds only with fake milliseconds
        echo $(($(date +%s) * 1000))
    fi
}

# Function to generate statistics from the result CSV
analyze_results() {
    local csv_file=$1
    local output_dir=$2
    
    if [ ! -f "$csv_file" ]; then
        echo "Error: CSV file not found: $csv_file"
        return 1
    fi
    
    # Get test duration
    local first_timestamp=$(awk -F, 'NR==2 {print $1}' "$csv_file")
    local last_timestamp=$(awk -F, 'END {print $1}' "$csv_file")
    local test_duration_ms=$((last_timestamp - first_timestamp))
    local test_duration_s=$((test_duration_ms / 1000))
    
    # Count total requests
    local total_requests=$(awk -F, 'NR>1' "$csv_file" | wc -l)
    
    # Calculate TPS
    local tps=$(echo "scale=2; $total_requests / $test_duration_s" | bc)
    
    # Count by result type
    local allowed_count=$(awk -F, 'NR>1 && $4=="ALLOWED" {count++} END {print count+0}' "$csv_file")
    local blocked_count=$(awk -F, 'NR>1 && $4=="BLOCKED" {count++} END {print count+0}' "$csv_file")
    local error_count=$(awk -F, 'NR>1 && $4 ~ /^ERROR/ {count++} END {print count+0}' "$csv_file")
    
    # Payload distribution
    local clean_count=$(awk -F, 'NR>1 && $5 ~ /clean\.json/ {count++} END {print count+0}' "$csv_file")
    local dummy_count=$(awk -F, 'NR>1 && $5 ~ /dummy-secret\.json/ {count++} END {print count+0}' "$csv_file")
    local real_count=$(awk -F, 'NR>1 && $5 ~ /real-secret\.json/ {count++} END {print count+0}' "$csv_file")
    
    # Calculate percentages
    local allowed_pct=$(echo "scale=2; $allowed_count * 100 / $total_requests" | bc)
    local blocked_pct=$(echo "scale=2; $blocked_count * 100 / $total_requests" | bc)
    local error_pct=$(echo "scale=2; $error_count * 100 / $total_requests" | bc)
    
    local clean_pct=$(echo "scale=2; $clean_count * 100 / $total_requests" | bc)
    local dummy_pct=$(echo "scale=2; $dummy_count * 100 / $total_requests" | bc)
    local real_pct=$(echo "scale=2; $real_count * 100 / $total_requests" | bc)
    
    # Calculate response time statistics
    local min_time=$(awk -F, 'NR>1 {print $2}' "$csv_file" | sort -n | head -1)
    local max_time=$(awk -F, 'NR>1 {print $2}' "$csv_file" | sort -n | tail -1)
    local avg_time=$(awk -F, 'NR>1 {sum+=$2} END {print sum/NR-1}' "$csv_file")
    
    # Calculate percentiles
    local sorted_times="${output_dir}/sorted_times.txt"
    awk -F, 'NR>1 {print $2}' "$csv_file" | sort -n > "$sorted_times"
    
    # Debug: check the distribution of response times
    echo "Debug: Response time distribution:" > "${output_dir}/debug_times.txt"
    awk '{count[$1]++} END {for (time in count) print time, count[time]}' "$sorted_times" | \
        sort -n | head -20 >> "${output_dir}/debug_times.txt"
    
    # Calculate percentiles using a simpler, more reliable approach
    if [ -s "$sorted_times" ]; then
        local count=$(wc -l < "$sorted_times")
        echo "Debug: Total data points: $count" >> "${output_dir}/debug_times.txt"
        
        # Basic check of the file
        echo "First 5 lines of sorted_times:" >> "${output_dir}/debug_times.txt"
        head -5 "$sorted_times" >> "${output_dir}/debug_times.txt"
        echo "Last 5 lines of sorted_times:" >> "${output_dir}/debug_times.txt"
        tail -5 "$sorted_times" >> "${output_dir}/debug_times.txt"
        
        # Calculate line numbers for percentiles - using integer math for simplicity
        local p50_line=$(( (count * 50) / 100 ))
        local p90_line=$(( (count * 90) / 100 ))
        local p95_line=$(( (count * 95) / 100 ))
        local p99_line=$(( (count * 99) / 100 ))
        
        # Ensure we have valid line numbers
        [ "$p50_line" -lt 1 ] && p50_line=1
        [ "$p90_line" -lt 1 ] && p90_line=1
        [ "$p95_line" -lt 1 ] && p95_line=1
        [ "$p99_line" -lt 1 ] && p99_line=1
        [ "$p50_line" -gt "$count" ] && p50_line=$count
        [ "$p90_line" -gt "$count" ] && p90_line=$count
        [ "$p95_line" -gt "$count" ] && p95_line=$count
        [ "$p99_line" -gt "$count" ] && p99_line=$count
        
        echo "Percentile line numbers: p50=$p50_line, p90=$p90_line, p95=$p95_line, p99=$p99_line" >> "${output_dir}/debug_times.txt"
        
        # Extract the values at those lines - using head and tail for more reliability
        p50=$(head -n "$p50_line" "$sorted_times" | tail -n 1)
        p90=$(head -n "$p90_line" "$sorted_times" | tail -n 1)
        p95=$(head -n "$p95_line" "$sorted_times" | tail -n 1)
        p99=$(head -n "$p99_line" "$sorted_times" | tail -n 1)
        
        # Add verification
        echo "Extracted percentile values: p50='$p50', p90='$p90', p95='$p95', p99='$p99'" >> "${output_dir}/debug_times.txt"
        
        # Set defaults if values are empty or non-numeric
        [[ ! "$p50" =~ ^[0-9]+(\.[0-9]+)?$ ]] && p50="0"
        [[ ! "$p90" =~ ^[0-9]+(\.[0-9]+)?$ ]] && p90="0"
        [[ ! "$p95" =~ ^[0-9]+(\.[0-9]+)?$ ]] && p95="0"
        [[ ! "$p99" =~ ^[0-9]+(\.[0-9]+)?$ ]] && p99="0"
        
        echo "Final percentile values: p50='$p50', p90='$p90', p95='$p95', p99='$p99'" >> "${output_dir}/debug_times.txt"
    else
        # Default values if no data
        local p50="0"
        local p90="0"
        local p95="0"
        local p99="0"
        echo "Warning: No data in sorted_times file" >> "${output_dir}/debug_times.txt"
    fi
    
    # Create HTML report
    local html_report="${output_dir}/report.html"
    
    echo "<!DOCTYPE html>
<html>
<head>
    <title>GHAS Performance Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        h1, h2 { color: #333; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .metric { margin-bottom: 5px; }
        .label { font-weight: bold; display: inline-block; width: 200px; }
        .value { display: inline-block; }
        .container { display: flex; flex-wrap: wrap; }
        .section { flex: 1; min-width: 300px; margin: 10px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .chart { height: 200px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>GHAS Performance Test Report</h1>
    <p>Test conducted on $(date)</p>
    
    <div class="container">
        <div class="section">
            <h2>Summary</h2>
            <div class="metric"><span class="label">Total Requests:</span> <span class="value">$total_requests</span></div>
            <div class="metric"><span class="label">Test Duration:</span> <span class="value">$test_duration_s seconds</span></div>
            <div class="metric"><span class="label">Transactions Per Second:</span> <span class="value">$tps TPS</span></div>
        </div>
        
        <div class="section">
            <h2>Response Time (ms)</h2>
            <div class="metric"><span class="label">Minimum:</span> <span class="value">$min_time ms</span></div>
            <div class="metric"><span class="label">Maximum:</span> <span class="value">$max_time ms</span></div>
            <div class="metric"><span class="label">Average:</span> <span class="value">$avg_time ms</span></div>
            <div class="metric"><span class="label">50th Percentile (P50):</span> <span class="value">$p50 ms</span></div>
            <div class="metric"><span class="label">90th Percentile (P90):</span> <span class="value">$p90 ms</span></div>
            <div class="metric"><span class="label">95th Percentile (P95):</span> <span class="value">$p95 ms</span></div>
            <div class="metric"><span class="label">99th Percentile (P99):</span> <span class="value">$p99 ms</span></div>
        </div>
    </div>
    
    <div class="container">
        <div class="section">
            <h2>Results</h2>
            <table>
                <tr>
                    <th>Result</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                <tr>
                    <td>Allowed</td>
                    <td>$allowed_count</td>
                    <td>$allowed_pct%</td>
                </tr>
                <tr>
                    <td>Blocked</td>
                    <td>$blocked_count</td>
                    <td>$blocked_pct%</td>
                </tr>
                <tr>
                    <td>Error</td>
                    <td>$error_count</td>
                    <td>$error_pct%</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Payload Distribution</h2>
            <table>
                <tr>
                    <th>Payload Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                <tr>
                    <td>Clean</td>
                    <td>$clean_count</td>
                    <td>$clean_pct%</td>
                </tr>
                <tr>
                    <td>Dummy Secret</td>
                    <td>$dummy_count</td>
                    <td>$dummy_pct%</td>
                </tr>
                <tr>
                    <td>Real Secret</td>
                    <td>$real_count</td>
                    <td>$real_pct%</td>
                </tr>
            </table>
        </div>
    </div>
    
    <div class="section">
        <h2>Test Configuration</h2>
        <div class="metric"><span class="label">Target URL:</span> <span class="value">$(grep 'Target URL' "${output_dir}/test_config.txt" | cut -d ' ' -f 3-)</span></div>
        <div class="metric"><span class="label">Concurrency:</span> <span class="value">$(grep 'Concurrency' "${output_dir}/test_config.txt" | cut -d ' ' -f 2)</span></div>
        <div class="metric"><span class="label">Duration:</span> <span class="value">$(grep 'Duration' "${output_dir}/test_config.txt" | cut -d ' ' -f 2) seconds</span></div>
        <div class="metric"><span class="label">Ramp-up:</span> <span class="value">$(grep 'Ramp-up' "${output_dir}/test_config.txt" | cut -d ' ' -f 2) seconds</span></div>
        <div class="metric"><span class="label">Request Timeout:</span> <span class="value">$(grep 'Timeout' "${output_dir}/test_config.txt" | cut -d ' ' -f 2) seconds</span></div>
        <div class="metric"><span class="label">Clean Payload %:</span> <span class="value">$(grep 'Clean' "${output_dir}/test_config.txt" | cut -d ' ' -f 2)</span></div>
        <div class="metric"><span class="label">Dummy Secret %:</span> <span class="value">$(grep 'Dummy' "${output_dir}/test_config.txt" | cut -d ' ' -f 2)</span></div>
        <div class="metric"><span class="label">Real Secret %:</span> <span class="value">$(grep 'Real' "${output_dir}/test_config.txt" | cut -d ' ' -f 2)</span></div>
    </div>
</body>
</html>" > "$html_report"
    
    # Create a plain text summary
    local text_summary="${output_dir}/summary.txt"
    
    echo "GHAS Performance Test Summary" > "$text_summary"
    echo "============================" >> "$text_summary"
    echo "Test conducted on $(date)" >> "$text_summary"
    echo "" >> "$text_summary"
    echo "Summary:" >> "$text_summary"
    echo "  Total Requests: $total_requests" >> "$text_summary"
    echo "  Test Duration: $test_duration_s seconds" >> "$text_summary"
    echo "  Transactions Per Second: $tps TPS" >> "$text_summary"
    echo "" >> "$text_summary"
    echo "Response Time (ms):" >> "$text_summary"
    echo "  Minimum: $min_time ms" >> "$text_summary"
    echo "  Maximum: $max_time ms" >> "$text_summary"
    echo "  Average: $avg_time ms" >> "$text_summary"
    echo "  50th Percentile (P50): $p50 ms" >> "$text_summary"
    echo "  90th Percentile (P90): $p90 ms" >> "$text_summary"
    echo "  95th Percentile (P95): $p95 ms" >> "$text_summary"
    echo "  99th Percentile (P99): $p99 ms" >> "$text_summary"
    echo "" >> "$text_summary"
    echo "Results:" >> "$text_summary"
    echo "  Allowed: $allowed_count ($allowed_pct%)" >> "$text_summary"
    echo "  Blocked: $blocked_count ($blocked_pct%)" >> "$text_summary"
    echo "  Error: $error_count ($error_pct%)" >> "$text_summary"
    echo "" >> "$text_summary"
    echo "Payload Distribution:" >> "$text_summary"
    echo "  Clean: $clean_count ($clean_pct%)" >> "$text_summary"
    echo "  Dummy Secret: $dummy_count ($dummy_pct%)" >> "$text_summary"
    echo "  Real Secret: $real_count ($real_pct%)" >> "$text_summary"
    
    # Return location of report files
    echo "$text_summary"
    echo "$html_report"
}

# Run the analysis with the provided result file
analyze_results "$1" "$2"
EOF

chmod +x "${OUTPUT_DIR}/analyze_results.sh"

# Save test configuration
cat > "${OUTPUT_DIR}/test_config.txt" << EOF
Target URL $TARGET_URL
Concurrency $CONCURRENCY
Duration $DURATION
Ramp-up $RAMP_UP
Timeout $REQUEST_TIMEOUT
Clean $TEST_CLEAN_PERCENTAGE%
Dummy $TEST_DUMMY_SECRET_PERCENTAGE%
Real $TEST_REAL_SECRET_PERCENTAGE%
EOF

# Check if Docker Compose is running
if ! docker-compose ps >/dev/null 2>&1; then
  echo -e "${YELLOW}Warning: Docker Compose may not be running. The application may not be available.${NC}"
  echo -e "Start the services with: docker-compose up -d"
fi

# Start the performance test
echo -e "${BLUE}Starting performance test focused on certificate and private key detection with the following configuration:${NC}"
echo -e "  ${CYAN}Target URL:${NC} $TARGET_URL"
echo -e "  ${CYAN}Concurrency:${NC} $CONCURRENCY users"
echo -e "  ${CYAN}Duration:${NC} $DURATION seconds"
echo -e "  ${CYAN}Ramp-up:${NC} $RAMP_UP seconds"
echo -e "  ${CYAN}Request Timeout:${NC} $REQUEST_TIMEOUT seconds"
echo -e "  ${CYAN}Payload Distribution:${NC}"
echo -e "    - Clean content: $TEST_CLEAN_PERCENTAGE%"
echo -e "    - Dummy secrets: $TEST_DUMMY_SECRET_PERCENTAGE%"
echo -e "    - Real secrets: $TEST_REAL_SECRET_PERCENTAGE%"

echo -e "\n${YELLOW}Test starting in 3 seconds...${NC}"
sleep 3

# Run the test
echo -e "${GREEN}Test in progress...${NC}"
RESULTS_CSV="${OUTPUT_DIR}/results.csv"
"${OUTPUT_DIR}/run_test.sh" "$TARGET_URL" "$DURATION" "$CONCURRENCY" "$RAMP_UP" "$REQUEST_TIMEOUT" "${OUTPUT_DIR}/select_payload.sh" "$RESULTS_CSV"

# Analyze results
echo -e "\n${BLUE}Analyzing results...${NC}"
SUMMARY=$("${OUTPUT_DIR}/analyze_results.sh" "$RESULTS_CSV" "$OUTPUT_DIR")

# Show summary
echo -e "\n${GREEN}Test completed!${NC}"
echo -e "Results saved to: ${OUTPUT_DIR}"

TEXT_SUMMARY=$(echo "$SUMMARY" | head -n 1)
HTML_REPORT=$(echo "$SUMMARY" | tail -n 1)

echo -e "\n${BLUE}Summary:${NC}"
cat "$TEXT_SUMMARY"

echo -e "\n${BLUE}Detailed HTML report:${NC} $HTML_REPORT"

    # Create a gnuplot script for response time histogram
    if command -v gnuplot &> /dev/null; then
        # Create histogram data
        awk '{print $1}' "$sorted_times" > "${output_dir}/histogram_data.txt"
        
        # Create a gnuplot script for histogram
        cat > "${output_dir}/histogram.gp" << EOF
set terminal png size 1000,500
set output '${output_dir}/response_time_histogram.png'
set title "Response Time Distribution Histogram"
set xlabel "Response Time (ms)"
set ylabel "Frequency"
set style fill solid 0.5
set grid
set xrange [0:*]
binwidth = 5
bin(x,width)=width*floor(x/width)
plot '${output_dir}/histogram_data.txt' using (bin(\$1,binwidth)):(1.0) smooth freq with boxes title "Response Time"
EOF

        # Execute gnuplot
        gnuplot "${output_dir}/histogram.gp"
        echo -e "\n${BLUE}Response time histogram:${NC} ${output_dir}/response_time_histogram.png"
    fi

    # Generate the plot
    gnuplot "${OUTPUT_DIR}/plot.gp"
    echo -e "\n${BLUE}Response time graph:${NC} ${OUTPUT_DIR}/response_time_graph.png"
fi

echo -e "\n${GREEN}Done!${NC}"