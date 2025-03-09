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
