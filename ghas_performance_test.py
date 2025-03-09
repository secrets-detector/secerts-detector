#!/usr/bin/env python3
"""
GHAS Performance Testing Script

A Python script to test the performance of the GitHub Advanced Security (GHAS)
push protection endpoint with accurate timing and concurrency.
"""

import argparse
import asyncio
import json
import os
import random
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

import aiohttp
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template

# ANSI color codes
GREEN = '\033[0;32m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
YELLOW = '\033[0;33m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'  # No Color

# Default configuration
DEFAULT_CONFIG = {
    'host': 'localhost',
    'port': '3000',
    'endpoint': '/api/v1/push-protection',
    'protocol': 'http',
    'concurrency': 10,
    'duration': 60,
    'ramp_up': 5,
    'request_timeout': 10,
    'clean_percentage': 30,
    'dummy_secret_percentage': 30,
    'real_secret_percentage': 40,
    'report_dir': './performance-reports'
}

# Test payloads
CLEAN_PAYLOAD = {
    "repository": {
        "owner": "test-org",
        "name": "test-repo"
    },
    "content": "# Configuration\nlog_level: debug\nport: 8080\nhost: 'localhost'\nretry_attempts: 3\nallowed_users: ['admin', 'developer']\ndatabase_url: 'postgres://user:placeholder@localhost:5432/mydb'\n\n# No certificates or private keys in this file",
    "content_type": "file",
    "filename": "config.yaml",
    "ref": "refs/heads/main"
}

DUMMY_SECRET_PAYLOAD = {
    "repository": {
        "owner": "test-org", 
        "name": "test-repo"
    },
    "content": "// This file contains TEST/DUMMY certificates and private keys\n\n// TEST CERTIFICATE\n-----BEGIN CERTIFICATE-----\nTEST_CERTIFICATE_FOR_DEVELOPMENT_ONLY\nMIIDazCCAlOgAwIBAgIUXQzF4d4eXBYyGcQf3RJVsEZ1eQ8wDQYJKoZIhvcNAQEL\nBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM\nGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzA1MTUxMjAwMDBaFw0yNDA1\nMTQxMjAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw\nHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQC5eIuoSCHDCIWgI2CObfvgJCyPulUGj0VxbOJmZWzl\n-----END CERTIFICATE-----\n\n// DUMMY PRIVATE KEY\n-----BEGIN PRIVATE KEY-----\nDUMMY_PRIVATE_KEY_DO_NOT_USE\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5F0ifNQF20kJi\nzRTmsea44zy0xM8+BjZ7pEr587gO6Ov3KoKZCV4xcFhvJ/9yWgRWoCYMvpOIxW/G\nWufmRObVReT7bhYYZquJcpOBgNJ7elPwKxi7mZ18Dedlf+fowwx3L5+agq2SZ4AV\n4ftNWl3R9uz5SiuGGkdQ14G4AMzEabV6hf53VZ1bvPM48bLZ2BzJRjrdcWFmCUla\n-----END PRIVATE KEY-----",
    "content_type": "file",
    "filename": "test-certs-and-keys.js",
    "ref": "refs/heads/feature/test-keys"
}

REAL_SECRET_PAYLOAD = {
    "repository": {
        "owner": "test-org",
        "name": "test-repo"
    },
    "content": "# Sensitive Configuration File\n\n# Production Certificate\n-----BEGIN CERTIFICATE-----\nMIIFHTCCAwWgAwIBAgIUUGihu0CQ3okROlCakzXXIODzMqUwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAwwTU2VjcmV0cy1EZXRlY3Rvci1DQTAeFw0yNTAzMDgyMDU3\nNDFaFw0yNjAzMDgyMDU3NDFaMB4xHDAaBgNVBAMME1NlY3JldHMtRGV0ZWN0b3It\nQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDPTNL0QNlOaymOGVSO\nfmkOSlmxFK1HhprMzdm+EWSMeWj/r8TrGQrgQoLsZU8cW94jkmjcNfU9C+xfUR9G\nJoAwEfCMmr/wHNETH8XCVbgIkqw8AHgpn4gS2NhhhoxsQ/PnzhHS3juNeWB4hcmQ\nayuudLsUad+bWQPn7+JS4n3JZQ1ikfjd+a5W+FDAzcdOLvK1QTnb3s74zDRzYQz0\n-----END CERTIFICATE-----\n\n# Private Key (DO NOT SHARE)\n-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDDCyQTg9KwEAgq\n8R87wvDBBD2OKOkNaykfoxloSU5Jnx6XThV3Nf3eipmBKw+kTkfEGSalw8c0qSU2\npTcm6yL8/lXbNydc7pXBq5fI24+eXJ33rg4+GV6z80m9Fxs+6ChPTqi7Rn+UpCd+\nVEQGTQgxV8uDvgNAughWFJsYcliNjB91rHhsmx0W567i8qi6EyofGMxQ4wvbYoQy\n1N9Gmq1wixdFDmVSKlD1CASUdtKIf3IWb0PKwjYxoiMznyPpIjD1KfC9WF2dvirf\nyrZk3F2fgSN5pEv51f6u6pKbSnCaNcOqr+/7SwAN7Lj3iMRYxhah8uCLu76a2Ant\n5yRqlcPNAgMBAAECggEAJqCX+Dpw+TfvmiuPQztoCV3w3+znvOXWauLXBxGPjOKT\nwSTweN/LQ63g2VVBH4n2ShauEgG8O8hs643cZpuGXiLzt3rMk6nXpFe6s4eSQat3\niIQi43cMS6i415dSKMr7IrvCDHbZkQNSpAEFyNasMvN/hXuV8tV1DbE+hyCsO3nm\nRdjU2LMOCmcJXoSrNIoEFXuvPJ5DvuxbI3gI4iabDxIlsrSF26QdSYF6FgwYZP+r\nDIGbw4a3dcY6hgCc6uUcjSX3Xh/E2y5dwP5u8Hsyn+3kOrVmtEcIoypdF7EtnUJA\n-----END PRIVATE KEY-----",
    "content_type": "file",
    "filename": "credentials.txt",
    "ref": "refs/heads/main"
}

class GHASPerformanceTester:
    """GHAS Performance Testing Tool"""
    
    def __init__(self, config):
        """Initialize the tester with the given configuration"""
        self.config = config
        self.results = []
        self.start_time = None
        self.end_time = None
        self.payloads = {
            'clean': CLEAN_PAYLOAD,
            'dummy': DUMMY_SECRET_PAYLOAD,
            'real': REAL_SECRET_PAYLOAD
        }
        
        # Ensure report directory exists
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(f"{config['report_dir']}/{self.timestamp}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Construct target URL
        self.target_url = f"{config['protocol']}://{config['host']}:{config['port']}{config['endpoint']}"

    def select_payload(self):
        """Select a random payload based on configured percentages"""
        rand = random.randint(1, 100)
        if rand <= self.config['clean_percentage']:
            return 'clean', self.payloads['clean']
        elif rand <= self.config['clean_percentage'] + self.config['dummy_secret_percentage']:
            return 'dummy', self.payloads['dummy']
        else:
            return 'real', self.payloads['real']

    async def send_request(self, session, user_id):
        """Send a single request to the target endpoint"""
        payload_type, payload = self.select_payload()
        
        start_time = time.time()
        try:
            async with session.post(
                self.target_url, 
                json=payload, 
                timeout=self.config['request_timeout']
            ) as response:
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to ms
                
                # Parse the response
                response_data = await response.json()
                status_code = response.status
                is_allowed = response_data.get('allow', False)
                blocking_findings = len(response_data.get('blocking_findings', []))
                non_blocking_findings = len(response_data.get('non_blocking_findings', []))
                
                # Determine result
                if status_code == 200:
                    result = "ALLOWED" if is_allowed else "BLOCKED"
                else:
                    result = f"ERROR_{status_code}"
                
                # Record the result
                self.results.append({
                    'timestamp': int(start_time * 1000),  # Unix timestamp in ms
                    'response_time': response_time,
                    'http_code': status_code,
                    'result': result,
                    'payload_type': payload_type,
                    'is_allowed': is_allowed,
                    'blocking_findings': blocking_findings,
                    'non_blocking_findings': non_blocking_findings,
                    'user_id': user_id
                })
                
                return True
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000  # Convert to ms
            
            # Record the error
            self.results.append({
                'timestamp': int(start_time * 1000),  # Unix timestamp in ms
                'response_time': response_time,
                'http_code': 0,
                'result': f"ERROR_{type(e).__name__}",
                'payload_type': payload_type,
                'is_allowed': False,
                'blocking_findings': 0,
                'non_blocking_findings': 0,
                'user_id': user_id
            })
            
            return False

    async def user_task(self, user_id, start_event):
        """Task representing a single user's activity"""
        # Wait for the start event
        await start_event.wait()
        
        # Calculate end time
        end_time = time.time() + self.config['duration']
        
        async with aiohttp.ClientSession() as session:
            while time.time() < end_time:
                await self.send_request(session, user_id)
                
                # Small sleep to prevent overwhelming
                await asyncio.sleep(0.05)

    async def run_test(self):
        """Run the performance test"""
        print(f"{BLUE}Starting performance test with the following configuration:{NC}")
        print(f"  {CYAN}Target URL:{NC} {self.target_url}")
        print(f"  {CYAN}Concurrency:{NC} {self.config['concurrency']} users")
        print(f"  {CYAN}Duration:{NC} {self.config['duration']} seconds")
        print(f"  {CYAN}Ramp-up:{NC} {self.config['ramp_up']} seconds")
        print(f"  {CYAN}Request Timeout:{NC} {self.config['request_timeout']} seconds")
        print(f"  {CYAN}Payload Distribution:{NC}")
        print(f"    - Clean content: {self.config['clean_percentage']}%")
        print(f"    - Dummy secrets: {self.config['dummy_secret_percentage']}%")
        print(f"    - Real secrets: {self.config['real_secret_percentage']}%")
        
        print(f"\n{YELLOW}Test starting in 3 seconds...{NC}")
        await asyncio.sleep(3)
        
        print(f"{GREEN}Test in progress...{NC}")
        
        # Record start time
        self.start_time = time.time()
        
        # Create a shared event for coordinating the start
        start_event = asyncio.Event()
        
        # Create user tasks
        user_tasks = []
        for i in range(self.config['concurrency']):
            user_tasks.append(asyncio.create_task(self.user_task(i+1, start_event)))
            
            # Ramp up gradually
            if i > 0 and self.config['ramp_up'] > 0:
                ramp_delay = self.config['ramp_up'] / self.config['concurrency']
                await asyncio.sleep(ramp_delay)
            
            # Signal this user to start
            start_event.set()
            
            # Reset the event for the next user
            if i < self.config['concurrency'] - 1:
                start_event = asyncio.Event()
        
        # Wait for the test duration to complete
        remaining_time = self.config['duration'] + 2  # Add a little extra time for tasks to complete
        print(f"All users started. Test will run for {self.config['duration']} seconds...")
        await asyncio.sleep(remaining_time)
        
        # Cancel any remaining tasks
        for task in user_tasks:
            if not task.done():
                task.cancel()
        
        # Record end time
        self.end_time = time.time()
        
        print(f"{GREEN}Test completed!{NC}")
        
    def analyze_results(self):
        """Analyze the test results and generate reports"""
        print(f"\n{BLUE}Analyzing results...{NC}")
        
        # Convert results to DataFrame for easier analysis
        df = pd.DataFrame(self.results)
        
        # Save raw results
        results_csv = self.output_dir / "results.csv"
        df.to_csv(results_csv, index=False)
        
        # Basic statistics
        total_requests = len(df)
        test_duration_s = self.end_time - self.start_time
        tps = total_requests / test_duration_s
        
        # Response time statistics
        if total_requests > 0:
            min_time = df['response_time'].min()
            max_time = df['response_time'].max()
            avg_time = df['response_time'].mean()
            
            # Calculate percentiles
            p50 = df['response_time'].quantile(0.5)
            p90 = df['response_time'].quantile(0.9)
            p95 = df['response_time'].quantile(0.95)
            p99 = df['response_time'].quantile(0.99)
        else:
            min_time = max_time = avg_time = p50 = p90 = p95 = p99 = 0
        
        # Count by result type
        allowed_count = len(df[df['result'] == 'ALLOWED'])
        blocked_count = len(df[df['result'] == 'BLOCKED'])
        error_count = len(df[~df['result'].isin(['ALLOWED', 'BLOCKED'])])
        
        # Payload distribution
        clean_count = len(df[df['payload_type'] == 'clean'])
        dummy_count = len(df[df['payload_type'] == 'dummy'])
        real_count = len(df[df['payload_type'] == 'real'])
        
        # Calculate percentages
        allowed_pct = (allowed_count / total_requests * 100) if total_requests > 0 else 0
        blocked_pct = (blocked_count / total_requests * 100) if total_requests > 0 else 0
        error_pct = (error_count / total_requests * 100) if total_requests > 0 else 0
        
        clean_pct = (clean_count / total_requests * 100) if total_requests > 0 else 0
        dummy_pct = (dummy_count / total_requests * 100) if total_requests > 0 else 0
        real_pct = (real_count / total_requests * 100) if total_requests > 0 else 0
        
        # Create plots if we have data
        if total_requests > 0:
            # Response time histogram
            plt.figure(figsize=(10, 6))
            plt.hist(df['response_time'], bins=30, alpha=0.7)
            plt.title('Response Time Distribution')
            plt.xlabel('Response Time (ms)')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            plt.savefig(self.output_dir / 'response_time_histogram.png')
            
            # Response time over time
            plt.figure(figsize=(12, 6))
            plt.scatter(df['timestamp'] - df['timestamp'].min(), df['response_time'], 
                      alpha=0.3, s=10)
            plt.title('Response Time Over Test Duration')
            plt.xlabel('Time (ms)')
            plt.ylabel('Response Time (ms)')
            plt.grid(True, alpha=0.3)
            plt.savefig(self.output_dir / 'response_time_over_time.png')
        
        # Save test configuration
        with open(self.output_dir / "test_config.txt", "w") as f:
            f.write(f"Target URL {self.target_url}\n")
            f.write(f"Concurrency {self.config['concurrency']}\n")
            f.write(f"Duration {self.config['duration']}\n")
            f.write(f"Ramp-up {self.config['ramp_up']}\n")
            f.write(f"Timeout {self.config['request_timeout']}\n")
            f.write(f"Clean {self.config['clean_percentage']}%\n")
            f.write(f"Dummy {self.config['dummy_secret_percentage']}%\n")
            f.write(f"Real {self.config['real_secret_percentage']}%\n")
        
        # Create HTML report
        html_template = """
<!DOCTYPE html>
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
        .chart { text-align: center; margin: 20px 0; }
        .chart img { max-width: 100%; }
    </style>
</head>
<body>
    <h1>GHAS Performance Test Report</h1>
    <p>Test conducted on {{ timestamp }}</p>
    
    <div class="container">
        <div class="section">
            <h2>Summary</h2>
            <div class="metric"><span class="label">Total Requests:</span> <span class="value">{{ total_requests }}</span></div>
            <div class="metric"><span class="label">Test Duration:</span> <span class="value">{{ test_duration_s|round(2) }} seconds</span></div>
            <div class="metric"><span class="label">Transactions Per Second:</span> <span class="value">{{ tps|round(2) }} TPS</span></div>
        </div>
        
        <div class="section">
            <h2>Response Time (ms)</h2>
            <div class="metric"><span class="label">Minimum:</span> <span class="value">{{ min_time|round(2) }} ms</span></div>
            <div class="metric"><span class="label">Maximum:</span> <span class="value">{{ max_time|round(2) }} ms</span></div>
            <div class="metric"><span class="label">Average:</span> <span class="value">{{ avg_time|round(2) }} ms</span></div>
            <div class="metric"><span class="label">50th Percentile (P50):</span> <span class="value">{{ p50|round(2) }} ms</span></div>
            <div class="metric"><span class="label">90th Percentile (P90):</span> <span class="value">{{ p90|round(2) }} ms</span></div>
            <div class="metric"><span class="label">95th Percentile (P95):</span> <span class="value">{{ p95|round(2) }} ms</span></div>
            <div class="metric"><span class="label">99th Percentile (P99):</span> <span class="value">{{ p99|round(2) }} ms</span></div>
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
                    <td>{{ allowed_count }}</td>
                    <td>{{ allowed_pct|round(2) }}%</td>
                </tr>
                <tr>
                    <td>Blocked</td>
                    <td>{{ blocked_count }}</td>
                    <td>{{ blocked_pct|round(2) }}%</td>
                </tr>
                <tr>
                    <td>Error</td>
                    <td>{{ error_count }}</td>
                    <td>{{ error_pct|round(2) }}%</td>
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
                    <td>{{ clean_count }}</td>
                    <td>{{ clean_pct|round(2) }}%</td>
                </tr>
                <tr>
                    <td>Dummy Secret</td>
                    <td>{{ dummy_count }}</td>
                    <td>{{ dummy_pct|round(2) }}%</td>
                </tr>
                <tr>
                    <td>Real Secret</td>
                    <td>{{ real_count }}</td>
                    <td>{{ real_pct|round(2) }}%</td>
                </tr>
            </table>
        </div>
    </div>
    
    <div class="section">
        <h2>Test Configuration</h2>
        <div class="metric"><span class="label">Target URL:</span> <span class="value">{{ target_url }}</span></div>
        <div class="metric"><span class="label">Concurrency:</span> <span class="value">{{ concurrency }}</span></div>
        <div class="metric"><span class="label">Duration:</span> <span class="value">{{ duration }} seconds</span></div>
        <div class="metric"><span class="label">Ramp-up:</span> <span class="value">{{ ramp_up }} seconds</span></div>
        <div class="metric"><span class="label">Request Timeout:</span> <span class="value">{{ request_timeout }} seconds</span></div>
        <div class="metric"><span class="label">Clean Payload %:</span> <span class="value">{{ clean_percentage }}%</span></div>
        <div class="metric"><span class="label">Dummy Secret %:</span> <span class="value">{{ dummy_percentage }}%</span></div>
        <div class="metric"><span class="label">Real Secret %:</span> <span class="value">{{ real_percentage }}%</span></div>
    </div>
    
    {% if total_requests > 0 %}
    <div class="section">
        <h2>Charts</h2>
        <div class="chart">
            <h3>Response Time Distribution</h3>
            <img src="response_time_histogram.png" alt="Response Time Histogram">
        </div>
        <div class="chart">
            <h3>Response Time Over Test Duration</h3>
            <img src="response_time_over_time.png" alt="Response Time Over Time">
        </div>
    </div>
    {% endif %}
</body>
</html>
"""
        
        template = Template(html_template)
        html_report = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_requests=total_requests,
            test_duration_s=test_duration_s,
            tps=tps,
            min_time=min_time,
            max_time=max_time,
            avg_time=avg_time,
            p50=p50,
            p90=p90,
            p95=p95,
            p99=p99,
            allowed_count=allowed_count,
            blocked_count=blocked_count,
            error_count=error_count,
            allowed_pct=allowed_pct,
            blocked_pct=blocked_pct,
            error_pct=error_pct,
            clean_count=clean_count,
            dummy_count=dummy_count,
            real_count=real_count,
            clean_pct=clean_pct,
            dummy_pct=dummy_pct,
            real_pct=real_pct,
            target_url=self.target_url,
            concurrency=self.config['concurrency'],
            duration=self.config['duration'],
            ramp_up=self.config['ramp_up'],
            request_timeout=self.config['request_timeout'],
            clean_percentage=self.config['clean_percentage'],
            dummy_percentage=self.config['dummy_secret_percentage'],
            real_percentage=self.config['real_secret_percentage']
        )
        
        with open(self.output_dir / "report.html", "w") as f:
            f.write(html_report)
        
        # Create a text summary
        text_summary = f"""GHAS Performance Test Summary
============================
Test conducted on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Summary:
  Total Requests: {total_requests}
  Test Duration: {test_duration_s:.2f} seconds
  Transactions Per Second: {tps:.2f} TPS

Response Time (ms):
  Minimum: {min_time:.2f} ms
  Maximum: {max_time:.2f} ms
  Average: {avg_time:.2f} ms
  50th Percentile (P50): {p50:.2f} ms
  90th Percentile (P90): {p90:.2f} ms
  95th Percentile (P95): {p95:.2f} ms
  99th Percentile (P99): {p99:.2f} ms

Results:
  Allowed: {allowed_count} ({allowed_pct:.2f}%)
  Blocked: {blocked_count} ({blocked_pct:.2f}%)
  Error: {error_count} ({error_pct:.2f}%)

Payload Distribution:
  Clean: {clean_count} ({clean_pct:.2f}%)
  Dummy Secret: {dummy_count} ({dummy_pct:.2f}%)
  Real Secret: {real_count} ({real_pct:.2f}%)
"""
        
        with open(self.output_dir / "summary.txt", "w") as f:
            f.write(text_summary)
        
        print(f"\n{GREEN}Test completed!{NC}")
        print(f"Results saved to: {self.output_dir}")
        print(f"\n{BLUE}Summary:{NC}")
        print(text_summary)
        print(f"\n{BLUE}Detailed HTML report:{NC} {self.output_dir}/report.html")
        
        return {
            'summary': self.output_dir / "summary.txt",
            'html_report': self.output_dir / "report.html"
        }

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='GHAS Performance Testing Tool')
    
    # Add command line arguments
    parser.add_argument('-H', '--host', default=DEFAULT_CONFIG['host'],
                        help=f'Target host (default: {DEFAULT_CONFIG["host"]})')
    parser.add_argument('-p', '--port', default=DEFAULT_CONFIG['port'],
                        help=f'Target port (default: {DEFAULT_CONFIG["port"]})')
    parser.add_argument('-e', '--endpoint', default=DEFAULT_CONFIG['endpoint'],
                        help=f'Target endpoint (default: {DEFAULT_CONFIG["endpoint"]})')
    parser.add_argument('-s', '--secure', action='store_true',
                        help='Use HTTPS instead of HTTP')
    parser.add_argument('-c', '--concurrency', type=int, default=DEFAULT_CONFIG['concurrency'],
                        help=f'Number of concurrent users (default: {DEFAULT_CONFIG["concurrency"]})')
    parser.add_argument('-d', '--duration', type=int, default=DEFAULT_CONFIG['duration'],
                        help=f'Test duration in seconds (default: {DEFAULT_CONFIG["duration"]})')
    parser.add_argument('-r', '--ramp-up', type=int, default=DEFAULT_CONFIG['ramp_up'],
                        help=f'Ramp-up time in seconds (default: {DEFAULT_CONFIG["ramp_up"]})')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_CONFIG['request_timeout'],
                        help=f'Request timeout in seconds (default: {DEFAULT_CONFIG["request_timeout"]})')
    parser.add_argument('--clean', type=int, default=DEFAULT_CONFIG['clean_percentage'],
                        help=f'Percentage of clean payloads (default: {DEFAULT_CONFIG["clean_percentage"]})')
    parser.add_argument('--dummy', type=int, default=DEFAULT_CONFIG['dummy_secret_percentage'],
                        help=f'Percentage of payloads with dummy secrets (default: {DEFAULT_CONFIG["dummy_secret_percentage"]})')
    parser.add_argument('--real', type=int, default=DEFAULT_CONFIG['real_secret_percentage'],
                        help=f'Percentage of payloads with real secrets (default: {DEFAULT_CONFIG["real_secret_percentage"]})')
    parser.add_argument('-o', '--output', default=DEFAULT_CONFIG['report_dir'],
                        help=f'Output directory for reports (default: {DEFAULT_CONFIG["report_dir"]})')
    
    args = parser.parse_args()
    
    # Check payload percentages
    total_percentage = args.clean + args.dummy + args.real
    if total_percentage != 100:
        print(f"{RED}Error: Payload percentages must sum to 100 (currently {total_percentage}){NC}")
        print(f"Clean: {args.clean}%, Dummy secrets: {args.dummy}%, Real secrets: {args.real}%")
        sys.exit(1)
    
    # Configure test
    config = {
        'host': args.host,
        'port': args.port,
        'endpoint': args.endpoint,
        'protocol': 'https' if args.secure else 'http',
        'concurrency': args.concurrency,
        'duration': args.duration,
        'ramp_up': args.ramp_up,
        'request_timeout': args.timeout,
        'clean_percentage': args.clean,
        'dummy_secret_percentage': args.dummy,
        'real_secret_percentage': args.real,
        'report_dir': args.output
    }
    
    # Create and run the tester
    tester = GHASPerformanceTester(config)
    await tester.run_test()
    tester.analyze_results()

if __name__ == '__main__':
    asyncio.run(main())