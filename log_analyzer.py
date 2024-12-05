import re
import pandas as pd
import numpy as np
from collections import defaultdict, Counter
from rich.console import Console
from rich.table import Table
from rich.progress import track
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import json
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from mlxtend.frequent_patterns import fpgrowth
from mlxtend.preprocessing import TransactionEncoder
import networkx as nx
from statsmodels.tsa.holtwinters import ExponentialSmoothing

class LogAnalyzer:
    def __init__(self, log_file, failed_login_threshold=5):
        self.log_file = log_file
        self.failed_login_threshold = failed_login_threshold
        self.console = Console()
        self.ip_requests = defaultdict(int)
        self.endpoint_counts = defaultdict(int)
        self.failed_logins = defaultdict(int)
        self.ip_timestamps = defaultdict(list)  # For rate limiting analysis
        self.status_codes = defaultdict(int)    # For response code analysis
        self.hourly_requests = defaultdict(int)  # For temporal analysis
        self.ip_features = defaultdict(lambda: defaultdict(int))  # For ML features
        self.ip_sequences = defaultdict(list)  # For sequential pattern mining
        self.ip_endpoint_sequences = defaultdict(list)  # For endpoint sequence analysis

    def parse_log_line(self, line):
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        endpoint_pattern = r'"[A-Z]+ ([^"]+)'
        status_pattern = r'" (\d{3})'
        timestamp_pattern = r'\[([^\]]+)\]'
        
        ip_match = re.search(ip_pattern, line)
        endpoint_match = re.search(endpoint_pattern, line)
        status_match = re.search(status_pattern, line)
        timestamp_match = re.search(timestamp_pattern, line)
        
        if all([ip_match, endpoint_match, status_match, timestamp_match]):
            parsed_data = {
                'ip': ip_match.group(1),
                'endpoint': endpoint_match.group(1).split()[0],
                'status': status_match.group(1),
                'timestamp': timestamp_match.group(1)
            }
            # Extract hour for temporal analysis
            timestamp = datetime.strptime(parsed_data['timestamp'].split()[0], "%d/%b/%Y:%H:%M:%S")
            parsed_data['hour'] = timestamp.hour
            return parsed_data
        return None

    def analyze_logs(self):
        total_lines = sum(1 for _ in open(self.log_file, 'r'))
        
        with open(self.log_file, 'r') as f:
            for line in track(f, total=total_lines, description="Analyzing logs..."):
                parsed = self.parse_log_line(line)
                if parsed:
                    ip = parsed['ip']
                    self.ip_requests[ip] += 1
                    self.endpoint_counts[parsed['endpoint']] += 1
                    self.status_codes[parsed['status']] += 1
                    self.hourly_requests[parsed['hour']] += 1
                    
                    # Collect features for ML
                    self.ip_features[ip]['total_requests'] += 1
                    self.ip_features[ip]['status_' + parsed['status']] += 1
                    self.ip_features[ip]['hour_' + str(parsed['hour'])] += 1
                    
                    # Track timestamps for rate limiting analysis
                    timestamp = datetime.strptime(parsed['timestamp'].split()[0], "%d/%b/%Y:%H:%M:%S")
                    self.ip_timestamps[ip].append(timestamp)
                    
                    # Track sequences for pattern mining
                    self.ip_sequences[ip].append(f"{parsed['status']}_{parsed['endpoint']}")
                    self.ip_endpoint_sequences[ip].append(parsed['endpoint'])
                    
                    # Track failed logins
                    if parsed['status'] == '401' and "login" in parsed['endpoint'].lower():
                        self.failed_logins[ip] += 1

    def detect_anomalies(self):
        # Prepare feature matrix
        ips = list(self.ip_features.keys())
        features = []
        
        for ip in ips:
            ip_data = self.ip_features[ip]
            feature_vector = [
                ip_data['total_requests'],
                ip_data['status_200'] / max(ip_data['total_requests'], 1),
                ip_data['status_401'] / max(ip_data['total_requests'], 1),
                ip_data['status_403'] / max(ip_data['total_requests'], 1),
                ip_data['status_404'] / max(ip_data['total_requests'], 1),
                ip_data['status_500'] / max(ip_data['total_requests'], 1),
            ]
            
            # Add hourly distribution features
            for hour in range(24):
                feature_vector.append(ip_data[f'hour_{hour}'] / max(ip_data['total_requests'], 1))
            
            features.append(feature_vector)
        
        # Convert to numpy array and scale features
        X = np.array(features)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest
        clf = IsolationForest(contamination=0.1, random_state=42)
        predictions = clf.fit_predict(X_scaled)
        
        # Collect anomalous IPs
        anomalous_ips = []
        for idx, pred in enumerate(predictions):
            if pred == -1:  # Anomaly
                anomalous_ips.append({
                    'ip': ips[idx],
                    'total_requests': self.ip_features[ips[idx]]['total_requests'],
                    'failed_logins': self.failed_logins[ips[idx]],
                    'unique_status_codes': len([k for k in self.ip_features[ips[idx]].keys() if k.startswith('status_')])
                })
        
        return sorted(anomalous_ips, key=lambda x: x['total_requests'], reverse=True)

    def generate_visualizations(self):
        # Create visualizations directory if it doesn't exist
        Path("visualizations").mkdir(exist_ok=True)
        
        # IP Requests Distribution
        fig = px.bar(
            x=list(self.ip_requests.keys()),
            y=list(self.ip_requests.values()),
            title="Requests per IP Address",
            labels={'x': 'IP Address', 'y': 'Number of Requests'}
        )
        fig.write_html("visualizations/ip_requests.html")
        
        # Endpoint Distribution
        fig = px.pie(
            values=list(self.endpoint_counts.values()),
            names=list(self.endpoint_counts.keys()),
            title="Endpoint Distribution"
        )
        fig.write_html("visualizations/endpoint_distribution.html")
        
        # Status Code Distribution
        fig = px.bar(
            x=list(self.status_codes.keys()),
            y=list(self.status_codes.values()),
            title="HTTP Status Code Distribution",
            labels={'x': 'Status Code', 'y': 'Count'}
        )
        fig.write_html("visualizations/status_codes.html")

    def detect_rate_limiting(self, requests_threshold=10, time_window_seconds=60):
        potential_dos = {}
        for ip, timestamps in self.ip_timestamps.items():
            timestamps.sort()
            for i in range(len(timestamps) - requests_threshold + 1):
                window = timestamps[i:i + requests_threshold]
                if (window[-1] - window[0]).total_seconds() <= time_window_seconds:
                    potential_dos[ip] = len(window)
        return potential_dos

    def analyze_attack_patterns(self):
        # 1. Sequential Pattern Mining
        sequences = []
        for ip, seq in self.ip_sequences.items():
            if len(seq) >= 3:  # Only analyze IPs with enough activity
                sequences.append(seq)
        
        if not sequences:
            return None, None, None
        
        try:
            te = TransactionEncoder()
            te_ary = te.fit(sequences).transform(sequences)
            df = pd.DataFrame(te_ary, columns=te.columns_)
            
            # Find frequent patterns
            frequent_patterns = fpgrowth(df, min_support=0.1, use_colnames=True)
            frequent_patterns['length'] = frequent_patterns['itemsets'].apply(len)
            frequent_patterns = frequent_patterns[frequent_patterns['length'] > 1]
        except Exception:
            frequent_patterns = None
        
        # 2. Attack Graph Analysis
        try:
            G = nx.DiGraph()
            
            # Build transition graph
            for ip, endpoints in self.ip_endpoint_sequences.items():
                for i in range(len(endpoints) - 1):
                    current = endpoints[i]
                    next_endpoint = endpoints[i + 1]
                    if G.has_edge(current, next_endpoint):
                        G[current][next_endpoint]['weight'] += 1
                    else:
                        G.add_edge(current, next_endpoint, weight=1)
            
            if len(G.nodes()) > 0:
                # Calculate endpoint centrality
                centrality = nx.eigenvector_centrality_numpy(G, weight='weight')
                critical_endpoints = {k: v for k, v in sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:3]}
            else:
                critical_endpoints = None
        except Exception:
            critical_endpoints = None
        
        # 3. Time Series Analysis and Prediction
        try:
            hourly_series = pd.Series(self.hourly_requests)
            if len(hourly_series) >= 48:  # Only attempt forecasting with enough data
                model = ExponentialSmoothing(
                    hourly_series,
                    seasonal_periods=24,
                    trend='add',
                    seasonal='add',
                ).fit()
                
                # Predict next 24 hours
                forecast = model.forecast(24)
                peak_hours = forecast.nlargest(3)
            else:
                peak_hours = pd.Series(self.hourly_requests).nlargest(3)  # Just show current peak hours
        except Exception:
            peak_hours = None
        
        return frequent_patterns, critical_endpoints, peak_hours

    def display_results(self):
        # 1. Requests per IP
        ip_table = Table(title="Requests per IP Address")
        ip_table.add_column("IP Address", style="cyan")
        ip_table.add_column("Request Count", style="magenta")
        
        sorted_ips = sorted(self.ip_requests.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            ip_table.add_row(ip, str(count))
        
        self.console.print(ip_table)
        self.console.print()
        
        # 2. Most Accessed Endpoint
        most_accessed = max(self.endpoint_counts.items(), key=lambda x: x[1])
        self.console.print(f"[green]Most Frequently Accessed Endpoint:[/green]")
        self.console.print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
        self.console.print()
        
        # 3. Suspicious Activity
        suspicious_table = Table(title="Suspicious Activity (Failed Login Attempts)")
        suspicious_table.add_column("IP Address", style="red")
        suspicious_table.add_column("Failed Login Count", style="yellow")
        
        suspicious_ips = {ip: count for ip, count in self.failed_logins.items() 
                         if count >= self.failed_login_threshold}
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            suspicious_table.add_row(ip, str(count))
        
        self.console.print(suspicious_table)
        self.console.print()
        
        # 4. Rate Limiting Analysis
        dos_attempts = self.detect_rate_limiting()
        if dos_attempts:
            dos_table = Table(title="Potential DoS Attempts (High Request Rate)")
            dos_table.add_column("IP Address", style="red")
            dos_table.add_column("Requests in Window", style="yellow")
            
            for ip, count in sorted(dos_attempts.items(), key=lambda x: x[1], reverse=True):
                dos_table.add_row(ip, str(count))
            
            self.console.print(dos_table)
        
        # 5. ML-based Anomaly Detection
        self.console.print("\n[bold magenta]Machine Learning-based Anomaly Detection[/bold magenta]")
        anomalies = self.detect_anomalies()
        
        if anomalies:
            anomaly_table = Table(title="Detected Anomalous IP Addresses")
            anomaly_table.add_column("IP Address", style="red")
            anomaly_table.add_column("Total Requests", style="yellow")
            anomaly_table.add_column("Failed Logins", style="yellow")
            anomaly_table.add_column("Unique Status Codes", style="yellow")
            
            for anomaly in anomalies:
                anomaly_table.add_row(
                    anomaly['ip'],
                    str(anomaly['total_requests']),
                    str(anomaly['failed_logins']),
                    str(anomaly['unique_status_codes'])
                )
            
            self.console.print(anomaly_table)
            self.console.print("\n[yellow]These IPs show unusual patterns and might require investigation.[/yellow]")
        else:
            self.console.print("[green]No anomalous behavior detected.[/green]")
        
        # 6. Advanced Attack Pattern Analysis
        self.console.print("\n[bold magenta]Predictive Attack Pattern Analysis[/bold magenta]")
        
        patterns, critical_endpoints, peak_hours = self.analyze_attack_patterns()
        
        if patterns is not None and not patterns.empty:
            pattern_table = Table(title="Discovered Attack Patterns")
            pattern_table.add_column("Pattern", style="cyan")
            pattern_table.add_column("Support", style="yellow")
            
            for _, row in patterns.nlargest(5, 'support').iterrows():
                pattern = ' -> '.join(sorted(row['itemsets']))  # Using ASCII arrow instead of Unicode
                pattern_table.add_row(pattern, f"{row['support']:.3f}")
            
            self.console.print(pattern_table)
        else:
            self.console.print("[yellow]Not enough sequential data to discover attack patterns.[/yellow]")
        
        if critical_endpoints:
            self.console.print("\n[yellow]Critical Endpoints (Potential Attack Targets):[/yellow]")
            endpoint_table = Table()
            endpoint_table.add_column("Endpoint", style="cyan")
            endpoint_table.add_column("Risk Score", style="red")
            
            for endpoint, score in critical_endpoints.items():
                endpoint_table.add_row(endpoint, f"{score:.3f}")
            
            self.console.print(endpoint_table)
        else:
            self.console.print("[yellow]Not enough endpoint transition data for risk analysis.[/yellow]")
        
        if peak_hours is not None:
            if len(self.hourly_requests) >= 48:
                title = "\n[yellow]Predicted Peak Attack Hours (Next 24h):[/yellow]"
            else:
                title = "\n[yellow]Current Peak Hours:[/yellow]"
            
            self.console.print(title)
            hours_table = Table()
            hours_table.add_column("Hour", style="cyan")
            hours_table.add_column("Requests", style="red")
            
            for hour, pred in peak_hours.items():
                hours_table.add_row(f"Hour {hour}", f"{pred:.1f}")
            
            self.console.print(hours_table)
            
            if len(self.hourly_requests) >= 48:
                self.console.print("\n[red]⚠ High-risk time windows identified![/red]")
                self.console.print("[yellow]Consider implementing additional security measures during these hours.[/yellow]")
            else:
                self.console.print("\n[yellow]Note: Limited time data available. Showing current peak hours instead of predictions.[/yellow]")
        else:
            self.console.print("[yellow]Not enough temporal data for peak hour analysis.[/yellow]")
    
    def save_results(self):
        try:
            # Prepare DataFrames for each section
            ip_requests_df = pd.DataFrame(list(self.ip_requests.items()), 
                                        columns=['IP Address', 'Request Count']).sort_values('Request Count', ascending=False)
            
            # Get only the most accessed endpoint
            most_accessed = max(self.endpoint_counts.items(), key=lambda x: x[1])
            endpoints_df = pd.DataFrame([most_accessed], columns=['Endpoint', 'Access Count'])
            
            suspicious_df = pd.DataFrame(
                [(ip, count) for ip, count in self.failed_logins.items() 
                 if count >= self.failed_login_threshold],
                columns=['IP Address', 'Failed Login Count']
            ).sort_values('Failed Login Count', ascending=False)
            
            # Create sections in a list first
            sections = [
                "Requests per IP\n" + ip_requests_df.to_csv(index=False),
                "Most Accessed Endpoint\n" + endpoints_df.to_csv(index=False),
                "Suspicious Activity\n" + suspicious_df.to_csv(index=False)
            ]
            
            # Write all sections at once
            with open('log_analysis_results.csv', 'w', newline='') as f:
                f.write("\n\n".join(sections))
            
            # Save detailed analysis as JSON for reference
            detailed_analysis = {
                'ip_requests': self.ip_requests,
                'endpoint_counts': self.endpoint_counts,
                'failed_logins': self.failed_logins,
                'status_codes': self.status_codes
            }
            
            with open('detailed_analysis.json', 'w') as f:
                json.dump(detailed_analysis, f, indent=4)
        except Exception as e:
            self.console.print(f"[red]Error saving results: {str(e)}[/red]")

def main():
    console = Console()
    
    try:
        analyzer = LogAnalyzer('sample.log')
        analyzer.analyze_logs()
        analyzer.display_results()
        analyzer.save_results()
        analyzer.generate_visualizations()
        
        console.print("\nAnalysis completed successfully!")
        console.print("Results have been saved to:")
        console.print("  - log_analysis_results.csv (CSV format)")
        console.print("  - detailed_analysis.json (Detailed JSON data)")
        console.print("  - visualizations/ directory (Interactive HTML charts)")
        
    except Exception as e:
        console.print(f"[red]Error during analysis: {str(e)}[/red]")

if __name__ == "__main__":
    main()
