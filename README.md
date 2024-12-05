# Advanced Security Log Analysis System

A state-of-the-art Python-based security log analysis tool that combines traditional security metrics with advanced machine learning and predictive analytics for comprehensive threat detection and prevention.

## Key Features

### 1. Traditional Security Analysis
- **IP Request Monitoring**
  - Tracks and analyzes requests per IP address
  - Identifies high-frequency requestors
  - Visualizes request distribution patterns

- **Endpoint Analysis**
  - Maps most accessed endpoints
  - Tracks endpoint access patterns
  - Generates interactive access distribution charts

- **Basic Security Checks**
  - Brute force attack detection
  - Failed login attempt monitoring
  - DoS/DDoS detection through rate limiting

### 2. Advanced Machine Learning Detection System
- **Anomaly Detection using Isolation Forest**
  - Automatically identifies suspicious behavior patterns
  - Multi-dimensional analysis of request characteristics
  - Detects sophisticated attacks that bypass traditional rules
  - Features analyzed:
    - Request frequency patterns
    - Status code distributions
    - Temporal access patterns
    - Login attempt behaviors

### 3. Predictive Attack Pattern Analysis
- **Sequential Pattern Mining (FP-Growth Algorithm)**
  - Discovers common attack sequences
  - Identifies typical attacker behavior patterns
  - Uses same algorithm as major e-commerce companies for pattern detection
  - Helps predict next possible attack steps

- **Attack Graph Analysis (Network Theory)**
  - Creates directed graphs of system navigation patterns
  - Uses eigenvector centrality (similar to Google's PageRank)
  - Identifies critical and vulnerable endpoints
  - Calculates risk scores for different system components

- **Time Series Analysis**
  - Predicts potential attack windows
  - Uses Exponential Smoothing for forecasting
  - Identifies high-risk time periods
  - Helps optimize security resource allocation

### 4. Visualization and Reporting
- **Interactive HTML Charts**
  - Request distribution visualization
  - Endpoint access patterns
  - Status code distribution
  - Attack pattern graphs

- **Comprehensive Reports**
  - CSV exports for detailed analysis
  - JSON data for integration with other tools
  - Rich console output with formatted tables

## Technical Deep Dive

### Machine Learning Components

1. **Isolation Forest for Anomaly Detection**
   - Why we use it:
     - Efficiently detects outliers in high-dimensional space
     - Performs well with imbalanced datasets (common in security logs)
     - Can identify novel attack patterns
   - What it detects:
     - Unusual request patterns
     - Abnormal status code distributions
     - Suspicious temporal patterns
     - Complex attack signatures

2. **Sequential Pattern Mining**
   - Implementation: FP-Growth Algorithm
   - Benefits:
     - Discovers hidden attack patterns
     - More efficient than traditional Apriori algorithm
     - Scales well with large log files
   - Applications:
     - Attack sequence prediction
     - Behavior pattern analysis
     - Attack strategy identification

3. **Graph Theory Application**
   - Techniques used:
     - Directed graphs for request flows
     - Eigenvector centrality for risk assessment
     - Network analysis for vulnerability detection
   - Provides:
     - Critical path analysis
     - Risk propagation mapping
     - Vulnerability identification

4. **Time Series Analysis**
   - Method: Exponential Smoothing
   - Features:
     - Seasonal pattern detection
     - Trend analysis
     - Future attack window prediction
   - Benefits:
     - Proactive security measures
     - Resource optimization
     - Attack prevention

## Output and Insights

The system provides multiple layers of security insights:
1. Traditional security metrics
2. ML-based anomaly detection
3. Predictive attack patterns
4. Critical endpoint identification
5. Temporal risk analysis

## Installation

1. Clone the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Requirements
- Python 3.8+
- Dependencies:
  - pandas==2.1.1
  - rich==13.6.0
  - plotly==5.17.0
  - tqdm==4.66.1
  - scikit-learn==1.3.1
  - numpy==1.26.0
  - mlxtend==0.22.0
  - statsmodels==0.14.1
  - networkx==3.2.1

## Usage

Run the analyzer:
```bash
python log_analyzer.py
```

## Output Files
- `log_analysis_results.csv`: Detailed analysis in CSV format
- `detailed_analysis.json`: Complete analysis data in JSON format
- `visualizations/`: Interactive HTML visualizations
  - `ip_requests.html`: IP request distribution
  - `endpoint_distribution.html`: Endpoint access patterns
  - `status_codes.html`: HTTP status code distribution

## Performance Considerations
- Efficient data structures for large log files
- Progress tracking for long operations
- Modular design for easy maintenance
- Graceful handling of limited data scenarios

## Security Best Practices
- No hardcoded credentials
- Configurable security thresholds
- Comprehensive error handling
- Detailed logging and reporting

## License
MIT License
