# AI-Enhanced Web Vulnerability Scanner

An intelligent web vulnerability scanner using AI techniques to improve detection, prioritization, and remediation of security vulnerabilities in web applications. The scanner integrates with OWASP ZAP (Zed Attack Proxy) for thorough vulnerability detection.

## Features

- **AI-Enhanced Detection**: Uses machine learning to detect complex vulnerabilities and reduce false positives
- **Intelligent Prioritization**: Contextually assesses risk levels for vulnerabilities
- **Automated Remediation Guidance**: Provides AI-generated recommendations for fixing issues
- **ZAP Integration**: Leverages OWASP ZAP for comprehensive vulnerability scanning
- **Web Interface**: User-friendly dashboard to manage and view scan results
- **Comprehensive Reporting**: Advanced reporting with compliance mapping
- **Lightweight Architecture**: Uses threading for task management without external dependencies

## Project Structure

```
vul_scan/
├── src/                    # Source code
│   ├── core/               # Core scanner functionality
│   ├── ai/                 # AI models and algorithms
│   ├── utils/              # Utility functions
│   ├── web/                # Web interface
│   └── database/           # Database models and operations
├── tests/                  # Test files
├── docs/                   # Documentation
├── requirements.txt        # Project dependencies
├── data/                   # Data storage (created at runtime)
├── logs/                   # Log files (created at runtime)
└── README.md               # Project overview
```

## Prerequisites

### 1. Install OWASP ZAP

This scanner requires OWASP ZAP (Zed Attack Proxy) to be installed on your system.

#### Option A: Download and Install ZAP

1. Download ZAP from the official website: https://www.zaproxy.org/download/
2. Install it according to your operating system instructions
3. Make sure ZAP is in your system PATH or set the `ZAP_PATH` environment variable to the location of `zap.sh` (Linux/Mac) or `zap.bat` (Windows)

#### Option B: Use Docker

```bash
# Pull and run the ZAP Docker image
docker pull owasp/zap2docker-stable
docker run -d -p 8080:8080 -p 8090:8090 --name zap owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### 2. Python Requirements

- Python 3.8 or higher
- pip package manager

## Installation

1. Clone the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Unix/MacOS: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Create necessary directories:
   ```bash
   mkdir -p data logs
   ```

## Usage

### 1. Generate AI Models (Optional)

Before using the scanner, you can train the AI models:

```bash
python -m src.ai.train_models
```

### 2. Start the Web Interface

```bash
python -m src.main --web
```

The web interface will be available at http://localhost:5000

### 3. Run a Scan from Command Line

```bash
python -m src.main --url https://example.com
```

### 4. Additional Options

```bash
python -m src.main --help
```

This will show all available command-line options:

```
options:
  --url URL             Target URL to scan
  --config CONFIG       Path to configuration file
  --web                 Start the web interface
  --output OUTPUT       Output file for scan results
  --verbose             Enable verbose output
  --depth DEPTH         Maximum crawl depth
  --threads THREADS     Number of threads to use
  --port PORT           Web server port (when using --web)
```

## Configuration

You can customize the scanner behavior by editing the `config.json` file in the root directory:

```json
{
  "zap_path": "/path/to/zap.sh",
  "zap_port": 8080,
  "zap_api_key": null,
  "max_depth": 3,
  "threads": 4,
  "timeout": 30,
  "user_agent": "VulnerabilityScannerBot/1.0",
  "enable_ai_analysis": true,
  "task_handling": {
    "use_threading": true,
    "max_concurrent_tasks": 5
  }
}
```

## Development

- Run tests: `pytest tests/`
- Format code: `black src/`

## Technical Details

### Task Handling

The scanner uses Python's built-in threading module to handle concurrent scans and background tasks:

- Each scan runs in its own thread
- Progress updates are tracked in memory
- No external message queue services are required

### Database

- All scan data is stored in a local SQLite database at `data/vulnscan.db`
- No external database services are required

## Troubleshooting

### ZAP Connection Issues

If the scanner can't connect to ZAP:

1. Make sure ZAP is installed and the path is correct
2. Check if ZAP is running in daemon mode
3. Verify that the port specified in the config is correct
4. Ensure there are no firewall rules blocking the connection

### Database Issues

All scan data is stored in SQLite at `data/vulnscan.db`. If you experience database issues:

1. Check file permissions for the `data` directory
2. Ensure the application has write access to the directory

## License

[MIT License](LICENSE)
