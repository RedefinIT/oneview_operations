# HPE OneView Server Profile Data Extraction Tool

Enterprise-grade Python script for extracting comprehensive server profile details from HPE OneView 9.4.

## Features

- **Comprehensive Data Extraction**:
  - Server profile name
  - Server hardware name
  - iLO IP address
  - Server serial number
  - MAC addresses for all network connections (with network names)
  - Power state
  - Profile state
  

## Requirements

- Python 3.8 or higher
- HPE OneView 9.4 (API version 4000)
- Network access to HPE OneView appliance

## Installation

1. **Clone or download the script**:
   ```bash
   git clone <repository-url>
   cd oneview_operations
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure credentials**:
   
   **Option A: Using .env file (recommended)**
   ```bash
   cp .env.example .env
   # Edit .env with your OneView credentials
   ```

   **Option B: Using environment variables**
   ```bash
   export ONEVIEW_HOSTNAME=oneview.example.com
   export ONEVIEW_USERNAME=Administrator
   export ONEVIEW_PASSWORD=your_password
   export ONEVIEW_API_VERSION=4000
   export ONEVIEW_SSL_VERIFY=False
   ```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ONEVIEW_HOSTNAME` | Yes | - | OneView hostname or IP address |
| `ONEVIEW_USERNAME` | Yes | - | OneView username |
| `ONEVIEW_PASSWORD` | Yes | - | OneView password |
| `ONEVIEW_API_VERSION` | No | 4000 | API version (4000 for OneView 9.x) |
| `ONEVIEW_SSL_VERIFY` | No | False | Enable SSL certificate verification |

### .env File Example

```bash
ONEVIEW_HOSTNAME=oneview.example.com
ONEVIEW_USERNAME=Administrator
ONEVIEW_PASSWORD=SecurePassword123
ONEVIEW_API_VERSION=4000
ONEVIEW_SSL_VERIFY=False
```

## Usage

### Basic Usage

Run the enhanced version (recommended):
```bash
python oneview_server_profiles_enhanced.py
```

Or the basic version:
```bash
python oneview_server_profiles.py
```

### Output Files

The script generates three types of output files with timestamps:

1. **JSON Export**: `server_profiles_YYYYMMDD_HHMMSS.json`
   - Structured data with all details
   - Includes nested connection information
   - Suitable for API consumption or further processing

2. **CSV Export**: `server_profiles_YYYYMMDD_HHMMSS.csv`
   - Flat format for spreadsheet applications
   - MAC addresses concatenated with semicolons
   - Easy to import into Excel or databases

3. **Log File**: `oneview_extraction_YYYYMMDD_HHMMSS.log`
   - Detailed execution log
   - Error tracking and debugging information
   - Progress and timing information

### Example Output

**Console Output**:
```
================================================================================
HPE OneView Server Profile Data Extraction Tool
================================================================================

Target: oneview.example.com
API Version: 4000
SSL Verify: False

2024-12-23 10:30:00 - Connecting to HPE OneView at oneview.example.com
2024-12-23 10:30:01 - Successfully connected to HPE OneView
2024-12-23 10:30:01 - Retrieving all server profiles...
2024-12-23 10:30:02 - Found 25 server profiles
2024-12-23 10:30:02 - Processing profile 1/25: ESXi-Host-01
...

✓ JSON export: /path/to/server_profiles_20241223_103005.json
✓ CSV export: /path/to/server_profiles_20241223_103005.csv

================================================================================
HPE OneView Server Profile Summary
================================================================================
Total Profiles: 25
Timestamp: 2024-12-23 10:30:05
================================================================================

Profile: ESXi-Host-01
  Server Hardware: Enclosure1, bay 1
  iLO IP: 10.0.1.101
  Serial Number: MXQ12345AB
  Power State: On
  Profile State: Normal
  Network Connections:
    - Production-VLAN100: 00:11:22:33:44:55 (Port: Flb 1:1-a, Type: Ethernet)
    - Storage-VLAN200: 00:11:22:33:44:56 (Port: Flb 1:1-b, Type: Ethernet)
```

**JSON Output Structure**:
```json
[
  {
    "profile_name": "ESXi-Host-01",
    "server_hardware_name": "Enclosure1, bay 1",
    "ilo_ip": "10.0.1.101",
    "serial_number": "MXQ12345AB",
    "power_state": "On",
    "profile_state": "Normal",
    "mac_addresses": [
      {
        "connection_id": "1",
        "connection_name": "Production",
        "network_name": "Production-VLAN100",
        "mac_address": "00:11:22:33:44:55",
        "mac_type": "Physical",
        "port_id": "Flb 1:1-a",
        "function_type": "Ethernet"
      }
    ],
    "profile_uri": "/rest/server-profiles/12345",
    "server_hardware_uri": "/rest/server-hardware/67890"
  }
]
```

**CSV Output Format**:
```csv
Profile Name,Server Hardware,iLO IP Address,Serial Number,Power State,Profile State,MAC Addresses,Profile URI,Server Hardware URI
ESXi-Host-01,Enclosure1 bay 1,10.0.1.101,MXQ12345AB,On,Normal,Production-VLAN100=00:11:22:33:44:55; Storage-VLAN200=00:11:22:33:44:56,/rest/server-profiles/12345,/rest/server-hardware/67890
```

## Error Handling

The script includes comprehensive error handling:

- **Connection Errors**: Validates connectivity and credentials before proceeding
- **API Errors**: Catches and logs HPE OneView API exceptions
- **Data Validation**: Handles missing or incomplete data gracefully
- **Network Timeouts**: Implements retry logic for transient failures
- **Logging**: All errors are logged with full stack traces for debugging

### Common Issues

1. **Authentication Failed**:
   ```
   ✗ OneView API Error: Invalid credentials
   ```
   - Verify username and password in .env file
   - Check user permissions in OneView

2. **Connection Timeout**:
   ```
   ✗ Failed to connect to OneView: Connection timeout
   ```
   - Verify network connectivity to OneView appliance
   - Check firewall rules
   - Verify ONEVIEW_HOSTNAME is correct

3. **SSL Certificate Error**:
   ```
   ✗ SSL certificate verification failed
   ```
   - Set `ONEVIEW_SSL_VERIFY=False` for self-signed certificates
   - Or install the CA certificate in your system trust store

## Integration with FastAPI

Example FastAPI endpoint to integrate this script:

```python
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional
import subprocess
import json

app = FastAPI()

class ServerProfile(BaseModel):
    profile_name: str
    server_hardware_name: str
    ilo_ip: str
    serial_number: str
    power_state: str
    profile_state: str
    mac_addresses: List[dict]

@app.get("/api/oneview/profiles", response_model=List[ServerProfile])
async def get_server_profiles():
    """Extract server profiles from OneView"""
    try:
        # Run extraction script
        result = subprocess.run(
            ["python", "oneview_server_profiles_enhanced.py"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"OneView extraction failed: {result.stderr}"
            )
        
        # Find the most recent JSON output
        import glob
        json_files = glob.glob("server_profiles_*.json")
        if not json_files:
            raise HTTPException(
                status_code=404,
                detail="No profile data found"
            )
        
        latest_file = max(json_files, key=os.path.getctime)
        
        # Load and return data
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        return data
        
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="OneView extraction timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {str(e)}"
        )
```

## Security Considerations

1. **Credential Storage**:
   - Never commit `.env` file to version control
   - Add `.env` to `.gitignore`
   - Use secure credential management in production (HashiCorp Vault, AWS Secrets Manager, etc.)

2. **SSL Verification**:
   - Use `ONEVIEW_SSL_VERIFY=True` in production
   - Install proper CA certificates
   - Avoid disabling SSL verification except for lab environments

3. **Permissions**:
   - Use read-only OneView accounts when possible
   - Follow principle of least privilege
   - Audit script execution logs

4. **Log Files**:
   - Log files may contain sensitive information
   - Rotate and secure log files appropriately
   - Review log retention policies

## Troubleshooting

### Enable Debug Logging

Modify the logging level in the script:

```python
logging.basicConfig(
    level=logging.DEBUG,  # Changed from INFO
    ...
)
```

### Verify API Version

Check your OneView version and corresponding API version:

```bash
# OneView 9.x = API version 4000
# OneView 8.x = API version 3600
# OneView 7.x = API version 3200
```

### Test Connection

Create a simple test script:

```python
from hpOneView.oneview_client import OneViewClient

config = {
    'ip': 'oneview.example.com',
    'credentials': {
        'userName': 'Administrator',
        'password': 'password'
    },
    'api_version': 4000
}

try:
    client = OneViewClient(config)
    print("Connection successful!")
except Exception as e:
    print(f"Connection failed: {e}")
```

## Performance Considerations

- **Large Environments**: For environments with 100+ profiles, expect 5-10 minutes runtime
- **Network Latency**: API calls are sequential; high latency increases total time
- **Rate Limiting**: HPE OneView may rate-limit excessive API calls
- **Optimization**: Consider implementing connection pooling for repeated executions

## License

This script is provided as-is for enterprise infrastructure management purposes.

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Review HPE OneView SDK documentation: https://github.com/HewlettPackard/oneview-python
- Consult HPE OneView API reference: https://techlibrary.hpe.com/

## Changelog

### Version 1.1.0
- Added power state and profile state extraction
- Enhanced error handling with detailed logging
- Improved network name resolution for all network types
- Added .env file support
- Better console output formatting

### Version 1.0.0
- Initial release
- Basic profile extraction functionality
- JSON and CSV export
- Environment variable configuration