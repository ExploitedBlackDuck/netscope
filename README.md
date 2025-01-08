Here is an even more polished, professional, and comprehensive version of the documentation that is structured to cater to a wide audience, including users, contributors, and developers. This version emphasizes clarity, usability, and professionalism.

---

# **NetScope: Asynchronous Network Scanner**

NetScope is a Python-based, asynchronous network scanner powered by Nmap. It offers fast, efficient, and flexible tools for network discovery, port scanning, and optional vulnerability detection, making it a valuable resource for system administrators, network engineers, and security professionals.

---

## **Table of Contents**

1. [Introduction](#introduction)
2. [Key Features](#key-features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Examples](#examples)
6. [Output](#output)
7. [Logging](#logging)
8. [Troubleshooting](#troubleshooting)
9. [Development](#development)
10. [Contributing](#contributing)
11. [License](#license)
12. [Contact](#contact)

---

## **Introduction**

NetScope is designed to simplify network scanning by integrating the power of Nmap with Python's asynchronous capabilities. Whether you are conducting a simple scan of active hosts or performing a detailed vulnerability assessment, NetScope delivers reliable and structured results in an efficient manner.

---

## **Key Features**

- **Fast Host Discovery**: Identify active hosts within a specified network range.
- **Port Scanning**: Detect open ports across a customizable range.
- **Optional Vulnerability Detection**: Perform security scans using Nmap's `vuln` scripts.
- **Asynchronous Execution**: Scan multiple hosts concurrently for optimal performance.
- **Customizable Output**: Save results in structured JSON format for further analysis or integration.
- **Detailed Logging**: Maintain a comprehensive log of actions and results for troubleshooting and auditing.

---

## **Installation**

### **Prerequisites**

1. **Python**:
   - Ensure Python 3.7 or later is installed. Verify your installation:
     ```bash
     python3 --version
     ```
   - Download Python from [python.org](https://www.python.org/downloads/) if needed.

2. **Nmap**:
   - Install Nmap on your system:
     - **Linux (Debian/Ubuntu)**:
       ```bash
       sudo apt update
       sudo apt install nmap
       ```
     - **macOS** (via Homebrew):
       ```bash
       brew install nmap
       ```
     - **Windows**: Download and install from [nmap.org](https://nmap.org/download.html), and ensure it is added to your system's PATH.

3. **Python Libraries**:
   - Install the required Python library:
     ```bash
     pip install python-nmap
     ```

---

## **Usage**

### **Command Syntax**

Run the script using the following format:
```bash
python netscope.py <network_range> [options]
```

### **Parameters**

| Parameter                  | Description                                                                 | Default Value        |
|----------------------------|-----------------------------------------------------------------------------|----------------------|
| `<network_range>`          | **Required**: Specify the network range to scan (e.g., `192.168.1.0/24`).  | N/A                  |
| `-p, --port_range`         | **Optional**: Specify the port range to scan (e.g., `22-443`).              | `1-65535`            |
| `-v, --vuln_scan`          | **Optional**: Enable vulnerability scanning using Nmap's `vuln` scripts.   | Disabled             |
| `-o, --output <filename>`  | **Optional**: Specify the file to save scan results in JSON format.         | `scan_results.json`  |

---

## **Examples**

### **1. Basic Scan**
Perform a simple scan of all hosts in the `192.168.1.0/24` network:
```bash
python netscope.py 192.168.1.0/24
```

### **2. Scan Specific Ports**
Scan only ports `22`, `80`, and `443`:
```bash
python netscope.py 192.168.1.0/24 -p 22,80,443
```

### **3. Enable Vulnerability Scanning**
Perform a vulnerability scan alongside port scanning:
```bash
python netscope.py 192.168.1.0/24 -v
```

### **4. Save Results to a Custom File**
Save scan results to a custom file named `custom_results.json`:
```bash
python netscope.py 192.168.1.0/24 -o custom_results.json
```

### **5. Combine All Options**
Perform a vulnerability scan on ports `22-443` and save the results:
```bash
python netscope.py 192.168.1.0/24 -p 22-443 -v -o results.json
```

---

## **Output**

### **Console Output**
Results are displayed in a structured, human-readable format:
```
Scan Results:

Host: 192.168.1.1
  Open Ports: [22, 80]
  Vulnerabilities:
    - ssh-vuln-cve2018-15473: Detected OpenSSH vulnerability.

Host: 192.168.1.10
  Open Ports: [443]
```

### **JSON Output**
Results are saved in JSON format, which is ideal for further analysis:
```json
{
    "192.168.1.1": {
        "open_ports": [22, 80],
        "vulnerabilities": [
            {
                "id": "ssh-vuln-cve2018-15473",
                "output": "Detected OpenSSH vulnerability."
            }
        ]
    },
    "192.168.1.10": {
        "open_ports": [443],
        "vulnerabilities": []
    }
}
```

---

## **Logging**

NetScope generates a detailed log file (`network_scan.log`) to record:
- Host discovery results.
- Port scanning details.
- Vulnerability scanning results.
- Errors encountered during execution.

### Sample Log Entry:
```
2025-01-07 12:45:00 - INFO - Discovering active hosts in range: 192.168.1.0/24
2025-01-07 12:45:01 - INFO - Active hosts discovered: ['192.168.1.1', '192.168.1.10']
2025-01-07 12:45:02 - INFO - Scanning open ports on host: 192.168.1.1
2025-01-07 12:45:03 - INFO - Open ports on 192.168.1.1: [22, 80]
2025-01-07 12:45:04 - INFO - Results saved to scan_results.json
```

---

## **Troubleshooting**

### Common Issues

#### **1. `python-nmap` Library Not Found**
Install the library:
```bash
pip install python-nmap
```

#### **2. Nmap Command Not Found**
Ensure Nmap is installed and accessible via your system's PATH:
```bash
nmap --version
```

#### **3. Missing `network_range` Argument**
Provide the required `network_range` argument:
```bash
python netscope.py 192.168.1.0/24
```

---

## **Development**

### **Project Structure**
```
netscope/
├── netscope.py        # Main script
├── README.md          # Documentation
├── network_scan.log   # Log file (generated during execution)
├── scan_results.json  # Default output file for results
```

---

## **Contributing**

We welcome contributions to improve NetScope! To contribute:
1. **Fork the Repository**: Create a personal copy of the project on GitHub.
2. **Create a Branch**: Develop your feature or fix in a new branch.
3. **Submit a Pull Request**: Open a pull request for review and integration.

---

## **License**

This project is licensed under the [MIT License](LICENSE). Feel free to use, modify, and distribute the software in accordance with the license.

---

## **Contact**

For questions, feedback, or issues, please contact:

- **Email**: [python.shield@aes256.io](python.shield@aes256.io)
