# pythales — Python Thales HSM Simulator

[![Python 3.11 | 3.12](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![License: LGPL v2](https://img.shields.io/badge/License-LGPL_v2-green.svg)](https://www.gnu.org/licenses/old-licenses/lgpl-2.0.html)

**pythales** is a Python-based simulator for [Thales Hardware Security Modules (HSM)](https://en.wikipedia.org/wiki/Hardware_security_module) widely used in payment systems and financial cryptography. It provides TCP socket server implementation of standard Thales command framing, LMK (Local Master Key) management, key generation, PIN verification, CVV/CSC verification, and diagnostic routines.

---

## Table of Contents

- [Overview & Features](#overview--features)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Running the HSM Server](#running-the-hsm-server)
- [Docker Containerization](#docker-containerization)
- [Environment Variables Reference](#environment-variables-reference)
- [Testing & Automated Verification](#testing--automated-verification)
- [License](#license)

---

## Overview & Features

- **Runtime Support**: Fully tested and compatible with **Python 3.11** and **Python 3.12** (`python:3.11-slim` base image).
- **Wire Protocol Framing**: Supports 2-byte big-endian length prefix framing:
  $$\text{Message} = [\text{2-byte Length (uint16)}] + [\text{Header}] + [\text{Command Code}] + [\text{Payload}]$$
- **Header Echo**: Supports custom message headers (e.g. 4-character string `SSSS`) echoed in responses.
- **Implemented HSM Commands**:
  - `NC`: Diagnostics Information (returns `ND` + LMK check value + firmware version).
  - `A0`: Generate a Key (returns `A1` + key under LMK/ZMK + key check value).
  - `BU`: Generate Key Check Value (returns `BV`).
  - `CA`: Translate PIN from TPK to ZPK (returns `CB`).
  - `CW`: Generate CVV/CSC (returns `CX`).
  - `CY`: Verify CVV/CSC (returns `CZ`).
  - `DC`: Verify PIN using ABA PVV method (returns `DD`).
  - `EC`: Verify Interchange PIN (returns `ED`).
  - `FA`: Translate ZPK from ZMK to LMK.
  - `HC`: Generate TMK, TPK, or PVK (returns `HD`).
  - `NO`: Software Version and System Status query (returns `NP`).

---

## Project Structure

```text
pythales/
├── pythales/                # Core HSM Python package
│   ├── __init__.py          # Package initialization
│   ├── hsm.py               # HSM core logic, crypto routines, LMK handling
│   ├── compat.py            # Python compatibility utilities
│   └── tests.py             # Unit test suite (80 test cases)
├── examples/
│   └── hsm_server.py        # Standalone TCP socket server entry point
├── Dockerfile               # Production Docker image build (python:3.11-slim)
├── docker-compose.yml       # Docker Compose service definition
├── .env.example             # Template environment configuration file
├── requirements.txt         # Runtime dependencies (pycryptodome, tracetools, pynblock)
├── setup.py                 # Package setup and metadata
├── test_hsm_client.py       # Automated TCP test verification client
└── README.md                # Project documentation
```

---

## Installation & Setup

### Prerequisites

- **Python**: Version 3.11 or 3.12 installed.
- **Git**: For cloning the repository.

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/timgabets/pythales
   cd pythales
   ```

2. **Create and activate a virtual environment**:
   - **Linux / macOS**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - **Windows (PowerShell)**:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. **Install dependencies**:
   ```bash
   pip install pycryptodome tracetools
   pip install --no-deps pynblock
   ```

4. **Install the `pythales` package**:
   ```bash
   pip install --no-deps -e .
   ```

---

## Running the HSM Server

You can launch the HSM server directly using Python. The server listens on IPv4 TCP port `1500` by default.

### Direct Python Invocation

```bash
python examples/hsm_server.py
```

### CLI Command Options

```text
Usage: python examples/hsm_server.py [OPTIONS]...

Options:
  -p, --port=[PORT]        TCP port to listen on (default: 1500 or HSM_PORT env var)
  -k, --key=[KEY]          Local Master Key (32-hex char LMK string)
  -h, --header=[HEADER]    Message header prefix (default: empty or HSM_HEADER env var)
  -d, --debug              Enable verbose debug logging (show CVV/PVV mismatch details)
  -s, --skip-parity        Skip key parity checks
  -a, --approve-all        Approve all requests regardless of pin/cvv validity
  --help                   Display usage information and exit
```

### Example Usage with Custom Flags

```bash
python examples/hsm_server.py --port 1500 --header SSSS --debug --skip-parity
```

Debug logging is written to the console with timestamps, log levels, client
connections, and request/response payloads in hexadecimal. Because payloads may
contain sensitive test data, enable this option only while troubleshooting.

### Sample Server Output

```text
 LMK: DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF
 Firmware version: 0007-E000
 Message header: SSSS
 Listening on port 1500
 Connected client: 127.0.0.1:54321
 18:00:00.123456 << 8 bytes received from 127.0.0.1:54321:
 	00 06 53 53 53 53 4e 43                                 ..SSSSNC
 18:00:00.124000 >> 35 bytes sent to 127.0.0.1:54321:
 	00 21 53 53 53 53 4e 44 30 30 46 34 45 44 43 38         .!SSSSND00F4EDC8
 	44 45 42 36 37 46 36 45 32 38 30 30 30 37 2d 45         DEB67F6E280007-E
 	30 30 30                                                000
 	[Response Code   ]: [ND]
 	[Error Code      ]: [00]
 	[LMK Check Value ]: [F4EDC8DEB67F6E28]
 	[Firmware Version]: [0007-E000]
```

---

## Docker Containerization

The project includes a lightweight, optimized `Dockerfile` based on `python:3.11-slim` and a `docker-compose.yml` configuration for single-command deployment.

### 1. Building the Docker Image

```bash
docker build -t pythales-hsm .
```

### 2. Running Container via Docker Run

Launch the container in detached mode mapping host port `1500` and loading environment variables:

```bash
# Create .env from template if not already present
cp .env.example .env

# Run container with environment file
docker run -d -p 1500:1500 --name hsm-server --env-file .env pythales-hsm
```

To stop and remove the container:
```bash
docker stop hsm-server
docker rm hsm-server
```

### 3. Running via Docker Compose

Docker Compose manages container lifecycle and port mapping automatically.

```bash
# Start container service in background
docker compose up -d

# View real-time container logs
docker compose logs -f

# Stop and remove container service
docker compose down
```

---

## Environment Variables Reference

The HSM server supports full configuration via environment variables (in `.env`, Docker parameters, or shell exports).

| Variable | Default Value | Description |
|---|---|---|
| `HSM_PORT` | `1500` | TCP listening port for the HSM server |
| `HSM_HOST` | `0.0.0.0` | Target host IP address / binding network interface |
| `HSM_HEADER` | `""` | Message header prefix to echo in framed responses (e.g. `SSSS`) |
| `HSM_KEY` | `deadbeefdeadbeefdeadbeefdeadbeef` | 32-hex character string representing the Local Master Key (LMK) |
| `HSM_DEBUG` | `false` | Enable verbose debug logging (`1`/`0`, `true`/`false`) |
| `HSM_SKIP_PARITY` | `false` | Skip key parity checking (`1`/`0`, `true`/`false`) |
| `HSM_APPROVE_ALL` | `false` | Force approval of all incoming requests (`1`/`0`, `true`/`false`) |
| `HSM_MAX_CONNECTIONS` | `1000` | Maximum allowed concurrent TCP client connections |
| `HSM_IDLE_TIMEOUT` | `30.0` | Idle connection timeout in seconds before closing socket |
| `HSM_ENABLE_KEEPALIVE` | `true` | Enable TCP Keep-Alive on client sockets (`true`/`false`) |

---

## Testing & Automated Verification

### 1. Unit Tests

The internal test suite validates command frame parsing, outgoing message formatting, key operations, PIN translation/verification, and CVV routines.

Run unit tests directly:

```bash
python pythales/tests.py
```

Or via standard `unittest` module:

```bash
python -m unittest discover pythales
```

Expected output:
```text
................................................................................
----------------------------------------------------------------------
Ran 80 tests in 0.019s

OK
```

### 2. Automated Client Verification Script

`test_hsm_client.py` is an automated TCP socket test client that connects to a running `hsm_server` instance, sends diagnostic (`NC`) and key generation (`A0`) framed requests, and verifies response headers, response codes, error codes, and key payloads.

#### Usage Syntax

```bash
python test_hsm_client.py [OPTIONS]
```

#### Client Options

- `--host`: HSM server IP or hostname (default: `127.0.0.1` or `HSM_HOST` env var).
- `--port`: HSM server TCP port (default: `1500` or `HSM_PORT` env var).
- `--header`: Message header string (default: empty or `HSM_HEADER` env var).

#### Verification Command Example

1. **Start the HSM server** (in one terminal or via Docker):
   ```bash
   python examples/hsm_server.py --port 1500
   ```

2. **Execute client verification** (in another terminal):
   ```bash
   python test_hsm_client.py --host 127.0.0.1 --port 1500
   ```

#### Sample Verification Output

```text
==================================================
 pythales HSM Automated Test Verification Client 
==================================================
 Target Host:   127.0.0.1
 Target Port:   1500
 Message Header: ''
 Successfully connected to HSM server at 127.0.0.1:1500

--- Test Case 1: Send NC (Diagnostics) Command ---
Sending framed request: NC (Header: b'')
  Response Code: 'ND'
  Error Code:    '00'
  LMK Check Value: 'F4EDC8DEB67F6E28'
  Firmware Version: '0007-E000'
[PASS] Test Case 1 (NC Diagnostics) passed successfully.

--- Test Case 2: Send A0 (Generate Key) Command ---
Sending framed request: A00000U (Header: b'')
  Response Code: 'A1'
  Error Code:    '00'
  Key Payload:   'UB26ED5C4FBC86D56C3308C3173254E0B'
[PASS] Test Case 2 (A0 Generate Key) passed successfully.

==================================================
 ALL VERIFICATION TESTS PASSED SUCCESSFULLY! [EXIT 0]
==================================================
```

---

## License

Distributed under the [GNU Lesser General Public License v2 (LGPLv2)](https://www.gnu.org/licenses/old-licenses/lgpl-2.0.html).
