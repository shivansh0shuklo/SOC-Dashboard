# SOC DASHBOARD
FileGuard | Host-Based Real-Time Threat Detection System (HIDS)

## Topics learned -->
*Flask
*Low level tcp client-server sockets
*Socket programing
*PostgreSQL(database pipelines&management)
*Port isolation concept
*Html
*Cryptographic file fingerprinting
*Treading

## Tech Used --> 
1. Languages & Frameworks: Python, Flask, HTML

2. Networking & Concurrency: Low-level TCP Sockets, Multi-threading (threading), Port Isolation Mechanics

3. Database & Storage: PostgreSQL (Optimized Database Pipelines & Log Management)

4. Security Engine Logic: Cryptographic File Fingerprinting (Hashing Architecture)

## Usage Of AI -->
* In style block of index.html
* preparing the road map
* kepping track of the project

# How To Initialize -->
## steps -->

1.  sudo systemctl start postgresql
    psql -U shivansh -d soc_dashboard -f schema.sql

2.  source .venv/bin/activate
    python server.py

3.  python main.py

4.  cd flask && python myapp.py

5.  Open http://127.0.0.1:5000


## System Architecture Overview
```text
[ Target Server / Endpoint ] 
      │ 
      ├──> Cryptographic FIM Daemon (Multi-threaded File Hashing)
      └──> Outbound Network Handler (Low-level TCP Sockets)
                 │
                 ▼  [ Secure Socket Pipe (Port Isolation) ]
                 │
[ Central Operations Framework ]
      │
      ├──> Telemetry Ingestion Engine
      ├──> PostgreSQL Database (Granular Incident Logging)
      └──> Flask Web Engine ──> [ Live SOC Dashboard UI ]

