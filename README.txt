PCAP Analyzer
=============

A web application for uploading and analyzing PCAP/PCAPNG network capture files.


REQUIREMENTS
------------
- install git
- install kiro

to run the pcap_analyzer app
------------
- Python 3.9+
- Node.js 18+


DOCKER SETUP (recommended)
---------------------------
Requires Docker Desktop: https://www.docker.com/products/docker-desktop/

1. Build and start the app:
   docker compose up --build -d

2. Open http://localhost in your browser.

3. To stop the app:
   docker compose down

4. To start again without rebuilding:
   docker compose up -d


BACKEND SETUP (manual)
----------------------
1. Open a terminal and navigate to the project root:
   cd 007_repo

2. Install Python dependencies:
   pip install -r backend/requirements.txt

3. Start the backend server:
   python -m uvicorn backend.main:app --reload

   The API will be available at http://127.0.0.1:8000


FRONTEND SETUP (manual)
------------------------
1. Open a second terminal and navigate to the frontend folder:
   cd 007_repo/frontend

2. Install Node dependencies (first time only):
   npm install

3. Start the frontend dev server:
   npm run dev

   The app will be available at http://localhost:5173


USAGE
-----
1. Make sure both backend and frontend are running.
2. Open http://localhost:5173 in your browser (or http://localhost if using Docker).
3. Upload a .pcap or .pcapng file and click Analyze.
4. Use the filter inputs and column headers to sort/filter results.
   - Prefix a filter value with ! to exclude matches (e.g. !UDP hides UDP rows).
5. Click any connection row to see its individual packets.


STOPPING THE SERVERS
--------------------
Press Ctrl+C in each terminal to stop the backend and frontend.
