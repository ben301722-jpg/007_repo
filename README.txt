PCAP Analyzer
=============

A web application for uploading and analyzing PCAP/PCAPNG network capture files.


DOCKER SETUP (recommended)
---------------------------
Requires Docker Desktop: https://www.docker.com/products/docker-desktop/


-- Online (another computer with internet access) --

1. Install Git: https://git-scm.com/download/win
2. Install Docker Desktop: https://www.docker.com/products/docker-desktop/
3. Clone and run:

   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   docker compose up --build -d

4. Open http://localhost in your browser.


-- Offline (no internet on the target computer) --

On your current machine, export the images:

   docker compose build
   docker save 007_repo-backend 007_repo-frontend -o pcap-analyzer.tar

Copy these two files to the offline computer:
   - pcap-analyzer.tar
   - docker-compose.yml

On the offline computer (Docker Desktop must be installed):

   docker load -i pcap-analyzer.tar
   docker compose up -d

Open http://localhost in your browser.


-- Stop the app --

   docker compose down

-- Start again without rebuilding --

   docker compose up -d


MANUAL SETUP (without Docker)
------------------------------
Requires Python 3.9+ and Node.js 18+.

Backend:
1. cd 007_repo
2. pip install -r backend/requirements.txt
3. python -m uvicorn backend.main:app --reload
   API available at http://127.0.0.1:8000

Frontend (second terminal):
1. cd 007_repo/frontend
2. npm install
3. npm run dev
   App available at http://localhost:5173


USAGE
-----
1. Open http://localhost (Docker) or http://localhost:5173 (manual).
2. Upload a .pcap or .pcapng file and click Analyze.
3. Use the filter inputs and column headers to sort/filter results.
   - Prefix a filter value with ! to exclude matches (e.g. !UDP hides UDP rows).
4. Click any connection row to see its individual packets.
