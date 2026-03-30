# Implementation Plan: PCAP Analyzer

## Overview

Implement a two-tier web application: a React + TypeScript (Vite) frontend and a Python + FastAPI backend. The backend uses `dpkt` to parse PCAP/PCAPNG files and returns a JSON list of connections. The frontend uploads files, validates them client-side, and renders a connection table.

## Tasks

- [x] 1. Set up project structure and core data models
  - Create `backend/` with `main.py`, `parser.py`, `models.py`, and `requirements.txt` (fastapi, uvicorn, dpkt, python-multipart, hypothesis, pytest)
  - Create `frontend/` via `npm create vite@latest` with React + TypeScript template; add `fast-check` and testing dependencies
  - Define `TerminationReason` enum and `Connection` dataclass in `backend/models.py`
  - Define TypeScript `Connection`, `AnalyzeResponse`, and `AnalyzeError` interfaces in `frontend/src/types.ts`
  - _Requirements: 2.2, 4.1_

- [ ] 2. Implement the PCAP parser
  - [x] 2.1 Implement `PcapParser` in `backend/parser.py`
    - Detect pcap vs pcapng by magic bytes; use `dpkt.pcap.Reader` or `dpkt.pcapng.Reader` accordingly
    - Iterate packets, extract IP layer (IPv4/IPv6) and transport layer (TCP, UDP, ICMP, other)
    - Build connection map keyed on `(src_ip, dst_ip, protocol_number, src_port, dst_port)`; ports default to 0 for non-port protocols
    - Track `seen_fin` / `seen_rst` per TCP flow; apply RST-priority termination logic
    - Resolve protocol numbers to IANA names via a static lookup table; fall back to decimal string
    - Raise a descriptive `ValueError` for invalid/non-pcap bytes
    - _Requirements: 1.3, 1.5, 2.3, 3.1, 3.2, 4.2, 4.3, 4.4, 4.5_

  - [ ]* 2.2 Write property test for row count equals distinct 5-tuples (Property 3)
    - **Property 3: Row count equals distinct 5-tuples**
    - **Validates: Requirements 2.1, 2.3, 3.3**
    - Build synthetic pcap bytes with random packets using `hypothesis`; assert `len(result) == len(distinct_5tuples)`
    - Tag: `# Feature: pcap-analyzer, Property 3: row count equals distinct 5-tuples`

  - [ ]* 2.3 Write property test for invalid file yields error (Property 1)
    - **Property 1: Invalid file yields an error**
    - **Validates: Requirements 1.3**
    - Generate random non-pcap byte sequences with `hypothesis`; assert parser raises `ValueError`
    - Tag: `# Feature: pcap-analyzer, Property 1: invalid file yields an error`

  - [ ]* 2.4 Write property tests for TCP termination reasons (Properties 7, 8, 9)
    - **Property 7: TCP termination — FIN** — Validates: Requirements 4.2
    - **Property 8: TCP termination — RST** — Validates: Requirements 4.3, 4.4
    - **Property 9: TCP termination — Timeout** — Validates: Requirements 4.5
    - Generate synthetic TCP packet flag sequences with `hypothesis`; assert correct `TerminationReason`
    - Tag each test with its property number

  - [ ]* 2.5 Write property test for protocol coverage (Property 5)
    - **Property 5: Protocol coverage**
    - **Validates: Requirements 3.1**
    - Build synthetic pcap with random IP protocol numbers; assert each protocol number appears in result
    - Tag: `# Feature: pcap-analyzer, Property 5: protocol coverage`

  - [ ]* 2.6 Write property test for protocol name resolution (Property 6)
    - **Property 6: Protocol name resolution**
    - **Validates: Requirements 3.2**
    - Generate protocol numbers with `hypothesis`; assert known numbers return IANA name, unknown return decimal string
    - Tag: `# Feature: pcap-analyzer, Property 6: protocol name resolution`

- [ ] 3. Implement the FastAPI endpoint
  - [x] 3.1 Implement `POST /api/analyze` in `backend/main.py`
    - Accept `multipart/form-data` with a single `file: UploadFile` field
    - Read file bytes, call `PcapParser`, return `{"connections": [...]}` on success
    - Return HTTP 400 `{"error": "..."}` for `ValueError` from parser; HTTP 500 for unexpected exceptions
    - Enable CORS for local frontend dev origin
    - _Requirements: 1.3, 1.5, 5.2_

  - [ ]* 3.2 Write unit tests for the API endpoint in `backend/tests/test_api.py`
    - Test valid pcap upload returns 200 with connection list
    - Test invalid file bytes returns 400 with error message
    - Test no `Authorization` header required (no-auth, Requirement 5.2)
    - _Requirements: 1.3, 5.2_

- [x] 4. Checkpoint — Ensure all backend tests pass
  - Run `pytest backend/tests/` and confirm all tests pass; resolve any failures before proceeding.

- [ ] 5. Implement frontend components
  - [x] 5.1 Implement `UploadForm` component in `frontend/src/components/UploadForm.tsx`
    - File input with `accept=".pcap,.pcapng"`
    - Client-side size validation: reject files > 100 MB and show error before sending
    - On submit, POST to `/api/analyze` as `multipart/form-data`; manage loading and error state
    - _Requirements: 1.1, 1.2, 1.4_

  - [ ]* 5.2 Write property test for file size gate (Property 2)
    - **Property 2: File size gate**
    - **Validates: Requirements 1.4**
    - Use `fast-check` to generate file sizes around the 100 MB boundary; assert validator rejects > 100 MB and accepts ≤ 100 MB
    - Tag: `# Feature: pcap-analyzer, Property 2: file size gate`
    - Place in `frontend/src/__tests__/UploadForm.test.tsx`

  - [x] 5.3 Implement `ConnectionTable` component in `frontend/src/components/ConnectionTable.tsx`
    - Render one `ConnectionRow` per connection with columns: Source IP, Destination IP, Protocol, Source Port, Destination Port, TCP Termination
    - Display IANA protocol name (from `types.ts` or a shared util) in the Protocol column
    - Show empty cell for `tcp_termination` when `null`; show `FIN`, `RST`, or `Timeout` for TCP rows
    - When `connections` array is empty, render "No connections found." message instead of table
    - _Requirements: 2.1, 2.2, 2.4, 3.2, 4.1, 4.6_

  - [ ]* 5.4 Write property test for row completeness (Property 4)
    - **Property 4: Row completeness**
    - **Validates: Requirements 2.2, 4.1, 4.6**
    - Use `fast-check` to generate random `Connection` objects; render `ConnectionTable`; assert all five base columns are non-null and `tcp_termination` is correct per protocol
    - Place in `frontend/src/__tests__/ConnectionTable.test.tsx`

  - [x] 5.5 Implement `ErrorBanner` and `LoadingIndicator` components
    - `ErrorBanner`: displays a string error message; hidden when no error
    - `LoadingIndicator`: shown while `isLoading` is true
    - _Requirements: 1.2, 1.3, 1.4_

  - [x] 5.6 Wire all components together in `frontend/src/App.tsx`
    - Compose `UploadForm`, `LoadingIndicator`, `ErrorBanner`, and `ConnectionTable`
    - Manage shared state: `connections`, `isLoading`, `error`
    - _Requirements: 1.2, 2.1_

  - [ ]* 5.7 Write unit tests for `UploadForm` in `frontend/src/__tests__/UploadForm.test.tsx`
    - Assert `accept` attribute is `.pcap,.pcapng`
    - Assert size error message shown for files > 100 MB
    - _Requirements: 1.1, 1.4_

- [x] 6. Final checkpoint — Ensure all tests pass
  - Run `pytest backend/tests/` and `npm test -- --run` in `frontend/`; confirm all tests pass. Ask the user if any questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Property tests use `hypothesis` (backend) and `fast-check` (frontend); each must run ≥ 100 iterations
- RST takes priority over FIN in TCP termination classification (Requirement 4.4)
- Ports default to `0` for protocols without port fields (e.g., ICMP)
