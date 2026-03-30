# Requirements Document

## Introduction

A web application that allows users to upload PCAP (packet capture) files and view a structured analysis of the network connections contained within. The application presents each connection as a single row with key metadata, and for TCP connections, indicates how the flow was terminated.

## Glossary

- **PCAP_File**: A binary file in libpcap format containing captured network packets.
- **Connection**: A unique network flow identified by the 5-tuple: source IP, destination IP, protocol, source port, and destination port.
- **Flow**: Synonym for Connection; a bidirectional or unidirectional stream of packets sharing the same 5-tuple.
- **Analyzer**: The backend component responsible for parsing PCAP files and extracting connection data.
- **UI**: The web-based frontend component the user interacts with.
- **TCP_Termination_Reason**: The reason a TCP flow ended, one of: FIN (graceful close), RST (reset), or Timeout (no packets observed within a defined idle period).
- **5-Tuple**: The combination of source IP address, destination IP address, protocol number, source port, and destination port that uniquely identifies a connection.

## Requirements

### Requirement 1: PCAP File Upload

**User Story:** As a network analyst, I want to upload a PCAP file through a web page, so that I can analyze the network traffic it contains without installing local tools.

#### Acceptance Criteria

1. THE UI SHALL provide a file upload control that accepts files with `.pcap` and `.pcapng` extensions.
2. WHEN a user submits a PCAP file, THE UI SHALL display a loading indicator until analysis results are available.
3. IF a user submits a file that is not a valid PCAP or PCAPNG file, THEN THE Analyzer SHALL return a descriptive error message identifying the file as invalid.
4. IF the uploaded file exceeds 100 MB, THEN THE UI SHALL reject the upload and display an error message stating the file size limit.
5. WHEN a PCAP file is successfully uploaded, THE Analyzer SHALL parse the file and extract all connections.

---

### Requirement 2: Connection Table Display

**User Story:** As a network analyst, I want to see analysis results as one line per connection, so that I can quickly scan and understand the traffic flows in the capture.

#### Acceptance Criteria

1. WHEN analysis results are available, THE UI SHALL display each connection as exactly one row in a table.
2. THE UI SHALL display the following columns for every connection row: source IP address, destination IP address, protocol, source port, and destination port.
3. THE Analyzer SHALL deduplicate packets belonging to the same 5-tuple into a single connection row.
4. WHEN a PCAP file contains zero connections, THE UI SHALL display a message indicating no connections were found.

---

### Requirement 3: Protocol Coverage

**User Story:** As a network analyst, I want all protocols in the capture to be represented, so that I get a complete picture of the traffic.

#### Acceptance Criteria

1. THE Analyzer SHALL extract connections for all IP-based protocols present in the PCAP file, including but not limited to TCP, UDP, and ICMP.
2. THE UI SHALL display the protocol field using the IANA-assigned protocol name (e.g., TCP, UDP, ICMP) when a name is available, and the numeric protocol number otherwise.
3. FOR all connections in a PCAP file, THE Analyzer SHALL produce at least one corresponding row in the results.

---

### Requirement 4: TCP Flow Termination Reason

**User Story:** As a network analyst, I want TCP connections to show how the flow ended, so that I can identify abnormal terminations like resets or timeouts.

#### Acceptance Criteria

1. WHEN a connection uses the TCP protocol, THE UI SHALL display a TCP_Termination_Reason column for that row.
2. WHEN a TCP flow contains a FIN packet, THE Analyzer SHALL classify the TCP_Termination_Reason as `FIN`.
3. WHEN a TCP flow contains a RST packet, THE Analyzer SHALL classify the TCP_Termination_Reason as `RST`.
4. WHEN a TCP flow contains both a FIN and a RST packet, THE Analyzer SHALL classify the TCP_Termination_Reason as `RST`.
5. WHEN a TCP flow has no FIN or RST packet, THE Analyzer SHALL classify the TCP_Termination_Reason as `Timeout`.
6. WHEN a connection does not use the TCP protocol, THE UI SHALL display an empty value in the TCP_Termination_Reason column.

---

### Requirement 5: No Authentication

**User Story:** As a user, I want to access the application without logging in, so that I can start analyzing captures immediately.

#### Acceptance Criteria

1. THE UI SHALL be accessible without requiring user authentication or account creation.
2. THE Analyzer SHALL process uploaded files without requiring any session token or credentials.
