# ICMP Traceroute Utility

## Introduction

This project extends a raw socket ICMP ping implementation into a basic `traceroute` tool. Traceroute is a network diagnostic utility that maps the path packets take from the host system to a target destination by using **ICMP (Internet Control Message Protocol)** messages.

The application sends ICMP Echo Requests (Type 8) with increasing **TTL (Time To Live)** values. Each router along the way replies with an ICMP Time Exceeded (Type 11) message when the TTL expires, and the final destination responds with an ICMP Echo Reply (Type 0). By collecting these responses, the tool identifies the path and round-trip time (RTT) to each hop.

> Note: This version simplifies the official RFC 1393 implementation to focus on core protocol behavior.

---

## Objectives

- Validate ICMP Echo Replies by comparing sequence numbers, identifiers, and raw data.
- Enhance the `IcmpPacket_EchoReply` class with validity tracking and helper methods.
- Add debug messages to display expected vs actual values.
- Modify console output to:
  - Show validity of ICMP replies.
  - Report RTT statistics (min, max, avg) and packet loss.
- Interpret ICMP response error codes (e.g., destination unreachable, TTL expired).
- Implement full traceroute functionality with increasing TTLs.

---

## Key Features

- ICMP-based Traceroute using raw sockets.
- Per-hop IP address discovery and RTT calculation.
- Robust packet validation and logging.
- Error code interpretation for human-readable output.
- RTT statistics: min, max, avg, and packet loss percentage.

---

## How It Works

1. Sends ICMP Echo Request with `TTL = 1`.
2. Each intermediate router decrements TTL by 1.
3. When TTL reaches 0, the router returns **ICMP Time Exceeded (Type 11)**.
4. Final destination replies with **ICMP Echo Reply (Type 0)**.
5. By tracking replies, the route is mapped hop-by-hop.

---

## Running the Program

> ⚠️ Raw socket operations require administrator/root privileges.

### On Linux/macOS:
```bash
sudo python3 IcmpHelperLibrary.py
```

## Sample Output
```bash
1   192.168.0.1     2 ms
2   10.0.0.1        6 ms
3   * * *           Request timed out
4   8.8.8.8         24 ms

--- Statistics ---
Min RTT: 2 ms
Max RTT: 24 ms
Avg RTT: 10.6 ms
Packet Loss: 25%
```

### ICMP Header Breakdown

| Bits     | Field      | Description                              |
|----------|------------|------------------------------------------|
| 160–167  | Type       | ICMP message type (e.g., 8 = Echo)       |
| 168–175  | Code       | Subtype of the ICMP type                 |
| 176–191  | Checksum   | Header + data error checker              |
| 192–207  | Identifier | Used to match request and reply          |
| 208–223  | Sequence   | Sequence number for matching packets     |


### ICMP Message Types Used

| Type | Code | Meaning                           |
| ---- | ---- | --------------------------------- |
| 0    | 0    | Echo Reply                        |
| 3    | 0–15 | Destination Unreachable (various) |
| 8    | 0    | Echo Request                      |
| 11   | 0    | Time Exceeded (TTL Expired)       |


## Acknowledgments
Portions of this README were developed with the assistance of ChatGPT by OpenAI.