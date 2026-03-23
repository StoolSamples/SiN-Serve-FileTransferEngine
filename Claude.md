# High-Performance UDP File Transfer System
## Continuation Engineering Specification (Post Phase 1 & 2)

You are a senior Python systems engineer.

You are continuing development of an existing high-performance file transfer system.  
**Phase 1 (core UDP reliability + chunking + file handling) and Phase 2 are already COMPLETE and provided to you as source files.**

---

# 🚨 CRITICAL DIRECTIVE

DO NOT re-implement Phase 1 or Phase 2.

You MUST:
- Analyze the provided codebase
- Reuse ALL existing working components
- Extend the system WITHOUT breaking existing functionality
- Refactor only when absolutely necessary and justify it

If functionality already exists:
→ USE IT  
→ DO NOT DUPLICATE IT  

---

# 🎯 OBJECTIVE

Continue building a **production-ready, high-performance UDP-based file transfer system** with modular architecture and scalability.

---

# 🧱 REQUIRED ARCHITECTURE

The system MUST follow this layered structure:

- GUI Layer (PyQt6) *(to be implemented later phase)*
- Transfer Controller
- Protocol Engine
- Transport Layer (UDP)
- Crypto Engine (AES-256-GCM) *(future phase)*
- Integrity Engine (SHA-256 chunk hashing) *(already implemented — extend if needed)*
- Rate Limiter *(hook now, implement later)*
- Config System (JSON)

---

# 🔍 FIRST TASK (MANDATORY)

Before writing ANY code:

1. Analyze all provided files
2. Produce a **System Audit Report** that includes:
   - What components already exist
   - What responsibilities each module handles
   - Any architectural violations
   - Performance bottlenecks
   - Missing abstractions needed for scaling

3. Produce a **Refactor Plan (if needed)**:
   - ONLY if required for multi-stream or scalability
   - Must be minimal and justified

DO NOT begin implementation until this is complete.

---

# ⚙️ CURRENT ASSUMPTIONS (FROM EXISTING SYSTEM)

The existing system already supports:

- UDP-based transport
- Chunk-based file transfer
- SHA-256 chunk validation
- Out-of-order packet handling
- Disk-based writes using byte offsets
- Chunk tracking + resend logic

These MUST remain intact and unchanged in behavior.

---

# 🚀 DEVELOPMENT PHASES (CONTINUATION)

## Phase 3 — Multi-Stream Transfer Engine

### Requirements:

- Add support for multiple simultaneous UDP streams
- Each stream operates on its own port
- Streams must:
  - Share a unified transfer session
  - Coordinate chunk distribution
  - Avoid duplicate chunk transmission

### Implementation Details:

- Introduce a **Stream Manager**
- Modify Transfer Controller to:
  - Split chunk workload across streams
  - Dynamically assign chunks to streams
- Receiver must:
  - Accept data from multiple sockets
  - Merge seamlessly into existing file-writing system

### Dynamic Scaling:

- Begin with fixed stream count (configurable)
- Add hooks for future adaptive scaling

---

## Phase 4 — Advanced Protocol Enhancements

### Add:

- Selective ACKs (SACK-style acknowledgment)
- Smarter resend strategy:
  - Avoid duplicate resend storms
  - Prioritize oldest missing chunks
- Packet pacing improvements

### Introduce:

- Packet windowing system
- RTT estimation (basic)

---

## Phase 5 — Rate Limiting System (Implementation)

### Requirements:

- Token Bucket Algorithm
- Independent:
  - Send rate limit
  - Receive rate limit

### Must:

- Integrate without breaking throughput
- Be dynamically adjustable

---

## Phase 6 — Encryption Layer

### Requirements:

- AES-256-GCM
- Encrypt DATA packets ONLY
- Maintain:
  - Packet integrity validation
  - Chunk checksum validation AFTER decryption

### Constraints:

- Zero-copy where possible
- Minimal performance overhead

---

## Phase 7 — GUI (PyQt6)

### Features:

- File selection
- Transfer progress per stream
- Throughput graphs
- Error reporting
- Connection/session management

---

# 📦 CONFIGURATION SYSTEM

Must be JSON-based and include:

```json
{
  "chunk_size": 2097152,
  "streams": 4,
  "ports": [5001, 5002, 5003, 5004],
  "rate_limit_send": null,
  "rate_limit_receive": null
}