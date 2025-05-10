# MTProto 2.0-Inspired Secure Messaging Server (Python/Flask)

This project implements a secure messaging system inspired by Telegram's MTProto 2.0 protocol. It demonstrates core security concepts including Diffie-Hellman key exchange, AES-IGE encryption, and secure message handling.

## 🚀 Features Implemented

### 🔐 Security Features
- Diffie-Hellman Auth Key Exchange
- AES-IGE Message Encryption (256-bit)
- Message ID Validation
- Sequence Number Tracking
- Time-based Message Validation
- Duplicate Message Prevention
- Session Management
- Salt Generation

### 📡 Protocol Components
1. Handshake Protocol
   - Nonce Exchange
   - PQ Parameter Handling
   - DH Key Exchange
   - Auth Key Generation

2. Message Layer
   - 64-bit Message IDs (time-based)
   - Sequence Numbers
   - Message Acknowledgment
   - Time Validation (5-minute window)

3. Encryption
   - AES-IGE Mode
   - 256-bit Keys
   - Proper IV Handling
   - Message Padding

## ⚙️ Setup Instructions

### Requirements
- Python 3.7+
- Flask
- PyCryptoDome

### Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Server
```bash
python server.py
```
Server will start on: http://localhost:8080

## 📡 API Endpoints

### 1. POST /req_pq
Request:
```json
{
  "nonce": "random_nonce_base64"
}
```
Response:
```json
{
  "nonce": "...",
  "server_nonce": "...",
  "pq": "hex_pq",
  "fingerprint": "hex_fingerprint"
}
```

### 2. POST /set_client_dh_params
Request:
```json
{
  "nonce": "...",
  "server_nonce": "...",
  "g_b": "hex_dh_value",
  "client_id": "user123"
}
```
Response:
```json
{
  "auth_key": "base64_auth_key",
  "session_id": "base64_session_id",
  "salt": "base64_salt",
  "status": "Auth key established"
}
```

### 3. POST /secure_message
Request:
```json
{
  "client_id": "user123",
  "message_id": "64bit_message_id",
  "session_id": "base64_session_id",
  "seq_no": 0,
  "encrypted_data": "base64_encrypted_message",
  "iv": "base64_iv"
}
```
Response:
```json
{
  "msg_id": "64bit_message_id",
  "seq_no": 1,
  "status": "Message received securely",
  "timestamp": "ISO_timestamp",
  "last_msg_id": "64bit_message_id"
}
```

## 🧠 Protocol Internals

### Message ID Structure
- 64-bit integer
- Upper 32 bits: Unix timestamp
- Lower 32 bits: Random number

### Security Measures
1. Message Validation
   - Time-based validation (5-minute window)
   - Duplicate message prevention
   - Sequence number validation

2. Encryption
   - AES-IGE mode
   - 256-bit keys
   - Proper IV handling
   - Message padding

3. Key Exchange
   - DH parameters: p=499, q=547
   - Auth key generation
   - Session management

## 🛡️ Security Considerations

### Implemented Security Features
- Time-based message validation
- Duplicate message prevention
- Sequence number tracking
- Proper key handling
- Message padding

### Limitations (Educational Purposes)
- Simplified DH parameters
- Basic error handling
- No message retry mechanism
- No message container support

## 🧑‍💻 Learning Outcomes

1. Cryptographic Concepts
   - Diffie-Hellman key exchange
   - AES encryption
   - Message authentication
   - Session management

2. Protocol Design
   - Message layer implementation
   - Sequence number handling
   - Time-based validation
   - Error handling

3. Security Implementation
   - Key generation
   - Message encryption
   - Session management
   - Security validation

## 📚 References
- MTProto 2.0 Protocol Documentation
- Telegram Security Guidelines
- AES-IGE Implementation Details

## 🐛 Known Issues
- Limited error recovery
- Basic message handling
- Simplified security parameters

## 🔜 Future Improvements
- Message retry mechanism
- Message container support
- Enhanced error handling
- Additional security features

## 📝 License
MIT License - For educational purposes only
