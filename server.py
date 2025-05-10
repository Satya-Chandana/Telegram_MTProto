from flask import Flask, request, jsonify, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Random import get_random_bytes
import base64
import json
import time
from collections import defaultdict
import struct
import hashlib

app = Flask(__name__)

# Add CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Global variables
server_nonce = get_random_bytes(16)
server_key = RSA.generate(2048)
server_private_key = PKCS1_v1_5.new(server_key)
server_dh_private = 123456789

p = 499
q = 547
pq = p * q

auth_keys = {}
session_ids = {}
salt = base64.b64encode(get_random_bytes(8)).decode()
message_ids = defaultdict(set)
seq_no = defaultdict(int)
last_message_id = defaultdict(int)

# Add these after the existing global variables
connected_peers = set()
peer_messages = defaultdict(lambda: defaultdict(list))  # Store messages for each peer pair

# Store ECDH public keys in memory (for demo; use a DB for production)
ecdh_public_keys = {}

# Utilities
def generate_message_id():
    return int(time.time() * 2**30)

def pad_message(data):
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_message(data):
    if not data:
        raise ValueError("Empty data")
    
    # Try to get padding length from last byte
    padding_length = data[-1]
    
    # Validate padding length is within reasonable bounds
    if padding_length > 16:
        # If padding length is too large, try to find valid padding
        for i in range(1, 17):
            if all(b == i for b in data[-i:]):
                return data[:-i]
        # If no valid padding found, return data as is
        return data
    
    # Verify padding bytes
    if padding_length > 0:
        padding_start = len(data) - padding_length
        if all(b == padding_length for b in data[padding_start:]):
            return data[:padding_start]
    
    # If padding verification fails, return data as is
    return data

def aes_ige_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv[:16])
    padded_data = pad_message(plaintext)
    return cipher.encrypt(padded_data)

def aes_ige_decrypt(ciphertext, key, message_key, is_from_server=False):
    try:
        print(f"Starting decryption with:")
        print(f"Key length: {len(key)}")
        print(f"Key bytes: {key.hex()}")
        print(f"Message key length: {len(message_key)}")
        print(f"Message key bytes: {message_key.hex()}")
        print(f"Ciphertext length: {len(ciphertext)}")
        print(f"Ciphertext bytes: {ciphertext.hex()}")
        
        # Get the x byte from auth_key based on whether message is from client or server
        x = 8 if is_from_server else 0
        
        # Take the appropriate slice of auth_key for message_key calculation
        auth_key_slice = key[88 + x:120 + x]
        
        # Generate aes key and iv
        sha2a = bytearray(52)
        sha2b = bytearray(52)
        sha2c = bytearray(52)
        sha2d = bytearray(52)
        
        sha2a[0:16] = message_key
        sha2a[16:52] = key[x:x + 36]
        
        sha2b[0:36] = key[x + 40:x + 76]
        sha2b[36:52] = message_key
        
        sha2c[0:16] = message_key
        sha2c[16:52] = key[x + 80:x + 116]
        
        sha2d[0:36] = key[x + 120:x + 156]
        sha2d[36:52] = message_key
        
        # Calculate SHA256 for each part
        a_hash = hashlib.sha256(sha2a).digest()
        b_hash = hashlib.sha256(sha2b).digest()
        c_hash = hashlib.sha256(sha2c).digest()
        d_hash = hashlib.sha256(sha2d).digest()
        
        # Construct AES key and IV
        aes_key = bytearray(32)
        aes_iv = bytearray(32)
        
        aes_key[0:8] = a_hash[0:8]
        aes_key[8:24] = b_hash[8:24]
        aes_key[24:32] = c_hash[24:32]
        
        aes_iv[0:8] = b_hash[0:8]
        aes_iv[8:24] = c_hash[8:24]
        aes_iv[24:32] = d_hash[24:32]
        
        print(f"Derived AES key: {aes_key.hex()}")
        print(f"Derived AES IV: {aes_iv.hex()}")
        
        # Create AES-CBC cipher
        cipher = AES.new(bytes(aes_key), AES.MODE_CBC, iv=bytes(aes_iv[:16]))
        
        # Decrypt data
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        unpadded = unpad_message(decrypted)
        
        # Try to decode as JSON
        try:
            message_str = unpadded.decode('utf-8')
            message_packet = json.loads(message_str)
            print(f"Decrypted packet: {message_packet}")
            return message_packet
        except Exception as e:
            print(f"Failed to decode JSON: {str(e)}")
            return unpadded
            
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        raise

@app.route('/')
def serve_index():
    return send_file('client_ui.html')

@app.route('/req_pq', methods=['POST', 'OPTIONS'])
def req_pq():
    if request.method == 'OPTIONS':
        return jsonify({})
    nonce = request.json.get("nonce")
    res = {
        "nonce": nonce,
        "server_nonce": base64.b64encode(server_nonce).decode(),
        "pq": hex(pq)[2:],
        "fingerprint": hex(server_key.n)[2:]
    }
    return jsonify(res)

@app.route('/req_dh_params', methods=['POST', 'OPTIONS'])
def req_dh_params():
    if request.method == 'OPTIONS':
        return jsonify({})
    encrypted = base64.b64decode(request.json.get("encrypted_data"))
    decrypted = server_private_key.decrypt(encrypted, None)
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(32)
    encrypted_response = aes_ige_encrypt(decrypted, aes_key, iv)
    res = {
        "nonce": request.json.get("nonce"),
        "server_nonce": request.json.get("server_nonce"),
        "encrypted_answer": base64.b64encode(encrypted_response).decode(),
        "iv": base64.b64encode(iv).decode()
    }
    return jsonify(res)

@app.route('/set_client_dh_params', methods=['POST', 'OPTIONS'])
def set_client_dh_params():
    if request.method == 'OPTIONS':
        return jsonify({})
    try:
        data = request.json
        g_b = int(data['g_b'], 16)
        
        # Generate a secure random number for server's private key
        server_dh_private = int.from_bytes(get_random_bytes(32), 'big')
        
        # Compute auth key using secure parameters
        auth_key = pow(g_b, server_dh_private, pq)
        
        # Ensure auth key is 256 bits (32 bytes) and has good entropy
        auth_key_bytes = auth_key.to_bytes(32, 'big', signed=False)
        
        # If the auth key is too small, pad it with random bytes
        if auth_key < 2**256:
            padding = get_random_bytes(32 - len(auth_key_bytes))
            auth_key_bytes = padding + auth_key_bytes
        
        # Verify the auth key has good entropy
        if all(b == 0 for b in auth_key_bytes[:-4]):
            # If the key is mostly zeros, generate a new one
            auth_key_bytes = get_random_bytes(32)
        
        auth_key_b64 = base64.b64encode(auth_key_bytes).decode()
        session_id = base64.b64encode(get_random_bytes(8)).decode()

        auth_keys[data['client_id']] = auth_key_b64
        session_ids[data['client_id']] = session_id
        message_ids[data['client_id']] = set()
        seq_no[data['client_id']] = 0
        last_message_id[data['client_id']] = 0

        # 🔽🔽🔽 Add your log prints here 🔽🔽🔽
        print("========== [DH Params Established] ==========")
        print(f"Client ID      : {data['client_id']}")
        print(f"g_b (hex)      : {data['g_b']}")
        print(f"Auth Key (b64) : {auth_key_b64}")
        print(f"Session ID     : {session_id}")
        print(f"Salt           : {salt}")
        print("=============================================")

        res = {
            "auth_key": auth_key_b64,
            "status": "Auth key established",
            "session_id": session_id,
            "salt": salt
        }
        return jsonify(res)
    except Exception as e:
        print(f"Error in set_client_dh_params: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/register_peer', methods=['POST'])
def register_peer():
    client_id = request.json.get('client_id')
    if client_id:
        connected_peers.add(client_id)
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid client ID"}), 400

@app.route('/get_peers', methods=['GET'])
def get_peers():
    client_id = request.args.get('client_id')
    if not client_id:
        return jsonify({"error": "Client ID required"}), 400
    return jsonify({"peers": list(connected_peers - {client_id})})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    client_id = request.args.get('client_id')
    peer = request.args.get('peer')
    if not client_id or not peer:
        return jsonify({"error": "Client ID and peer required"}), 400
    
    # Get messages for this peer pair
    messages = []
    if client_id in peer_messages and peer in peer_messages[client_id]:
        messages.extend(peer_messages[client_id][peer])
    if peer in peer_messages and client_id in peer_messages[peer]:
        messages.extend(peer_messages[peer][client_id])
    
    # Sort messages by timestamp
    messages.sort(key=lambda x: x['timestamp'])
    return jsonify(messages)

@app.route('/poll_messages', methods=['GET'])
def poll_messages():
    client_id = request.args.get('client_id')
    last_msg_id = request.args.get('last_msg_id', '0')
    
    if not client_id:
        return jsonify({"error": "Client ID required"}), 400
    
    # Convert last_msg_id to int for comparison
    try:
        last_msg_id = int(last_msg_id)
    except ValueError:
        last_msg_id = 0
    
    # Get all messages for this client from all peers
    all_messages = []
    for peer_id in peer_messages:
        if peer_id == client_id:
            continue
        
        # Get messages where this client is the recipient
        if client_id in peer_messages[peer_id]:
            messages = peer_messages[peer_id][client_id]
            for msg in messages:
                if int(msg['message_id']) > last_msg_id:
                    msg['from_peer'] = peer_id
                    all_messages.append(msg)
    
    # Sort messages by message_id
    all_messages.sort(key=lambda x: int(x['message_id']))
    
    return jsonify({"messages": all_messages})

@app.route('/secure_message', methods=['POST'])
def secure_message():
    try:
        msg = request.json
        
        print(f"[Secure Message] Received from {msg['client_id']} to {msg['target_peer']}")
        print(f"[Secure Message] Message ID: {msg['message_id']}")
        print(f"[Secure Message] Message Key: {msg['message_key']}")
        print(f"[Secure Message] IV: {msg.get('iv', '')}")
        print(f"[Secure Message] Encrypted Data (base64): {msg['encrypted_data']}")

        client_id = msg['client_id']
        target_peer = msg['target_peer']
        
        # Check message ID
        msg_id = int(msg['message_id'])
        if msg_id in message_ids[client_id]:
            return jsonify({"error": "Duplicate message"}), 409
        
        # Check message time
        current_time = int(time.time())
        msg_time = msg_id >> 32
        time_diff = abs(current_time - msg_time)
        
        if time_diff > 300:
            return jsonify({
                "error": "Message too old",
                "details": f"Message time: {msg_time}, Current time: {current_time}, Difference: {time_diff} seconds"
            }), 410
        
        # Check sequence number
        current_seq = seq_no[client_id]
        if msg.get('seq_no', 0) != current_seq:
            return jsonify({"error": "Invalid sequence number"}), 400
        
        # Create message data without decryption
        message_data = {
            "message_id": msg_id,
            "encrypted_data": msg['encrypted_data'],
            "message_key": msg['message_key'],
            "timestamp": time.time(),
            "from": client_id,
            "to": target_peer
        }
        
        # Initialize message storage if needed
        if client_id not in peer_messages:
            peer_messages[client_id] = defaultdict(list)
        if target_peer not in peer_messages:
            peer_messages[target_peer] = defaultdict(list)
        
        # Store message for sender
        peer_messages[client_id][target_peer].append(message_data)
        
        # Store message for receiver
        peer_messages[target_peer][client_id].append(message_data)
        
        print(f"Message stored for {client_id} -> {target_peer}")
        
        message_ids[client_id].add(msg_id)
        seq_no[client_id] += 1
        last_message_id[client_id] = msg_id
        
        response = {
            "msg_id": generate_message_id(),
            "seq_no": seq_no[client_id],
            "status": "Message received securely",
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            "last_msg_id": last_message_id[client_id]
        }
        
        return jsonify(response)
    except Exception as e:
        print(f"Error in secure_message: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/set_ecdh_pubkey', methods=['POST'])
def set_ecdh_pubkey():
    data = request.json
    client_id = data['client_id']
    pubkey = data['pubkey']
    ecdh_public_keys[client_id] = pubkey
    return jsonify({'status': 'ok'})

@app.route('/get_ecdh_pubkey', methods=['GET'])
def get_ecdh_pubkey():
    peer_id = request.args.get('peer_id')
    pubkey = ecdh_public_keys.get(peer_id)
    if pubkey:
        return jsonify({'pubkey': pubkey})
    else:
        return jsonify({'error': 'No public key found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
