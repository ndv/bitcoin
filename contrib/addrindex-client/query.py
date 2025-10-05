#!/usr/bin/env python3
import argparse
import os
import socket
import struct
import time
import hashlib
import random
from typing import Tuple, Optional
from binascii import hexlify
from base58 import b58encode_check, b58decode_check

import numpy as np
import pyopencl as cl

# ======== Bitcoin P2P constants (mainnet) ========
MAGIC_MAINNET = 0xD9B4BEF9  # message start
USER_AGENT = b"/addrindex-client:0.1/"
PROTOCOL_VERSION = 70016
SERVICES = 0  # we don't advertise addrindex ourselves
RELAY = 1

# Command names from ndv/bitcoin README (<=12 bytes, NUL-padded)
# https://github.com/ndv/bitcoin  (address_index branch README)
CMD_VERSION       = b"version"
CMD_VERACK        = b"verack"
CMD_SENDCHALLENGE = b"challenge"
CMD_GETADDRDATA   = b"getaddrdata"
CMD_SENDADDRDATA  = b"sendaddrdata"

# ======== Helpers ========
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def pack_varint(n: int) -> bytes:
    if n < 0xfd:
        return struct.pack("<B", n)
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)
        
def unpack_varint(b: bytes, pos: int) -> Tuple[int, int]:
    if b[pos] < 0xfd:
        return pos+1, int(b[pos])
    if b[pos] == 0xfd:
        return pos+3, struct.unpack_from("<H", b, pos+1)[0]
    if b[pos] == 0xfe:
        return pos+5, struct.unpack_from("<I", b, pos+1)[0]
    if b[pos] == 0xff:
        return pos+9, struct.unpack("<Q", b, pos+1)[0]
        
def pack_varstr(b: bytes) -> bytes:
    return pack_varint(len(b)) + b

def build_header(command: bytes, payload: bytes, magic: int = MAGIC_MAINNET) -> bytes:
    cmd12 = command.ljust(12, b"\x00")[:12]
    length = struct.pack("<I", len(payload))
    checksum = sha256d(payload)[:4]
    return struct.pack("<I", magic) + cmd12 + length + checksum

def send_msg(sock: socket.socket, command: bytes, payload: bytes):
    #print(f"send_msg {command}\n")
    hdr = build_header(command, payload)
    sock.sendall(hdr + payload)

class BlockHeader:
    def __init__(self, nVersion: int, hashPrevBlock: bytes, hashMerkleRoot: bytes, nTime: int, nBits: int, nNonce: int):
        self.nVersion = nVersion
        self.hashPrevBlock = hashPrevBlock
        self.hashMerkleRoot = hashMerkleRoot
        self.nTime = nTime
        self.nBits = nBits
        self.nNonce = nNonce
        
class OutPoint:
    def __init__(self, txid: bytes, n: int):
        self.txid = txid
        self.n = n
        
class TxIn:
    def __init__(self, prevout: OutPoint, scriptSig: bytes, nSequence: int):
        self.prevout = prevout
        self.scriptSig = scriptSig
        self.nSequence = nSequence
        
class TxOut:
    def __init__(self, amount: int, scriptPubKey: bytes):
        self.amount = amount
        self.scriptPubKey = scriptPubKey
        
class Transaction:
    def __init__(self, vin: list[TxIn], vout: list[TxOut], version: int, nLockTime: int):
        self.vin = vin
        self.vout = vout
        self.version = version
        self.nLockTime = nLockTime
        
def unpack_transaction(b: bytes, pos: int) -> Tuple[int, Transaction]:
    version, next = struct.unpack_from("<IB", b, pos)
    flags = 0
    if next == 0:
        flags = b[pos+5]
        pos += 6
    else:
        pos += 4
    
    pos, nin = unpack_varint(b, pos)
    vin = []
    for i in range(nin):
        txid, n = struct.unpack_from("<32sI", b, pos)
        txid = txid[::-1]
        prevout = OutPoint(txid, n)
        pos, script_len = unpack_varint(b, pos+36)
        script = b[pos:pos+script_len]
        pos += script_len
        nSequence = struct.unpack_from("<I", b, pos)[0]
        pos += 4
        vin += [TxIn(prevout, script, nSequence)]
        
    pos, nout = unpack_varint(b, pos)
    vout = []
    for i in range(nout):
        amount = struct.unpack_from("<Q", b, pos)[0]
        pos, script_len = unpack_varint(b, pos + 8)
        script = b[pos:pos+script_len]
        pos += script_len
        vout += [TxOut(amount, script)]
        
    if flags & 1 == 1:
        # skip the script witness if any
        pos, n1 = unpack_varint(b, pos)
        for i in range(n1):
            pos, n2 = unpack_varint(b, pos)
            pos += n2
    
    nLockTime = struct.unpack_from("<I", b, pos)[0]
    return pos + 4, Transaction(vin, vout, version, nLockTime)

def hash_tx(tx: Transaction) -> bytes:
    bb = struct.pack("<I", tx.version) + pack_varint(len(tx.vin))
    for i in tx.vin:
        bb += struct.pack("<32sI", i.prevout.txid[::-1], i.prevout.n) + pack_varint(len(i.scriptSig)) + i.scriptSig + struct.pack("<I", i.nSequence)
    bb += pack_varint(len(tx.vout))
    for o in tx.vout:
        bb += struct.pack("<Q", o.amount) + pack_varint(len(o.scriptPubKey)) + o.scriptPubKey
    bb += struct.pack("<I", tx.nLockTime)
    return sha256d(bb)[::-1]
    
class WalletTransaction:
    def __init__(self, block_header: BlockHeader, height: int, chainWork: bytes, tx: Transaction, pos: int, proof: list[bytes]):
        self.block_header = block_header
        self.height = height
        self.chainWork = chainWork
        self.tx = tx
        self.pos = pos
        self.proof = proof
        
class AddrResponce:
    def __init__(self, txs: list[WalletTransaction], eof: bool, lastBlockHeight: int, lastBlockHash: bytes):
        self.txs = txs
        self.eof = eof
        # if eof, the last block height & hash which is indexed
        self.lastBlockHeight = lastBlockHeight
        self.lastBlockHash = lastBlockHash

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_REV = {c: i for i, c in enumerate(CHARSET)}

def _polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _create_checksum(hrp, data):  # bech32 (NOT bech32m)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _verify_checksum(hrp, data):
    return _polymod(_hrp_expand(hrp) + data) == 1

def bech32_encode(hrp, data):  # data is list of 5-bit integers
    combined = data + _create_checksum(hrp, data)
    return hrp + '1' + ''.join(CHARSET[d] for d in combined)
    
# ---------------- DECODE ----------------
def bech32_decode(bech):
    """Return (hrp, data) or (None, None) if invalid."""
    if not (8 <= len(bech) <= 90):
        return None, None
    bech = bech.lower()
    if bech.rfind('1') == -1:
        return None, None
    pos = bech.rfind('1')
    hrp = bech[:pos]
    data_part = bech[pos+1:]
    if any(c not in CHARSET for c in data_part):
        return None, None
    data = [CHARSET_REV[c] for c in data_part]
    if not _verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]
    
def convertbits(data_bytes, from_bits=8, to_bits=5, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    for b in data_bytes:
        if b < 0 or b >> from_bits:
            raise ValueError("Invalid byte")
        acc = (acc << from_bits) | b
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    else:
        if bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
            raise ValueError("Invalid leftover bits")
    return ret

def script_to_addr(s: bytes) -> str:
    if len(s) == 23 and s[0] == 169 and s[1] == 0x14 and s[22] == 135:
        return b58encode_check(b'\x05' + s[2:22]).decode()
    if s[0] == 0 or s[0] >= 81 and s[0] <= 96:
        if s[0] == 0:
            version = 0
        else:
            version = s[0] - 80
        program = s[2:]
        if version == 0 and len(program) == 20:
            return bech32_encode("bc", [0] + convertbits(program, 8, 5, pad=True))
        if version == 0 and len(program) == 32:
            return bech32_encode("bc", [0] + convertbits(program, 8, 5, pad=True))
        if version == 1 and len(program) == 32:
            return "taproot addr"
        return "unknown witness addr"
    if len(s) == 25 and s[0] == 118 and s[1] == 169 and s[2] == 20 and s[23] == 136 and s[24] == 172:
        return b58encode_check(b'\0'+s[3:23]).decode()
    print("unknown script " + hexlify(s).decode())
    return "Unknown address"
            
def dump(resp: AddrResponce):
    for tx in resp.txs:
        hash = hash_tx(tx.tx)
        print(hexlify(hash).decode())
        print("In:  ", end='')
        for i in tx.tx.vin:
            print(hexlify(i.prevout.txid).decode() + "/" + str(i.prevout.n), end=', ')
        print("\nOut: ")
        for o in tx.tx.vout:
            print("  " + str(o.amount) + " -> " + script_to_addr(o.scriptPubKey))

def unpack_addr_responce(b: bytes) -> AddrResponce:
    pos, n = unpack_varint(b, 0)
    txs = []
    for i in range(n):
        fmt = "<I32s32sIII"
        nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce = struct.unpack_from(fmt, b, pos)
        hashPrevBlock = hashPrevBlock[::-1]
        hashMerkleRoot = hashMerkleRoot[::-1]
        pos += struct.calcsize(fmt)
        header = BlockHeader(nVersion, hashPrevBlock, hashMerkleRoot, nTime, nBits, nNonce)
        
        fmt = "<i32s"
        height, chainWork = struct.unpack_from(fmt, b, pos)
        chainWork = chainWork[::-1]
        pos += struct.calcsize(fmt)
        
        pos, tx = unpack_transaction(b, pos)
        
        txpos = struct.unpack_from("<I", b, pos)[0]
        pos += 4
        
        pos, proof_len = unpack_varint(b, pos)
        proof = []
        for k in range(proof_len):
            hash = b[pos+k*32:pos+k*32+32]
            hash = hash[::-1]
            proof += [hash]
            
        pos += proof_len*32
        txs += [WalletTransaction(header, height, chainWork, tx, txpos, proof)]
    
    eof = b[pos]
    lastBlockHeight = 0
    lastBlockHash = b''
    if eof == 1:
        lastBlockHeight, lastBlockHash = struct.unpack_from("<I32s", b, pos + 1)
        lastBlockHash = lastBlockHash[::-1]
    
    return AddrResponce(txs, eof, lastBlockHeight, lastBlockHash)
    
def recv_all(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf

def read_msg(sock: socket.socket) -> Tuple[str, bytes]:
    # 24-byte header
    hdr = recv_all(sock, 24)
    magic, = struct.unpack("<I", hdr[:4])
    if magic != MAGIC_MAINNET:
        raise ValueError(f"Unexpected magic {magic:#x}")
    command = hdr[4:16].rstrip(b"\x00").decode("ascii", errors="ignore")
    
    #print(f"received {command}\n")
    
    length, = struct.unpack("<I", hdr[16:20])
    checksum = hdr[20:24]
    payload = recv_all(sock, length)
    if sha256d(payload)[:4] != checksum:
        raise ValueError("Bad payload checksum")
    return command, payload

# ======== Standard Bitcoin handshake ========
def make_version_payload(addr_recv=(0, 0), addr_from=(0, 0), start_height=0) -> bytes:
    """
    See: Bitcoin P2P 'version' message format.
    """
    version = struct.pack("<i", PROTOCOL_VERSION)
    services = struct.pack("<Q", SERVICES)
    timestamp = struct.pack("<q", int(time.time()))

    def net_addr(services_val: int, ip: bytes, port: int) -> bytes:
        # services (8) + IPv6/IPv4-mapped (16) + port (2 big-endian)
        return struct.pack("<Q", services_val) + ip + struct.pack(">H", port)

    # IPv4-mapped ::ffff:0.0.0.0 for both (we don't care here)
    ip_zero = b"\x00" * 10 + b"\xff\xff" + b"\x00\x00\x00\x00"
    addr_recv_bytes = net_addr(0, ip_zero, addr_recv[1] if addr_recv[1] else 8333)
    addr_from_bytes = net_addr(0, ip_zero, addr_from[1] if addr_from[1] else 0)

    nonce = struct.pack("<Q", random.getrandbits(64))
    ua = pack_varstr(USER_AGENT)
    start_height_bytes = struct.pack("<i", start_height)
    relay = struct.pack("<?", RELAY == 1)

    return (version + services + timestamp + addr_recv_bytes + addr_from_bytes +
            nonce + ua + start_height_bytes + relay)

# ======== Address-index extension logic (per ndv/bitcoin README) ========
# CAddrRequest (little-endian fields as in typical Bitcoin serialization):
# struct CAddrRequest {
#   uint64_t key_start;
#   uint256  transaction_start;   // 32 bytes (all zero for first page)
#   uint64_t key_end;
#   uint64_t nonce;               // mined to minimize sha256(challenge||addrRequest)
# }
#
# Challenge update after each request:
#   next_challenge = sha256("next challenge" || prev_challenge)
#
# The node *initiates* by sending SENDCHALLENGE{challenge} (8 bytes).
# Then we answer with GETADDRDATA{CAddrRequest}, and receive SENDADDRDATA{...}.
# Source: README in ndv/bitcoin address_index branch.
# https://github.com/ndv/bitcoin
#

KERNEL_SRC = r"""
uint byteswap(uint x)
{
    return (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00) | (x >> 24);
}
__constant unsigned int _IV[8] = {
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19
};

unsigned int rotr(unsigned int x, int n)
{
	return (x >> n) ^ (x << (32 - n));
}

unsigned int MAJ(unsigned int a, unsigned int b, unsigned int c)
{
	return (a & b) ^ (a & c) ^ (b & c);
}

unsigned int CH(unsigned int e, unsigned int f, unsigned int g)
{
	return (e & f) ^ (~e & g);
}

unsigned int s0(unsigned int x)
{
	return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

unsigned int s1(unsigned int x)
{
	return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}


#define round(a, b, c, d, e, f, g, h, m, k)\
{\
   unsigned int s = CH(e, f, g) + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + k + m;\
   d += s + h;\
   h += s + MAJ(a, b, c) + (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));\
}

void sha256_digest(unsigned int w[16], unsigned int digest[8])
{
	//printf(\"sha256 %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d\\n\", w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);

	unsigned int a, b, c, d, e, f, g, h;

	a = _IV[0];
	b = _IV[1];
	c = _IV[2];
	d = _IV[3];
	e = _IV[4];
	f = _IV[5];
	g = _IV[6];
	h = _IV[7];

	round(a, b, c, d, e, f, g, h, w[0], 0x428a2f98U);
	round(h, a, b, c, d, e, f, g, w[1], 0x71374491U);
	round(g, h, a, b, c, d, e, f, w[2], 0xb5c0fbcfU);
	round(f, g, h, a, b, c, d, e, w[3], 0xe9b5dba5U);
	round(e, f, g, h, a, b, c, d, w[4], 0x3956c25bU);
	round(d, e, f, g, h, a, b, c, w[5], 0x59f111f1U);
	round(c, d, e, f, g, h, a, b, w[6], 0x923f82a4U);
	round(b, c, d, e, f, g, h, a, w[7], 0xab1c5ed5U);
	round(a, b, c, d, e, f, g, h, w[8], 0xd807aa98U);
	round(h, a, b, c, d, e, f, g, w[9], 0x12835b01U);
	round(g, h, a, b, c, d, e, f, w[10], 0x243185beU);
	round(f, g, h, a, b, c, d, e, w[11], 0x550c7dc3U);
	round(e, f, g, h, a, b, c, d, w[12], 0x72be5d74U);
	round(d, e, f, g, h, a, b, c, w[13], 0x80deb1feU);
	round(c, d, e, f, g, h, a, b, w[14], 0x9bdc06a7U);
	round(b, c, d, e, f, g, h, a, w[15], 0xc19bf174U);

	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0xe49b69c1U);
	round(h, a, b, c, d, e, f, g, w[1], 0xefbe4786U);
	round(g, h, a, b, c, d, e, f, w[2], 0xfc19dc6U);
	round(f, g, h, a, b, c, d, e, w[3], 0x240ca1ccU);
	round(e, f, g, h, a, b, c, d, w[4], 0x2de92c6fU);
	round(d, e, f, g, h, a, b, c, w[5], 0x4a7484aaU);
	round(c, d, e, f, g, h, a, b, w[6], 0x5cb0a9dcU);
	round(b, c, d, e, f, g, h, a, w[7], 0x76f988daU);
	round(a, b, c, d, e, f, g, h, w[8], 0x983e5152U);
	round(h, a, b, c, d, e, f, g, w[9], 0xa831c66dU);
	round(g, h, a, b, c, d, e, f, w[10], 0xb00327c8U);
	round(f, g, h, a, b, c, d, e, w[11], 0xbf597fc7U);
	round(e, f, g, h, a, b, c, d, w[12], 0xc6e00bf3U);
	round(d, e, f, g, h, a, b, c, w[13], 0xd5a79147U);
	round(c, d, e, f, g, h, a, b, w[14], 0x6ca6351U);
	round(b, c, d, e, f, g, h, a, w[15], 0x14292967U);

	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0x27b70a85U);
	round(h, a, b, c, d, e, f, g, w[1], 0x2e1b2138U);
	round(g, h, a, b, c, d, e, f, w[2], 0x4d2c6dfcU);
	round(f, g, h, a, b, c, d, e, w[3], 0x53380d13U);
	round(e, f, g, h, a, b, c, d, w[4], 0x650a7354U);
	round(d, e, f, g, h, a, b, c, w[5], 0x766a0abbU);
	round(c, d, e, f, g, h, a, b, w[6], 0x81c2c92eU);
	round(b, c, d, e, f, g, h, a, w[7], 0x92722c85U);
	round(a, b, c, d, e, f, g, h, w[8], 0xa2bfe8a1U);
	round(h, a, b, c, d, e, f, g, w[9], 0xa81a664bU);
	round(g, h, a, b, c, d, e, f, w[10], 0xc24b8b70U);
	round(f, g, h, a, b, c, d, e, w[11], 0xc76c51a3U);
	round(e, f, g, h, a, b, c, d, w[12], 0xd192e819U);
	round(d, e, f, g, h, a, b, c, w[13], 0xd6990624U);
	round(c, d, e, f, g, h, a, b, w[14], 0xf40e3585U);
	round(b, c, d, e, f, g, h, a, w[15], 0x106aa070U);


	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0x19a4c116U);
	round(h, a, b, c, d, e, f, g, w[1], 0x1e376c08U);
	round(g, h, a, b, c, d, e, f, w[2], 0x2748774cU);
	round(f, g, h, a, b, c, d, e, w[3], 0x34b0bcb5U);
	round(e, f, g, h, a, b, c, d, w[4], 0x391c0cb3U);
	round(d, e, f, g, h, a, b, c, w[5], 0x4ed8aa4aU);
	round(c, d, e, f, g, h, a, b, w[6], 0x5b9cca4fU);
	round(b, c, d, e, f, g, h, a, w[7], 0x682e6ff3U);
	round(a, b, c, d, e, f, g, h, w[8], 0x748f82eeU);
	round(h, a, b, c, d, e, f, g, w[9], 0x78a5636fU);
	round(g, h, a, b, c, d, e, f, w[10], 0x84c87814U);
	round(f, g, h, a, b, c, d, e, w[11], 0x8cc70208U);
	round(e, f, g, h, a, b, c, d, w[12], 0x90befffaU);
	round(d, e, f, g, h, a, b, c, w[13], 0xa4506cebU);
	round(c, d, e, f, g, h, a, b, w[14], 0xbef9a3f7U);
	round(b, c, d, e, f, g, h, a, w[15], 0xc67178f2U);

	a += _IV[0];
	b += _IV[1];
	c += _IV[2];
	d += _IV[3];
	e += _IV[4];
	f += _IV[5];
	g += _IV[6];
	h += _IV[7];

	digest[0] = a;
	digest[1] = b;
	digest[2] = c;
	digest[3] = d;
	digest[4] = e;
	digest[5] = f;
	digest[6] = g;
	digest[7] = h;
}

void sha256_digest_add(unsigned int w[16], unsigned int digest[8])
{
	unsigned int a, b, c, d, e, f, g, h;

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];
	f = digest[5];
	g = digest[6];
	h = digest[7];

	round(a, b, c, d, e, f, g, h, w[0], 0x428a2f98U);
	round(h, a, b, c, d, e, f, g, w[1], 0x71374491U);
	round(g, h, a, b, c, d, e, f, w[2], 0xb5c0fbcfU);
	round(f, g, h, a, b, c, d, e, w[3], 0xe9b5dba5U);
	round(e, f, g, h, a, b, c, d, w[4], 0x3956c25bU);
	round(d, e, f, g, h, a, b, c, w[5], 0x59f111f1U);
	round(c, d, e, f, g, h, a, b, w[6], 0x923f82a4U);
	round(b, c, d, e, f, g, h, a, w[7], 0xab1c5ed5U);
	round(a, b, c, d, e, f, g, h, w[8], 0xd807aa98U);
	round(h, a, b, c, d, e, f, g, w[9], 0x12835b01U);
	round(g, h, a, b, c, d, e, f, w[10], 0x243185beU);
	round(f, g, h, a, b, c, d, e, w[11], 0x550c7dc3U);
	round(e, f, g, h, a, b, c, d, w[12], 0x72be5d74U);
	round(d, e, f, g, h, a, b, c, w[13], 0x80deb1feU);
	round(c, d, e, f, g, h, a, b, w[14], 0x9bdc06a7U);
	round(b, c, d, e, f, g, h, a, w[15], 0xc19bf174U);

	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0xe49b69c1U);
	round(h, a, b, c, d, e, f, g, w[1], 0xefbe4786U);
	round(g, h, a, b, c, d, e, f, w[2], 0xfc19dc6U);
	round(f, g, h, a, b, c, d, e, w[3], 0x240ca1ccU);
	round(e, f, g, h, a, b, c, d, w[4], 0x2de92c6fU);
	round(d, e, f, g, h, a, b, c, w[5], 0x4a7484aaU);
	round(c, d, e, f, g, h, a, b, w[6], 0x5cb0a9dcU);
	round(b, c, d, e, f, g, h, a, w[7], 0x76f988daU);
	round(a, b, c, d, e, f, g, h, w[8], 0x983e5152U);
	round(h, a, b, c, d, e, f, g, w[9], 0xa831c66dU);
	round(g, h, a, b, c, d, e, f, w[10], 0xb00327c8U);
	round(f, g, h, a, b, c, d, e, w[11], 0xbf597fc7U);
	round(e, f, g, h, a, b, c, d, w[12], 0xc6e00bf3U);
	round(d, e, f, g, h, a, b, c, w[13], 0xd5a79147U);
	round(c, d, e, f, g, h, a, b, w[14], 0x6ca6351U);
	round(b, c, d, e, f, g, h, a, w[15], 0x14292967U);

	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0x27b70a85U);
	round(h, a, b, c, d, e, f, g, w[1], 0x2e1b2138U);
	round(g, h, a, b, c, d, e, f, w[2], 0x4d2c6dfcU);
	round(f, g, h, a, b, c, d, e, w[3], 0x53380d13U);
	round(e, f, g, h, a, b, c, d, w[4], 0x650a7354U);
	round(d, e, f, g, h, a, b, c, w[5], 0x766a0abbU);
	round(c, d, e, f, g, h, a, b, w[6], 0x81c2c92eU);
	round(b, c, d, e, f, g, h, a, w[7], 0x92722c85U);
	round(a, b, c, d, e, f, g, h, w[8], 0xa2bfe8a1U);
	round(h, a, b, c, d, e, f, g, w[9], 0xa81a664bU);
	round(g, h, a, b, c, d, e, f, w[10], 0xc24b8b70U);
	round(f, g, h, a, b, c, d, e, w[11], 0xc76c51a3U);
	round(e, f, g, h, a, b, c, d, w[12], 0xd192e819U);
	round(d, e, f, g, h, a, b, c, w[13], 0xd6990624U);
	round(c, d, e, f, g, h, a, b, w[14], 0xf40e3585U);
	round(b, c, d, e, f, g, h, a, w[15], 0x106aa070U);


	w[0] = w[0] + s0(w[1]) + w[9] + s1(w[14]);
	w[1] = w[1] + s0(w[2]) + w[10] + s1(w[15]);
	w[2] = w[2] + s0(w[3]) + w[11] + s1(w[0]);
	w[3] = w[3] + s0(w[4]) + w[12] + s1(w[1]);
	w[4] = w[4] + s0(w[5]) + w[13] + s1(w[2]);
	w[5] = w[5] + s0(w[6]) + w[14] + s1(w[3]);
	w[6] = w[6] + s0(w[7]) + w[15] + s1(w[4]);
	w[7] = w[7] + s0(w[8]) + w[0] + s1(w[5]);
	w[8] = w[8] + s0(w[9]) + w[1] + s1(w[6]);
	w[9] = w[9] + s0(w[10]) + w[2] + s1(w[7]);
	w[10] = w[10] + s0(w[11]) + w[3] + s1(w[8]);
	w[11] = w[11] + s0(w[12]) + w[4] + s1(w[9]);
	w[12] = w[12] + s0(w[13]) + w[5] + s1(w[10]);
	w[13] = w[13] + s0(w[14]) + w[6] + s1(w[11]);
	w[14] = w[14] + s0(w[15]) + w[7] + s1(w[12]);
	w[15] = w[15] + s0(w[0]) + w[8] + s1(w[13]);

	round(a, b, c, d, e, f, g, h, w[0], 0x19a4c116U);
	round(h, a, b, c, d, e, f, g, w[1], 0x1e376c08U);
	round(g, h, a, b, c, d, e, f, w[2], 0x2748774cU);
	round(f, g, h, a, b, c, d, e, w[3], 0x34b0bcb5U);
	round(e, f, g, h, a, b, c, d, w[4], 0x391c0cb3U);
	round(d, e, f, g, h, a, b, c, w[5], 0x4ed8aa4aU);
	round(c, d, e, f, g, h, a, b, w[6], 0x5b9cca4fU);
	round(b, c, d, e, f, g, h, a, w[7], 0x682e6ff3U);
	round(a, b, c, d, e, f, g, h, w[8], 0x748f82eeU);
	round(h, a, b, c, d, e, f, g, w[9], 0x78a5636fU);
	round(g, h, a, b, c, d, e, f, w[10], 0x84c87814U);
	round(f, g, h, a, b, c, d, e, w[11], 0x8cc70208U);
	round(e, f, g, h, a, b, c, d, w[12], 0x90befffaU);
	round(d, e, f, g, h, a, b, c, w[13], 0xa4506cebU);
	round(c, d, e, f, g, h, a, b, w[14], 0xbef9a3f7U);
	round(b, c, d, e, f, g, h, a, w[15], 0xc67178f2U);

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
	digest[5] += f;
	digest[6] += g;
	digest[7] += h;
}

__kernel void hash(ulong challenge, ulong key_start, __global const uint* tx, ulong key_end, ulong max_hash, 
	__global ulong* best_complexity, __global volatile ulong* best_nonce)
{
	for (ulong nonce = get_global_id(0) + 1; nonce < 0xffffffffffffffffUL-get_global_size(0); nonce += get_global_size(0)) {
		uint w[16] = {byteswap((uint)challenge), byteswap((uint)(challenge>>32)), byteswap((uint)key_start), byteswap((uint)(key_start>>32)), 
				  tx[7], tx[6], tx[5], tx[4], tx[3], tx[2], tx[1], tx[0], 
				  byteswap((uint)key_end), byteswap((uint)(key_end>>32)), 
				  byteswap((uint)nonce), byteswap((uint)(nonce>>32))};
		uint digest[8];
		sha256_digest(w, digest);
		w[0] = 0x80000000U; for (int i=1; i<15; i++) w[i] = 0; w[15] = 64*8;
		sha256_digest_add(w, digest);
		ulong c = ((ulong)digest[0] << 32) | digest[1];
		if (c < max_hash) {
			*best_complexity = c;
			*best_nonce = nonce;
		}
		barrier(CLK_GLOBAL_MEM_FENCE);
		if (*best_nonce) return;
	}
}
"""

# ======== OpenCL context/program cache ========
_cl_ctx: Optional[cl.Context] = None
_cl_queue: Optional[cl.CommandQueue] = None
_cl_prog: Optional[cl.Program] = None
_cl_device: Optional[cl.Device] = None
_cl_kernel: Optional[cl.Kernel] = None

def _init_opencl():
    global _cl_ctx, _cl_queue, _cl_prog, _cl_device
    if _cl_ctx is not None:
        return
    # Pick first available device (GPU preferred)
    plats = cl.get_platforms()
    if not plats:
        raise RuntimeError("No OpenCL platform found.")
    devices = []
    for p in plats:
        try:
            devices += p.get_devices(device_type=cl.device_type.GPU)
        except:
            pass
    if not devices:
        for p in plats:
            try:
                devices += p.get_devices(device_type=cl.device_type.CPU)
            except:
                pass
    if not devices:
        raise RuntimeError("No OpenCL devices found (GPU/CPU).")
    
    # choose the device owning the maximum compute units
    best_device = devices[0]
    for i in range(1, len(devices)):
        if devices[i].max_compute_units > best_device.max_compute_units:
            best_device = devices[i]
    print(f"[*] Using this device for PoW mining: {best_device.name}")
    _cl_device = best_device;
    _cl_ctx = cl.Context(devices=[_cl_device])
    _cl_queue = cl.CommandQueue(_cl_ctx)
    _cl_prog = cl.Program(_cl_ctx, KERNEL_SRC).build()

def mine_nonce(challenge8: bytes, key_start: int, key_end: int, txid32: bytes, complexity: int) -> Tuple[int, int]:
    """
    Uses OpenCL to find a nonce producing a 64-bit 'complexity' below a target.
    Returns (best_nonce, best_complexity).
    """
    assert len(challenge8) == 8
    assert len(txid32) == 32

    ctx, q, prog = _cl_ctx, _cl_queue, _cl_prog

    # Prepare tx words as 8×uint32 little-endian. Kernel reads tx[7]..tx[0].
    tx_words = np.frombuffer(txid32, dtype=np.dtype(">u4"))  # 8 uint32
    if tx_words.size != 8:
        raise ValueError("txid32 should be 32 bytes")

    # Buffers
    mf = cl.mem_flags
    tx_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=tx_words)

    best_complexity = np.array([np.uint64(0xFFFFFFFFFFFFFFFF)], dtype=np.uint64)
    best_nonce      = np.array([np.uint64(0)], dtype=np.uint64)
    best_complexity_buf = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=best_complexity)
    best_nonce_buf      = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=best_nonce)

    # Work sizes (tweak as you like)
    # A moderate global size works broadly; you can scale up on big GPUs.
    global_size = (_cl_device.max_compute_units*1024,)
    local_size  = None       # let driver choose

    # Inputs
    # NOTE: The kernel byteswaps words itself to big-endian inside.
    key_start_u64 = np.uint64(key_start)
    key_end_u64   = np.uint64(key_end)

    # Reset best_nonce to 0 for this pass so kernel won't early-return immediately.
    best_nonce[...] = 0
    cl.enqueue_copy(q, best_nonce_buf, best_nonce)

    max_hash_u64 = np.uint64(2 ** (64-complexity))
    global _cl_kernel
    if _cl_kernel is None:
        _cl_kernel = cl.Kernel(prog, 'hash')
    evt = _cl_kernel(
        q, global_size, local_size,
        np.uint64(struct.unpack("<Q", challenge8)),
        np.uint64(key_start_u64),
        tx_buf,
        np.uint64(key_end_u64),
        np.uint64(max_hash_u64),
        best_complexity_buf,
        best_nonce_buf
    )
    evt.wait()

    cl.enqueue_copy(q, best_nonce, best_nonce_buf).wait()
    cl.enqueue_copy(q, best_complexity, best_complexity_buf).wait()

    return int(best_nonce[0]), int(best_complexity[0])

def build_getaddrdata_payload(key_start: int, key_end: int, from_txid: bytes, challenge8: bytes, complexity:int ) -> bytes:
    nonce, _ = mine_nonce(challenge8, key_start, key_end, from_txid, complexity)
    payload = struct.pack("<Q", key_start) + from_txid[::-1] + struct.pack("<Q", key_end) + struct.pack("<Q", nonce)
    return payload

def parse_sendchallenge(payload: bytes) -> bytes:
    return struct.unpack("<B8s", payload)

class Wallet:
    def __init__(self, addr: str):
        self.utxos = dict()
        self.addr = addr
        self.transactions = []
        
    def add(self, tx: Transaction):
        relevant = False
        for i in tx.vin:
            key = hexlify(i.prevout.txid).decode() + "/" + str(i.prevout.n)
            if key in self.utxos:
                del(self.utxos[key])
                relevant = True
        txid = hash_tx(tx).hex()
        for n, out in enumerate(tx.vout):
            if self.addr == script_to_addr(out.scriptPubKey):
                key = txid + "/" + str(n)
                self.utxos[key] = out
                relevant = True
        if relevant:
            self.transactions += [tx]
                
    def balance(self):
        sum = 0
        for out in self.utxos.values():
            sum += out.amount
        return sum
        
    def txs(self):
        return self.transactions
        
def address_to_key(adr:str) -> bytes:
    hrp, data = bech32_decode(adr)
    if hrp is None:
        data = b58decode_check(adr)
        return struct.unpack_from(">Q", data, 1)[0]
    data = bytes(convertbits(data[1:], 5, 8))
    return struct.unpack_from(">Q", data, 0)[0]
    
class Session:
    def __init__(self, host: str, port: int):
        if _cl_ctx is None:
            _init_opencl()
        self.host = host
        self.port = port
        self.save_payload = None
        self.challenge = None
        self.required_complexity_2 = 58
        
    def save_payload_to(self, file: str):
        self.save_payload = file
        
    def __enter__(self):
        print(f"[*] Connecting to {self.host}:{self.port}...")
        self.s = socket.create_connection((self.host, self.port), timeout=300)
        print(f"[*] Connected to {self.host}:{self.port}")
        self.s.settimeout(300)
        # --- Handshake ---
        send_msg(self.s, CMD_VERSION, make_version_payload())
        # Read until we have exchanged version/verack both ways
        version_received = False
        while self.challenge is None or not version_received:
            cmd, payload = read_msg(self.s)
            if cmd == "version":
                # Reply with verack
                send_msg(self.s, CMD_VERACK, b"")
                version_received = True
            elif cmd == CMD_SENDCHALLENGE.decode():
                self.required_complexity_2, self.challenge = parse_sendchallenge(payload)
                print(f"[*] Got challenge: {self.challenge.hex()}")
                break
            # ignore other messages
            
        print(f"[*] Handshake complete")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.s.close()
    
    def wallet_from_address(self, addr: str) -> Wallet:
        # --- Build and send GETADDRDATA ---
        key = address_to_key(addr)
        
        from_txid = b'\0'*32
        
        wallet = Wallet(addr)
        cplx = self.required_complexity_2 // 2 + 4
        while True:
            req = build_getaddrdata_payload(key, key + 1, from_txid, self.challenge, cplx)
            send_msg(self.s, CMD_GETADDRDATA, req)
            print(f"[*] Sent GETADDRDATA (key {key}, txid={from_txid[:8].hex()}...).")

            # --- Receive SENDADDRDATA (one response message) ---
            if self.save_payload is not None:
                f = open(self.save_payload, "wb")
            
            while True:
                cmd, payload = read_msg(self.s)
                c = cmd.strip("\x00").lower()
                if c == CMD_SENDADDRDATA.decode():
                    print(f"[*] Received SENDADDRDATA: {len(payload)} bytes")
                    
                    if self.save_payload is not None:
                        f.write(payload)
                        
                    resp = unpack_addr_responce(payload)
                    
                    for tx in resp.txs:
                        wallet.add(tx.tx)
                        
                    if resp.eof or len(resp.txs) == 0:
                        break
                        
                    from_txid = hash_tx(resp.txs[-1].tx)
                    
                    break
                    
            self.challenge = sha256(b"next challenge\0" + self.challenge + req)[:8]
            cplx += 1
            
            if resp.eof:
                break

        if self.save_payload is not None:
            f.close()
            
        return wallet


def main():
    ap = argparse.ArgumentParser(description="Query addr-index over P2P: wait SENDCHALLENGE, send GETADDRDATA, receive SENDADDRDATA.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8333)
    ap.add_argument("--check-address", help="Check a single address balance or a list of comma-separated addresses.")
    ap.add_argument("--tx", help="Dump transactions in the --check-address mode.", action='store_true')
    ap.add_argument("--save-payload", help="Save the transaction response to a binary file.")
    ap.add_argument("--parse-payload", help="Parse and print the transaction response.")
    args = ap.parse_args()

    if args.parse_payload is not None:
        with open(args.parse_payload, "rb") as f:
            dump(unpack_addr_responce(f.read()))
        return
    
    with Session(args.host, args.port) as session:
        session.save_payload_to(args.save_payload)
        if args.check_address is not None:
            for address in args.check_address.split(','):
                wallet = session.wallet_from_address(address)
                if args.tx:
                    print(f"{address}\n  balance: {wallet.balance()}\n  transactions: {len(wallet.txs())}")
                    for tx in wallet.txs():
                        hash = hash_tx(tx)
                        print("    "+hexlify(hash).decode())
                        print("      In:  ", end='')
                        for i in tx.vin:
                            print(hexlify(i.prevout.txid).decode() + "/" + str(i.prevout.n), end=', ')
                        print("\n      Out: ")
                        for o in tx.vout:
                            print("        " + str(o.amount) + " -> " + script_to_addr(o.scriptPubKey))
                else:
                    print(f"{address} balance: {wallet.balance()} transactions: {len(wallet.txs())}")

if __name__ == "__main__":
    main()
