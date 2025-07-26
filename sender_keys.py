"""
Signal group SenderKeyRecord, SenderKeyState, SenderChainKey and SenderMessageKey logic
(Python adaptation for Discord/group bots, using protobuf for serialization).

Depends on sender_key_pb2.py (generated from sender_key.proto).
"""

import os
import collections
from typing import Optional, List, Deque

import sender_key_pb2

# --- SenderMessageKey ---

class SenderMessageKey:
    def __init__(self, iteration: int, seed: bytes):
        self.iteration = iteration
        self.seed = seed

    def to_proto(self):
        msg = sender_key_pb2.textsecure__SenderKeyStateStructure_SenderMessageKey()
        msg.iteration = self.iteration
        msg.seed = self.seed
        return msg

    @classmethod
    def from_proto(cls, proto):
        return cls(proto.iteration, proto.seed)

# --- SenderChainKey ---

class SenderChainKey:
    MESSAGE_KEY_SEED = b"\x01"
    CHAIN_KEY_SEED = b"\x02"

    def __init__(self, iteration: int, chain_key: bytes):
        self.iteration = iteration
        self.chain_key = chain_key

    def next(self) -> 'SenderChainKey':
        return SenderChainKey(
            self.iteration + 1,
            _hmac_sha256(self.chain_key, self.CHAIN_KEY_SEED)
        )

    def sender_message_key(self) -> SenderMessageKey:
        return SenderMessageKey(
            self.iteration,
            _hmac_sha256(self.chain_key, self.MESSAGE_KEY_SEED)
        )

    def to_proto(self):
        msg = sender_key_pb2.textsecure__SenderKeyStateStructure_SenderChainKey()
        msg.iteration = self.iteration
        msg.seed = self.chain_key
        return msg

    @classmethod
    def from_proto(cls, proto):
        return cls(proto.iteration, proto.seed)

# --- SenderKeyState ---

class SenderKeyState:
    def __init__(
        self,
        sender_key_id: int,
        sender_chain_key: SenderChainKey,
        sender_signing_pub: bytes,
        sender_signing_priv: Optional[bytes],
        sender_message_keys: Optional[Deque[SenderMessageKey]] = None
    ):
        self.sender_key_id = sender_key_id
        self.sender_chain_key = sender_chain_key
        self.sender_signing_pub = sender_signing_pub
        self.sender_signing_priv = sender_signing_priv or b""
        self.sender_message_keys: Deque[SenderMessageKey] = sender_message_keys or collections.deque(maxlen=2000)

    def to_proto(self):
        msg = sender_key_pb2.textsecure__SenderKeyStateStructure()
        msg.senderKeyId = self.sender_key_id
        msg.senderChainKey.CopyFrom(self.sender_chain_key.to_proto())
        msg.senderSigningKey.public = self.sender_signing_pub
        if self.sender_signing_priv:
            msg.senderSigningKey.private = self.sender_signing_priv
        for mk in self.sender_message_keys:
            msg.senderMessageKeys.append(mk.to_proto())
        return msg

    @classmethod
    def from_proto(cls, proto):
        chain_key = SenderChainKey.from_proto(proto.senderChainKey)
        pub = proto.senderSigningKey.public
        priv = proto.senderSigningKey.private if proto.senderSigningKey.HasField("private") else None
        mks = collections.deque(
            (SenderMessageKey.from_proto(mk) for mk in proto.senderMessageKeys),
            maxlen=2000
        )
        return cls(proto.senderKeyId, chain_key, pub, priv, mks)

    def add_sender_message_key(self, mk: SenderMessageKey):
        self.sender_message_keys.append(mk)

    def has_sender_message_key(self, iteration: int) -> bool:
        return any(mk.iteration == iteration for mk in self.sender_message_keys)

    def remove_sender_message_key(self, iteration: int) -> Optional[SenderMessageKey]:
        for i, mk in enumerate(self.sender_message_keys):
            if mk.iteration == iteration:
                return self.sender_message_keys.pop(i)
        return None

# --- SenderKeyRecord ---

class SenderKeyRecord:
    def __init__(self, states: Optional[Deque[SenderKeyState]] = None):
        self.states: Deque[SenderKeyState] = states or collections.deque(maxlen=5)

    @classmethod
    def new_empty(cls):
        return cls()

    @classmethod
    def deserialize(cls, buf: bytes):
        rec_proto = sender_key_pb2.textsecure__SenderKeyRecordStructure()
        rec_proto.ParseFromString(buf)
        dq = collections.deque(
            (SenderKeyState.from_proto(proto) for proto in rec_proto.senderKeyStates),
            maxlen=5
        )
        return cls(dq)

    def is_empty(self) -> bool:
        return not self.states

    def add_sender_key_state(self, state: SenderKeyState):
        self.states.appendleft(state)
        while len(self.states) > 5:
            self.states.pop()

    def set_sender_key_state(self, state: SenderKeyState):
        self.states.clear()
        self.add_sender_key_state(state)

    def sender_key_state_for_keyid(self, keyid: int) -> Optional[SenderKeyState]:
        for state in self.states:
            if state.sender_key_id == keyid:
                return state
        return None

    def serialize(self) -> bytes:
        rec_proto = sender_key_pb2.textsecure__SenderKeyRecordStructure()
        for s in self.states:
            rec_proto.senderKeyStates.append(s.to_proto())
        return rec_proto.SerializeToString()

# --- HMAC utility (SHA-256, for chain key/message key derivation) ---

import hmac
import hashlib

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
