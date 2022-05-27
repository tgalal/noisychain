import base64
import os
from uuid import uuid4
from typing import List
import json
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey

class ProtocolState:
    def __init__(self, h=None, k=None, ck=None, e=None, recv_ch=None,
            send_ch=None, my_ch_key=None, their_ch_key=None,
            cipher_sending_key=None, cipher_receiving_key=None, m=None):
        self.h = h or b''
        self.k = k or b''
        self.ck = ck or b''
        self.e = e
        self.recv_ch = recv_ch or ''
        self.send_ch = send_ch or ''
        self.my_ch_key = my_ch_key
        self.their_ch_key = their_ch_key
        self.cipher_sending_key = cipher_sending_key or (b"", 0)
        self.cipher_receiving_key = cipher_receiving_key or (b"", 0)
        self.m = m or b''

class ConversationState:
    id: str | None
    protocol_name: str
    protocol_states: List[ProtocolState]

    def __init__(self, protocol_name: str, protocol_states=None, id=None):
        self.id = id
        self.protocol_name = protocol_name
        self.protocol_states = protocol_states or []
    
    def fist(self) -> ProtocolState:
        return self.protocol_states[0]

    def last(self) -> ProtocolState:
        return self.protocol_states[-1]

class StateManager:
    def __init__(self, storage_dir = None):
        self._storage_dir = storage_dir or "/tmp/state"
        if not os.path.exists(self._storage_dir):
            os.mkdir(self._storage_dir)

    def _get_conversation_file(self, conversation_id: str):
        return os.path.join(self._storage_dir, f"{conversation_id}.json")

    def store(self, conversation: ConversationState):
        if conversation.id is None:
            conversation.id = str(uuid4())
        conversation_data = {
            "protocol_name": conversation.protocol_name,
            "states": []
        };
        for state in conversation.protocol_states:
            my_ch_key = state.my_ch_key.data \
                    if state.my_ch_key else b""
            their_ch_key = state.their_ch_key.data \
                    if state.their_ch_key else b""
            e = state.e.data if state.e else b""
            conversation_data["states"].append({
                "h": base64.b64encode(state.h).decode(),
                "k": base64.b64encode(state.k).decode(),
                "ck": base64.b64encode(state.ck).decode(),
                "e": base64.b64encode(e).decode(),
                "recv_ch": state.recv_ch,
                "send_ch": state.send_ch,
                "my_ch_key": base64.b64encode(my_ch_key).decode(),
                "their_ch_key": base64.b64encode(their_ch_key).decode(),
                "m": base64.b64encode(state.m).decode(),
                "cipher_sending_key": [base64.b64encode(
                    state.cipher_sending_key[0]).decode(),
                    state.cipher_sending_key[1]],
                "cipher_receiving_key": [base64.b64encode(
                    state.cipher_receiving_key[0]).decode(),
                    state.cipher_receiving_key[1]],
            })
        write_data = json.dumps(conversation_data, indent=2)
        with open(self._get_conversation_file(conversation.id), 'w') as f:
            f.write(write_data)

    def load(self, conversation_id) -> ConversationState:
        with open(self._get_conversation_file(conversation_id), 'r') as f:
            conversation_data = json.loads(f.read())
            conversation = ConversationState(
                    id=conversation_id,
                    protocol_name=conversation_data["protocol_name"],
                    protocol_states=[]
                )
            for state in conversation_data["states"]:
                protocol_state = ProtocolState()
                protocol_state.h = base64.b64decode(state["h"].encode())
                protocol_state.k = base64.b64decode(state["k"].encode())
                protocol_state.m = base64.b64decode(state["m"].encode())
                protocol_state.recv_ch = state["recv_ch"]
                protocol_state.send_ch = state["send_ch"]
                my_ch_key = base64.b64decode(state["my_ch_key"].encode())
                their_ch_key = \
                        base64.b64decode(state["their_ch_key"].encode())
                if my_ch_key:
                    protocol_state.my_ch_key = PrivateKey(my_ch_key)
                if their_ch_key:
                    protocol_state.their_ch_key = PublicKey(their_ch_key)
                e = base64.b64decode(state["e"].encode())
                if e:
                    protocol_state.e = PrivateKey(e)
                protocol_state.ck = base64.b64decode(state["ck"].encode())
                protocol_state.cipher_sending_key = (
                    base64.b64decode(
                        state["cipher_sending_key"][0].encode()),
                    state["cipher_sending_key"][1]
                )
                protocol_state.cipher_receiving_key = (
                    base64.b64decode(
                        state["cipher_receiving_key"][0].encode()),
                    state["cipher_receiving_key"][1]
                )
                conversation.protocol_states.append(protocol_state)
            return  conversation
