from __future__ import annotations
from dissononce.extras.dh.experimental.secp256k1.private import PrivateKey
from dissononce.extras.dh.experimental.secp256k1.public import PublicKey
from typing import List
import base64


class ProtocolState:
    def __init__(
            self, h=None, k=None, ck=None, e=None, recv_ch=None,
            send_ch=None, my_ch_key=None, their_ch_key=None,
            cipher_sending_key=None, cipher_receiving_key=None, m=None,
            their_public=None, state_type: int=0
            ):
        self.h = h or b''
        self.k = k or b''
        self.ck = ck or b''
        self.e = e
        self.recv_ch = recv_ch
        self.send_ch = send_ch or ''
        self.my_ch_key = my_ch_key
        self.their_ch_key = their_ch_key
        self.cipher_sending_key = cipher_sending_key or (b"", 0)
        self.cipher_receiving_key = cipher_receiving_key or (b"", 0)
        self.m = m or b''
        self.their_public = their_public
        self.state_type = state_type

    @classmethod
    def parse(cls, data: dict) -> ProtocolState:
        protocol_state = ProtocolState()
        protocol_state.h = base64.b64decode(data["h"].encode())
        protocol_state.k = base64.b64decode(data["k"].encode())
        protocol_state.m = base64.b64decode(data["m"].encode())
        my_ch_key = base64.b64decode(data["my_ch_key"].encode())
        their_ch_key = base64.b64decode(data["their_ch_key"].encode())
        their_public = base64.b64decode(data["their_public"].encode())
        e = base64.b64decode(data["e"].encode())
        recv_ch = (base64.b64decode(data["recv_ch"][0].encode()), data["recv_ch"][1])

        if my_ch_key:
            protocol_state.my_ch_key = PrivateKey(my_ch_key)
        if their_ch_key:
            protocol_state.their_ch_key = PublicKey(their_ch_key)
        if e:
            protocol_state.e = PrivateKey(e)
        if their_public:
            protocol_state.their_public = PublicKey(their_public)

        if recv_ch[0] and recv_ch[1]:
            protocol_state.recv_ch = (PrivateKey(recv_ch[0]), recv_ch[1])

        protocol_state.ck = base64.b64decode(data["ck"].encode())

        protocol_state.cipher_sending_key = (
            base64.b64decode(
                data["cipher_sending_key"][0].encode()),
            data["cipher_sending_key"][1]
        )
        protocol_state.cipher_receiving_key = (
            base64.b64decode(
                data["cipher_receiving_key"][0].encode()),
            data["cipher_receiving_key"][1]
        )
        protocol_state.state_type = data["state_type"]
        protocol_state.send_ch = data["send_ch"]
        return protocol_state
    
    def to_dict(self):
        return self.__dict__()

    def __dict__(self):
        my_ch_key = self.my_ch_key.data if self.my_ch_key else b""
        their_ch_key = self.their_ch_key.data if self.their_ch_key else b""
        e = self.e.data if self.e else b""
        their_public = self.their_public.data if self.their_public else b""

        if self.recv_ch:
            recv_ch = (self.recv_ch[0].data, self.recv_ch[1])
        else:
            recv_ch = (b'', None)

        return {
            "state_type": self.state_type,
            "h": base64.b64encode(self.h).decode(),
            "k": base64.b64encode(self.k).decode(),
            "ck": base64.b64encode(self.ck).decode(),
            "e": base64.b64encode(e).decode(),
            "recv_ch": [base64.b64encode(recv_ch[0]).decode(), recv_ch[1]],
            "send_ch": self.send_ch,
            "my_ch_key": base64.b64encode(my_ch_key).decode(),
            "their_ch_key": base64.b64encode(their_ch_key).decode(),
            "m": base64.b64encode(self.m).decode(),
            "cipher_sending_key": [base64.b64encode(
                self.cipher_sending_key[0]).decode(),
                self.cipher_sending_key[1]],
            "cipher_receiving_key": [base64.b64encode(
                self.cipher_receiving_key[0]).decode(),
                self.cipher_receiving_key[1]],
            "their_public": base64.b64encode(their_public).decode()
        }

class ProtocolSession:
    id: str | None
    protocol_name: str
    protocol_states: List[ProtocolState]

    def __init__(self, protocol_name: str, protocol_states=None, id=None):
        self.id = id
        self.protocol_name = protocol_name
        self.protocol_states = protocol_states or []
 
    def fist(self) -> ProtocolState | None:
        return self.protocol_states[0] if len(self.protocol_states) else None

    def last(self) -> ProtocolState | None:
        return self.protocol_states[-1] if len(self.protocol_states) else None

    def __len__(self):
        return len(self.protocol_states)
    
    def new_state(self, **kwargs):
        if not len(self):
            return ProtocolState(**kwargs)
        else:
            last_state = self[-1]
            data = last_state.to_dict()
            data.update(**kwargs)
            pstate = ProtocolState.parse(data)
            # self.append(pstate)
            return pstate

    def append(self, state):
        return self.put(state)

    def put(self, state: ProtocolState):
        if state.state_type == 0:
            self.protocol_states.append(state)
        elif state.state_type == 1:
            last = self[-1]
            if last.state_type == 1:
                self.protocol_states.pop()
            self.protocol_states.append(state)

    def __getitem__(self, index):
        return self.protocol_states[index]
