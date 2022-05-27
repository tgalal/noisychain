from .session import ProtocolSession
import os


class SessionStore:
    def store(self, session: ProtocolSession):
        pass
 
    def load(self, session_id: str) -> ProtocolSession | None:
        pass

class InMemorySessionStore(SessionStore):
    def __init__(self):
        self._store = {}

    def store(self, session: ProtocolSession):
        self._store[session.id] = session
 
    def load(self, session_id: str) -> ProtocolSession | None:
        if session_id in self._store:
            return self._store[session_id]

class DirSessionStore(SessionStore):
    def __init__(self, storage_dir):
        self._storage_dir = storage_dir
        if not os.path.exists(self._storage_dir):
            os.mkdir(self._storage_dir)

    def _get_session_file(self, session_id: str) -> str:
        return os.path.join(self._storage_dir,
                f"{session_id}.json")

