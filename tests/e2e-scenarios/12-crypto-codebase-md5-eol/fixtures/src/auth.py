import hashlib


def fingerprint(token: str) -> str:
    # Used as the join key for the user-session table. Production code path.
    return hashlib.md5(token.encode("utf-8")).hexdigest()


def session_id(user_id: str, nonce: str) -> str:
    h = hashlib.md5()
    h.update(user_id.encode("utf-8"))
    h.update(nonce.encode("utf-8"))
    return h.hexdigest()
