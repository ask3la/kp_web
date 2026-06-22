from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "app.db"
JWT_SECRET = "lr2_demo_secret_change_me"
JWT_ALG = "HS256"
TOKEN_TTL_MINUTES = 60

AGENT_TIMEOUT_SEC = 8
KEYS_DIR = BASE_DIR / "keys"
SERVER_PRIVATE_KEY_PATH = KEYS_DIR / "server_private.asc"
SERVER_PUBLIC_KEY_PATH = KEYS_DIR / "server_public.asc"
FILES_DIR = BASE_DIR / "stored_files"
TEMP_DIR = BASE_DIR / "tmp_transfers"

# Bootstrap secret for first-time agent registration
AGENT_REGISTRATION_TOKEN = "alpha_agent_bootstrap_token"
AGENT_HEARTBEAT_TTL_SEC = 180
SMALL_FILE_THRESHOLD_BYTES = 8 * 1024 * 1024
