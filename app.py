import hashlib
import io
import os
import secrets
import time
import requests
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
import psycopg
import streamlit as st
from deep_translator import GoogleTranslator, MyMemoryTranslator
from psycopg_pool import ConnectionPool
from pypdf import PdfReader
from pptx import Presentation
from PIL import Image

if "username" not in st.session_state:
    st.session_state.username = None
if "user_role" not in st.session_state:
    st.session_state.user_role = None


try:
    import pytesseract
    _TESSERACT_IMPORTED = True
except ImportError:
    _TESSERACT_IMPORTED = False

try:
    import speech_recognition as sr
    _SPEECH_RECOGNITION_IMPORTED = True
except ImportError:
    _SPEECH_RECOGNITION_IMPORTED = False

try:
    from gtts import gTTS
    _GTTS_IMPORTED = True
except ImportError:
    _GTTS_IMPORTED = False

# --- 1. DATABASE SETUP & HELPERS (PostgreSQL) ---
#
# Requires the DATABASE_URL environment variable, e.g.:
#   export DATABASE_URL="postgresql://user:password@host/dbname?sslmode=require"
# Install with: pip install "psycopg[binary,pool]"

DATABASE_URL = os.environ.get("DATABASE_URL")
REMEMBER_TOKEN_DAYS = 30
RESET_CODE_TTL_MINUTES = 30


def _resolve_database_url():

    url = os.environ.get("DATABASE_URL")
    if not url:
        try:
            url = st.secrets["DATABASE_URL"]
        except (FileNotFoundError, KeyError):
            url = None
    return url


@st.cache_resource
def get_pool():
    url = _resolve_database_url()
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Export it, add it to .streamlit/secrets.toml, "
            "or paste it into the app's Secrets in Streamlit Community Cloud."
        )
    return ConnectionPool(conninfo=url, min_size=1, max_size=5, open=True)



@contextmanager
def db_cursor():
    """One pooled connection per call: commits on success, rolls back on error."""
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            yield cur


def init_db():
    with db_cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS translations (
                id               BIGSERIAL PRIMARY KEY,
                user_role        TEXT NOT NULL,
                field            TEXT NOT NULL,
                source_text      TEXT NOT NULL,
                translated_text  TEXT NOT NULL,
                target_language  TEXT NOT NULL,
                timestamp        TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            BIGSERIAL PRIMARY KEY,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS remember_tokens (
                id         BIGSERIAL PRIMARY KEY,
                user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS reset_tokens (
                id         BIGSERIAL PRIMARY KEY,
                user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash  TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                used_at    TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS app_ratings (
                id         BIGSERIAL PRIMARY KEY,
                rating     INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
                comment    TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS active_class_link (
                id         SMALLINT PRIMARY KEY CHECK (id = 1),
                url        TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )


def save_to_db(user_role, field, source_text, translated_text, target_language):
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO translations
                (user_role, field, source_text, translated_text, target_language)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_role, field, source_text, translated_text, target_language),
        )


def get_all_records():
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT id, user_role, field, source_text, translated_text,
                   target_language,
                   to_char(timestamp, 'YYYY-MM-DD HH24:MI') AS timestamp
            FROM translations
            ORDER BY id DESC
            """
        )
        return cur.fetchall()


def delete_record(record_id):
    with db_cursor() as cur:
        cur.execute("DELETE FROM translations WHERE id = %s", (record_id,))


# --- AUTH: PASSWORD, REMEMBER-ME & RESET HELPERS ---

def _normalize_username(username):
    return username.strip().lower()


def _hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
    )
    return f"{salt}${digest.hex()}"


def _verify_password(password, stored):
    try:
        salt, _ = stored.split("$", 1)
    except (AttributeError, ValueError):
        return False
    return secrets.compare_digest(_hash_password(password, salt), stored)


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def create_user(username, password):
    username = _normalize_username(username)
    try:
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, _hash_password(password)),
            )
        return True, None
    except psycopg.errors.UniqueViolation:
        return False, "That username is already taken."


def get_user_by_username(username):
    """Returns (id, username, password_hash) or None."""
    with db_cursor() as cur:
        cur.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s",
            (_normalize_username(username),),
        )
        return cur.fetchone()


def issue_remember_token(user_id):
    raw_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REMEMBER_TOKEN_DAYS)
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO remember_tokens (user_id, token_hash, expires_at) "
            "VALUES (%s, %s, %s)",
            (user_id, _sha256(raw_token), expires_at),
        )
    return raw_token


def forget_remember_token(raw_token):
    if not raw_token:
        return
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM remember_tokens WHERE token_hash = %s", (_sha256(raw_token),)
        )


def user_for_remember_token(raw_token):
    if not raw_token:
        return None
    digest = _sha256(raw_token)
    with db_cursor() as cur:
        cur.execute(
            """
            SELECT u.username, rt.expires_at
            FROM remember_tokens rt
            JOIN users u ON u.id = rt.user_id
            WHERE rt.token_hash = %s
            """,
            (digest,),
        )
        row = cur.fetchone()
    if not row:
        return None
    username, expires_at = row
    if datetime.now(timezone.utc) > expires_at:
        forget_remember_token(raw_token)
        return None
    return username

def issue_reset_code(username):
    """Create a one-time reset code. Returns (code, error)."""
    username = _normalize_username(username)

    with db_cursor() as cur:
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if not row:
            return None, "No such user."
        code = "".join(secrets.choice("23456789ABCDEFGHJKMNPQRSTUVWXYZ") for _ in range(8))
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=RESET_CODE_TTL_MINUTES)
        cur.execute(
            "INSERT INTO reset_tokens (user_id, code_hash, expires_at) VALUES (%s, %s, %s)",
            (row[0], _sha256(code), expires_at),
        )
    return code, None

def reset_password_with_code(username, code, new_password):
    """Redeem an admin-issued one-time reset code. Returns (ok, message)."""
    if len(new_password) < 4:
        return False, "New password must be at least 4 characters."

    user = get_user_by_username(username)
    if not user:
        return False, "Invalid code."
    user_id = user[0]
    code_hash = _sha256(code.strip())

    with db_cursor() as cur:
        cur.execute(
            """
            SELECT id, expires_at FROM reset_tokens
            WHERE user_id = %s AND code_hash = %s AND used_at IS NULL
            ORDER BY id DESC LIMIT 1
            FOR UPDATE
            """,
            (user_id, code_hash),
        )
        row = cur.fetchone()
        if not row:
            return False, "Invalid code."

        token_id, expires_at = row
        if datetime.now(timezone.utc) > expires_at:
            return False, "That code has expired - ask your teacher for a new one."

        cur.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (_hash_password(new_password), user_id),
        )
        cur.execute("UPDATE reset_tokens SET used_at = NOW() WHERE id = %s", (token_id,))
        cur.execute("DELETE FROM remember_tokens WHERE user_id = %s", (user_id,))

    return True, "Password updated - you can log in now."


# --- APP RATINGS ---

def add_rating(rating, comment=""):
    rating = int(rating)
    if not 1 <= rating <= 5:
        raise ValueError("Rating must be from 1 to 5.")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO app_ratings (rating, comment) VALUES (%s, %s)",
            (rating, comment.strip()[:500] or None),
        )


def get_rating_summary():
    with db_cursor() as cur:
        cur.execute("SELECT AVG(rating), COUNT(*) FROM app_ratings")
        average, count = cur.fetchone()
        return (float(average or 0.0), count)


# --- SHARED LIVE CLASS LINK ---

def save_class_link(url):
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Enter a complete link starting with https://")
    with db_cursor() as cur:
        cur.execute(
            """
            INSERT INTO active_class_link (id, url)
            VALUES (1, %s)
            ON CONFLICT (id) DO UPDATE
            SET url = EXCLUDED.url, updated_at = NOW()
            """,
            (url,),
        )


def get_class_link():
    with db_cursor() as cur:
        cur.execute("SELECT url FROM active_class_link WHERE id = 1")
        row = cur.fetchone()
        return row[0] if row else None


def clear_class_link():
    with db_cursor() as cur:
        cur.execute("DELETE FROM active_class_link WHERE id = 1")


# --- FILE TEXT EXTRACTION HELPERS ---

def extract_text_from_pdf(file_bytes):
    """Pull all readable text out of a PDF, page by page. Returns None on failure."""
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        pages_text = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            if page_text.strip():
                pages_text.append(page_text.strip())
        return "\n\n".join(pages_text).strip() or None
    except Exception:
        return None


def extract_text_from_pptx(file_bytes):
    """Pull all text boxes/bullets out of a PowerPoint deck, slide by slide. Returns None on failure."""
    try:
        prs = Presentation(io.BytesIO(file_bytes))
        slides_text = []
        for i, slide in enumerate(prs.slides, start=1):
            lines = []
            for shape in slide.shapes:
                if getattr(shape, "has_text_frame", False):
                    for paragraph in shape.text_frame.paragraphs:
                        line = "".join(run.text for run in paragraph.runs).strip()
                        if line:
                            lines.append(line)
            if lines:
                slides_text.append(f"Slide {i}:\n" + "\n".join(lines))
        return "\n\n".join(slides_text).strip() or None
    except Exception:
        return None


def extract_text_from_image(file_bytes):
    """
    OCR an image (e.g. a photo of handwritten/printed notes) using
    Tesseract via pytesseract. Returns None if OCR isn't available on
    this machine rather than raising, so the caller can show a helpful
    message instead of crashing.
    """
    if not _TESSERACT_IMPORTED:
        return None
    try:
        image = Image.open(io.BytesIO(file_bytes))
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception:
        return None


# Language Code Mapper for Google Translate
LANG_CODES = {
    "isiZulu": "zu",
    "isiXhosa": "xh",
    "Afrikaans": "af",
    "English": "en",
    "Setswana": "tn",
    "Sesotho": "st",
}

# MyMemory uses full locale-style codes. All currently supported languages
# have a MyMemory fallback in case Google Translate is unavailable.
MYMEMORY_CODES = {
    "isiZulu": "zu-ZA",
    "isiXhosa": "xh-ZA",
    "Afrikaans": "af-ZA",
    "English": "en-GB",
    "Setswana": "tn-BW",
    "Sesotho": "st-ST",
}


def _looks_like_error_page(text):
    """Detect an HTML/server error page returned as if it were a translation."""
    if not text:
        return True
    lowered = text.lower()
    return "<html" in lowered or "server error" in lowered or "error 500" in lowered


def _looks_untranslated(original, translated, target_lang_name):
    """
    Detect a translation call that silently echoed the input back instead
    of translating it - a known failure mode of free translation
    endpoints when text is too long or the service is having trouble.
    Not a perfect check (e.g. a single shared proper noun could match),
    but effective for whole-block comparisons.
    """
    if target_lang_name == "English":
        return False  # translating into English can legitimately be a no-op
    return translated.strip().lower() == original.strip().lower()


def _split_into_chunks(text, max_len):
    """
    Split text into pieces no longer than max_len, preferring to break on
    line boundaries so slide/paragraph structure survives. Falls back to
    hard character splitting for any single line longer than max_len.
    """
    chunks = []
    current_lines = []
    current_len = 0

    def flush():
        if current_lines:
            chunks.append("\n".join(current_lines))

    for line in text.split("\n"):
        if len(line) > max_len:
            flush()
            current_lines.clear()
            current_len = 0
            for i in range(0, len(line), max_len):
                chunks.append(line[i : i + max_len])
            continue

        added_len = len(line) + 1
        if current_len + added_len > max_len and current_lines:
            flush()
            current_lines = [line]
            current_len = added_len
        else:
            current_lines.append(line)
            current_len += added_len

    flush()
    return [c for c in chunks if c.strip()]


# Conservative request-size limits for each free backend.
GOOGLE_CHUNK_LIMIT = 4500
MYMEMORY_CHUNK_LIMIT = 480


# --- SPEECH-TO-TEXT & TEXT-TO-SPEECH HELPERS ---

# Locale codes for Google's free Web Speech recognition backend.
STT_LANG_CODES = {
    "isiZulu": "zu-ZA",
    "isiXhosa": "xh-ZA",
    "Afrikaans": "af-ZA",
    "English": "en-ZA",
    "Setswana": "tn-ZA",
    "Sesotho": "st-ZA",
}
SPOKEN_LANGUAGE_OPTIONS = list(STT_LANG_CODES.keys())

# gTTS (Google Text-to-Speech) only reliably supports a small subset of
# South Africa's official languages today. Languages not listed here have
# no audio playback option yet.
TTS_LANG_CODES = {
    "Afrikaans": "af",
    "English": "en",
}


def speech_to_text(audio_bytes, spoken_language):
    """
    Transcribe recorded audio (WAV bytes, e.g. from st.audio_input) to text
    using SpeechRecognition's free Google Web Speech API backend. Returns a
    (text, error_message) tuple - exactly one of which is None/empty.
    """
    if not _SPEECH_RECOGNITION_IMPORTED:
        return None, (
            "Speech-to-text needs the `SpeechRecognition` Python package. "
            "Install it with `pip install SpeechRecognition` and restart the app."
        )

    locale_code = STT_LANG_CODES.get(spoken_language, "en-ZA")
    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(io.BytesIO(audio_bytes)) as source:
            audio_data = recognizer.record(source)
        text = recognizer.recognize_google(audio_data, language=locale_code)
        return text.strip(), None
    except sr.UnknownValueError:
        return None, "Couldn't make out any speech in that recording. Please try again, speaking clearly."
    except sr.RequestError as e:
        return None, f"Speech recognition service is unavailable right now ({e}). Please try again shortly."
    except Exception as e:
        return None, f"Couldn't transcribe that recording ({e}). Please try again or type the text manually."


def text_to_speech(text, spoken_language):
    """
    Convert text to spoken audio (MP3 bytes) using gTTS. Returns an
    (audio_bytes, error_message) tuple - exactly one of which is None.
    """
    if not text or not text.strip():
        return None, "There's no text to read aloud yet."
    if not _GTTS_IMPORTED:
        return None, (
            "Text-to-speech needs the `gTTS` Python package. Install it "
            "with `pip install gTTS` and restart the app."
        )

    tts_code = TTS_LANG_CODES.get(spoken_language)
    if tts_code is None:
        return None, (
            f"Audio playback isn't available yet for {spoken_language}. "
            "This currently works for English and Afrikaans; support for "
            "other languages may be added as compatible free speech "
            "services become available."
        )

    try:
        buffer = io.BytesIO()
        gTTS(text=text, lang=tts_code).write_to_fp(buffer)
        return buffer.getvalue(), None
    except Exception as e:
        return None, f"Couldn't generate audio right now ({e}). Please try again shortly."


def read_aloud_button(text, spoken_language, label, key):
    if st.button(label, key=key):
        if not text or not text.strip():
            st.info("There's no text to read aloud yet.")
            return

        with st.spinner("Generating audio..."):
            audio_bytes, error = text_to_speech(text, spoken_language)

        if audio_bytes:
            st.audio(audio_bytes, format="audio/mp3")
        else:
            st.info(error)


def _translate_with_google(text, code):
    translated = GoogleTranslator(source="auto", target=code).translate(text)
    if not translated or _looks_like_error_page(translated):
        raise ValueError("Google Translate returned an unexpected response.")
    return translated


def _translate_with_mymemory(text, mymemory_code):
    translated = MyMemoryTranslator(
        source=MYMEMORY_CODES["English"], target=mymemory_code
    ).translate(text)
    if not translated or _looks_like_error_page(translated):
        raise ValueError("MyMemory returned an unexpected response.")
    return translated

def _resolve_secret(name):
    value = os.environ.get(name)
    if not value:
        try:
            value = st.secrets[name]
        except (FileNotFoundError, KeyError):
            value = None
    return value


GEMINI_KEY = _resolve_secret("GEMINI_API_KEY")


def _translate_with_gemini(text, target_lang_name):
    resp = requests.post(
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.5-flash-lite:generateContent",
        headers={"x-goog-api-key": GEMINI_KEY, "Content-Type": "application/json"},
        json={
            "contents": [{"parts": [{"text":
                f"Translate the following text to {target_lang_name}. "
                "Reply with ONLY the translation, nothing else:\n\n" + text
            }]}],
            "generationConfig": {"temperature": 0.1},
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()



def perform_translation(text, target_lang_name):
    code = LANG_CODES.get(target_lang_name, "en")
    mymemory_code = MYMEMORY_CODES.get(target_lang_name)

    # Long text (e.g. extracted from a multi-slide deck or PDF) can exceed
    # what the free translation endpoints accept in one request. Chunk it
    # so each request stays under the relevant limit.
   
google_chunks = _split_into_chunks(text, GOOGLE_CHUNK_LIMIT)
if GEMINI_KEY:
        try:
            results = []
            for i, chunk in enumerate(google_chunks):
                if i > 0:
                    time.sleep(5)  # stay under the free-tier rate limit
                results.append(_translate_with_gemini(chunk, target_lang_name))
            return "\n".join(results)
        except Exception:
            pass  # fall back to Google, then MyMemory



translated_chunks = []
google_error = None
google_failed = False

for chunk in google_chunks:
        try:
            result = _translate_with_google(chunk, code)
            if _looks_untranslated(chunk, result, target_lang_name):
                raise ValueError(
                    "Google Translate returned the text unchanged - likely "
                    "blocked, rate-limited, or the request was too large."
                )
 translated_chunks.append(result)
        except Exception as e:
            google_error = str(e)
            google_failed = True
            break

if not google_failed:
        return "\n".join(translated_chunks)
if mymemory_code is None:
        return (
            f"Translation error: Google Translate is currently unavailable "
            f"({google_error}), and there is no fallback translator for "
            f"{target_lang_name} yet. Please try again in a moment, or "
            "translate a shorter excerpt."
        )

    # Retry from scratch with MyMemory, chunked to its much smaller limit.
    mymemory_chunks = _split_into_chunks(text, MYMEMORY_CHUNK_LIMIT)
    translated_chunks = []
    mymemory_error = None

for chunk in mymemory_chunks:
        try:
            result = _translate_with_mymemory(chunk, mymemory_code)
            if _looks_untranslated(chunk, result, target_lang_name):
                raise ValueError("MyMemory returned the text unchanged.")
            translated_chunks.append(result)
        except Exception as e:
            mymemory_error = str(e)
            translated_chunks = None
            break

if translated_chunks is not None:
        return "\n".join(translated_chunks)

    return (
        "Translation error: both translation services are currently "
        f"unavailable (Google: {google_error} | MyMemory: {mymemory_error}). "
        "This can happen with very long text or a slow/blocked connection - "
        "try a shorter excerpt, or check your internet connection and try again."
    )


# --- 2. PAGE CONFIGURATION, THEME & STARTUP ---

st.set_page_config(page_title="STEAM APP", page_icon="🛡️", layout="wide")

@st.cache_resource
def _startup():
    init_db()
    return True


try:
    _startup()
except Exception as e:
    st.error(f"Could not reach the database: {e}")
    st.info("Set the DATABASE_URL environment variable and restart the app.")
    st.stop()


LOGO_SVG = """
<svg xmlns="http://www.w3.org/2000/svg"
     width="52" height="56" viewBox="0 0 52 56"
     role="img" aria-label="STEAM APP five-node network logo">
  <circle cx="26" cy="28" r="22.8" fill="#151515" stroke="#D4AF37" stroke-width="1.4"/>
  <g fill="none" stroke="#D4AF37" stroke-width="1.3" stroke-linecap="round" opacity="0.85">
    <path d="M26 13.1 41.68 24.5 35.71 42.95 16.29 42.95 10.32 24.5Z"/>
    <path d="M26 29.6 26 13.1 M26 29.6 41.68 24.5 M26 29.6 35.71 42.95 M26 29.6 16.29 42.95 M26 29.6 10.32 24.5"/>
  </g>
  <g fill="#D4AF37" stroke="#0A0A0A" stroke-width="1.2">
    <circle cx="26" cy="13.1" r="3.5"/>
    <circle cx="41.68" cy="24.5" r="3.5"/>
    <circle cx="35.71" cy="42.95" r="3.5"/>
    <circle cx="16.29" cy="42.95" r="3.5"/>
    <circle cx="10.32" cy="24.5" r="3.5"/>
  </g>
  <circle cx="26" cy="29.6" r="4.2" fill="#0A0A0A" stroke="#F5F5F5" stroke-width="1.3"/>
  <circle cx="26" cy="29.6" r="1.6" fill="#D4AF37"/>
</svg>
"""


st.markdown("""
<style>
/* =========================================================
    STEAM APP — base theme
   ========================================================= */
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
    background: #0A0A0A !important;
    color: #F5F5F5 !important;
}
[data-testid="stHeader"] { background: transparent !important; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp p, .stApp li, .stApp span { color: #F5F5F5; }
.stApp a { color: #D4AF37 !important; }
.stApp a:hover { color: #F0D878 !important; }

[data-testid="stButton"] button, [data-testid="stFormSubmitButton"] button {
    background: #D4AF37 !important;
    color: #111 !important;
    border: 1px solid #D4AF37 !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
}
[data-testid="stButton"] button:hover, [data-testid="stFormSubmitButton"] button:hover {
    background: #F0D878 !important;
    border-color: #F0D878 !important;
    color: #111 !important;
}

/* STEAM dashboard cards */
.steam-card {
    background: #151515 !important;
    color: #F5F5F5 !important;
    border: 1px solid #3B321E !important;
    border-top: 3px solid #D4AF37 !important;
    border-radius: 10px !important;
    box-shadow: 0 4px 14px rgba(0, 0, 0, .22);
}
.module-kicker {
    color: #D4AF37 !important;
    font-size: .72rem;
    font-weight: 700;
    letter-spacing: .22em;
    margin-bottom: 2px;
}

[data-testid="stCodeBlock"] {
    background: #151515 !important;
    border: 1px solid #514321 !important;
    border-left: 3px solid #D4AF37 !important;
    border-radius: 8px !important;
}
[data-testid="stCodeBlock"] pre, .stApp pre { color: #F5F5F5 !important; }
/* st.code — current Streamlit test id is stCode (was stCodeBlock) */
[data-testid="stCode"] {
    background: #151515 !important;
    border: 1px solid #514321 !important;
    border-left: 3px solid #D4AF37 !important;
    border-radius: 8px !important;
}
[data-testid="stCode"] pre, [data-testid="stCode"] pre code {
    background: #151515 !important;
    color: #F5F5F5 !important;
}
[data-testid="stCode"] pre code span {
    color: #E8D48B !important;
}

[data-testid="stExpander"] .stButton > button {
    background: transparent !important;
    color: #D4AF37 !important;
    border: 1px solid #D4AF37 !important;
}
[data-testid="stExpander"] .stButton > button:hover {
    background: #D4AF37 !important;
    color: #111 !important;
}

/* Alerts */
[data-testid="stAlert"], [data-testid="stAlert"] div[data-baseweb="notification"] {
    background: #151515 !important;
    color: #F5F5F5 !important;
    border: 1px solid #514321 !important;
    border-left: 4px solid #D4AF37 !important;
    border-radius: 8px !important;
}
[data-testid="stAlert"] div[data-baseweb="notification"] * { color: #F5F5F5 !important; }
[data-testid="stAlert"] svg, [data-testid="stAlert"] svg * {
    color: #D4AF37 !important;
    fill: #D4AF37 !important;
    stroke: #D4AF37 !important;
}

/* Sidebar */
[data-testid="stSidebar"], section.stSidebar {
    background: #111 !important;
    border-right: 1px solid #514321 !important;
}
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { color: #F5F5F5 !important; }
[data-testid="stSidebar"] label, [data-testid="stSidebar"] [data-testid="stWidgetLabel"] { color: #D4AF37 !important; }
[data-testid="stSidebar"] [data-baseweb="select"] > div, section.stSidebar [data-baseweb="select"] > div {
    background: #151515 !important;
    border-color: #514321 !important;
    color: #F5F5F5 !important;
}
[data-testid="stSidebar"] [data-baseweb="select"] *, section.stSidebar [data-baseweb="select"] * { color: #F5F5F5 !important; }
[data-baseweb="popover"], [role="listbox"] { background: #151515 !important; border: 1px solid #514321 !important; }
[role="option"] { background: #151515 !important; color: #F5F5F5 !important; }
[role="option"]:hover, [role="option"][aria-selected="true"] { background: #302817 !important; color: #F0D878 !important; }
[data-testid="stSidebar"] [data-testid="stRadio"] label, section.stSidebar [data-testid="stRadio"] label {
    color: #F5F5F5 !important;
    border-radius: 7px;
    padding: 4px 8px;
}
[data-testid="stSidebar"] [data-testid="stRadio"] label:hover, section.stSidebar [data-testid="stRadio"] label:hover { background: #1D1A13 !important; }
[data-testid="stSidebar"] [role="radio"][aria-checked="true"], [data-testid="stSidebar"] [role="radio"][aria-checked="true"] *,
section.stSidebar [role="radio"][aria-checked="true"] { color: #D4AF37 !important; }
[data-testid="stSidebar"] [role="radio"][aria-checked="true"] svg, section.stSidebar [role="radio"][aria-checked="true"] svg { fill: #D4AF37 !important; }
[data-testid="stSidebar"] hr, section.stSidebar hr { border-color: #514321 !important; }
[data-testid="stSidebar"] [data-testid="stButton"] button {
    background: transparent !important;
    color: #D4AF37 !important;
    border: 1px solid #D4AF37 !important;
    border-radius: 8px !important;
    font-weight: 700 !important;
}
[data-testid="stSidebar"] [data-testid="stButton"] button:hover {
    background: #D4AF37 !important;
    color: #111 !important;
    border-color: #F0D878 !important;
}
[data-testid="stSidebar"] [data-testid="stAlert"] {
    background: linear-gradient(135deg, #1c1911, #151515) !important;
    border: 1px solid #514321 !important;
    border-left: 4px solid #D4AF37 !important;
    border-radius: 12px !important;
    box-shadow: 0 6px 20px rgba(212, 175, 55, .08) !important;
}
[data-testid="stSidebar"] [data-testid="stAlert"] div[data-baseweb="notification"] {
    background: transparent !important;
    border: 0 !important;
    color: #F5F5F5 !important;
}
[data-testid="stSidebar"] [data-testid="stAlert"] strong { color: #D4AF37 !important; }
[data-testid="stSidebar"] [data-testid="stAlert"] svg, [data-testid="stSidebar"] [data-testid="stAlert"] svg * {
    color: #D4AF37 !important;
    fill: #D4AF37 !important;
}

/* File uploader */
[data-testid="stFileUploader"] { color: #F5F5F5 !important; }
[data-testid="stFileUploader"] [data-testid="stWidgetLabel"], [data-testid="stFileUploader"] label { color: #D4AF37 !important; }
[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzone"], [data-testid="stFileUploader"] section {
    background: #171717 !important;
    border: 1px dashed #514321 !important;
    border-radius: 12px !important;
}
[data-testid="stFileUploader"] [data-testid="stFileUploaderDropzone"]:hover,
[data-testid="stFileUploader"] section:hover { border-color: #D4AF37 !important; background: #1c1911 !important; }
[data-testid="stFileUploader"] button {
    background: #D4AF37 !important;
    color: #111 !important;
    border: 1px solid #D4AF37 !important;
    border-radius: 7px !important;
    font-weight: 700 !important;
}
[data-testid="stFileUploader"] button:hover { background: #F0D878 !important; border-color: #F0D878 !important; }
[data-testid="stFileUploaderFile"] {
    background: #151515 !important;
    color: #F5F5F5 !important;
    border: 1px solid #514321 !important;
    border-left: 3px solid #D4AF37 !important;
    border-radius: 7px !important;
}

/* Microphone + audio playback */
[data-testid="stAudioInput"] {
    background: #151515 !important;
    color: #F5F5F5 !important;
    border: 1px solid #514321 !important;
    border-radius: 10px !important;
    padding: 8px !important;
}
[data-testid="stAudioInput"] button {
    background: #D4AF37 !important;
    color: #111 !important;
    border: 1px solid #D4AF37 !important;
    border-radius: 50% !important;
}
[data-testid="stAudioInput"] button:hover { background: #F0D878 !important; }
[data-testid="stAudio"] { background: #151515 !important; border: 1px solid #514321 !important; border-radius: 10px !important; padding: 6px !important; }
audio { display: block; width: 100%; background: #151515; border-radius: 8px; color-scheme: dark; }
audio::-webkit-media-controls-panel { background-color: #151515; }

/* Image preview + video player */
[data-testid="stImage"] {
    background: #151515 !important;
    border: 1px solid #514321 !important;
    border-radius: 12px !important;
    padding: 10px !important;
    box-shadow: 0 6px 20px rgba(212, 175, 55, 0.08) !important;
}
[data-testid="stImage"] img { border-radius: 8px !important; }
[data-testid="stImage"] figcaption, [data-testid="stImage"] [data-testid="stCaptionContainer"], [data-testid="stImage"] p {
    color: #B9A45E !important;
    font-size: 0.78rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
}
[data-testid="stVideo"] {
    background: #151515 !important;
    border: 1px solid #514321 !important;
    border-radius: 12px !important;
    padding: 10px !important;
    box-shadow: 0 6px 20px rgba(212, 175, 55, 0.08) !important;
}
[data-testid="stVideo"] video { display: block; width: 100%; border-radius: 8px !important; color-scheme: dark; }

/* Login, signup, forgot-password */
[data-testid="stForm"] {
    background: #151515 !important;
    border: 1px solid #514321 !important;
    border-radius: 10px !important;
    padding: 1rem !important;
}
[data-testid="stTabs"] [data-baseweb="tab-list"] { background: #111 !important; border-bottom: 1px solid #514321 !important; gap: .35rem; }
[data-testid="stTabs"] button[role="tab"] { background: transparent !important; color: #B9B9B9 !important; }
[data-testid="stTabs"] button[role="tab"][aria-selected="true"] { color: #D4AF37 !important; border-bottom: 2px solid #D4AF37 !important; }
[data-testid="stForm"] [data-testid="stWidgetLabel"], [data-testid="stExpander"] [data-testid="stWidgetLabel"] { color: #D4AF37 !important; }
[data-baseweb="input"] > div, [data-baseweb="textarea"] > div { background: #111 !important; border-color: #514321 !important; }
 [data-baseweb="input"] input, [data-baseweb="textarea"] textarea {
    background: #111 !important;
    color: #F5F5F5 !important;
    -webkit-text-fill-color: #F5F5F5 !important;
    caret-color: #F5F5F5 !important;
}
input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus, input:-webkit-autofill:active {
    -webkit-text-fill-color: #F5F5F5 !important;
    -webkit-box-shadow: 0 0 0 1000px #111 inset !important;
    caret-color: #F5F5F5 !important;
    transition: background-color 9999s ease-out 0s;
}

 [data-baseweb="input"] input, [data-baseweb="textarea"] textarea {
    background: #111 !important;
    color: #F5F5F5 !important;
    -webkit-text-fill-color: #F5F5F5 !important;
    caret-color: #F5F5F5 !important;
}
input:-webkit-autofill, input:-webkit-autofill:hover, input:-webkit-autofill:focus, input:-webkit-autofill:active {
    -webkit-text-fill-color: #F5F5F5 !important;
    -webkit-box-shadow: 0 0 0 1000px #111 inset !important;
    caret-color: #F5F5F5 !important;
    transition: background-color 9999s ease-out 0s;
}

    border-color: #D4AF37 !important;
    box-shadow: 0 0 0 1px #D4AF37 !important;
}
[data-testid="stCheckbox"] label { color: #F5F5F5 !important; }
[data-testid="stCheckbox"] [role="checkbox"][aria-checked="true"] { background: #D4AF37 !important; border-color: #D4AF37 !important; }
[data-testid="stExpander"] { background: #121212 !important; border: 1px solid #514321 !important; border-radius: 10px !important; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] .streamlit-expanderHeader { color: #F5F5F5 !important; }
[data-testid="stExpander"] .streamlit-expanderHeader:hover { color: #D4AF37 !important; }

/* Main-content selects, text areas, inputs, spinners, dividers */
[data-testid="stMain"] [data-testid="stSelectbox"] [data-testid="stWidgetLabel"] { color: #D4AF37 !important; }
[data-testid="stMain"] [data-testid="stSelectbox"] [data-baseweb="select"] > div {
    background: #111 !important;
    border-color: #514321 !important;
    color: #F5F5F5 !important;
}
[data-testid="stMain"] [data-testid="stSelectbox"] [data-baseweb="select"] * { color: #F5F5F5 !important; }
[data-testid="stMain"] [data-testid="stSelectbox"] [data-baseweb="select"] svg { fill: #D4AF37 !important; }
[data-testid="stMain"] [data-testid="stTextArea"] [data-testid="stWidgetLabel"] { color: #D4AF37 !important; }
[data-testid="stMain"] [data-testid="stTextArea"] textarea {
    background: #111 !important;
    color: #F5F5F5 !important;
    border: 1px solid #514321 !important;
    border-radius: 8px !important;
}
[data-testid="stMain"] [data-testid="stTextArea"] textarea:focus { border-color: #D4AF37 !important; box-shadow: 0 0 0 1px #D4AF37 !important; }
[data-testid="stMain"] [data-testid="stTextInput"] [data-testid="stWidgetLabel"] { color: #D4AF37 !important; }
[data-testid="stMain"] [data-testid="stTextInput"] [data-baseweb="input"] > div { background: #111 !important; border-color: #514321 !important; }
[data-testid="stMain"] [data-testid="stTextInput"] input { color: #F5F5F5 !important; }
[data-testid="stMain"] [data-testid="stSpinner"] { color: #D4AF37 !important; }
[data-testid="stMain"] hr { border-color: #514321 !important; opacity: 1 !important; }
</style>
""", unsafe_allow_html=True)

OFFICIAL_LANGUAGES = list(LANG_CODES.keys())
STEAM_FIELDS = [
    "Arts",
    "Science",
    "Technology",
    "Engineering",
    "Mathematics",
]

# --- 3. AUTH GATE: LOGIN / SIGN UP / FORGOT PASSWORD ---


def _qp(name, default=None):
    """Read a query parameter across Streamlit versions."""
    try:
        value = st.query_params.get(name, default)
    except (AttributeError, TypeError):
        values = st.experimental_get_query_params().get(name, [])
        value = values[0] if values else default
    return value[0] if isinstance(value, list) and value else value


def _set_remember_param(token=None):
    """Set or remove the remember query parameter across Streamlit versions."""
    try:
        if token:
            st.query_params["remember"] = token
        else:
            st.query_params.pop("remember", None)
    except (AttributeError, TypeError):
        params = st.experimental_get_query_params()
        params.pop("remember", None)
        if token:
            params["remember"] = [token]
        st.experimental_set_query_params(**params)


 
if not st.session_state.get("username"):

    raw_token = _qp("remember")
    if raw_token:
        remembered_username = user_for_remember_token(raw_token)
        if remembered_username:
            st.session_state["username"] = remembered_username
            st.session_state["_remember_token"] = raw_token
        else:
            _set_remember_param()

     
    if not st.session_state.get("username"):
        st.markdown( 
            
            f"""
            <div style="display:flex;align-items:center;gap:14px;margin:8px 0 24px">
              {LOGO_SVG}
              <div>
                 <div style="font-size:2rem;font-weight:800;color:#F5F5F5">STEAM APP</div>
                <div style="color:#D4AF37">STEAM learning in every language</div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        login_tab, signup_tab = st.tabs(["Login", "Sign Up"])

        with login_tab:
            with st.form("login_form"):
                login_username = st.text_input("Username", key="login_username")
                login_password = st.text_input(
                    "Password", type="password", key="login_password"
                )
                remember_me = st.checkbox("Remember me")
                login_submitted = st.form_submit_button("Log in")

            if login_submitted:
                user = get_user_by_username(login_username)
                if user and _verify_password(login_password, user[2]):
                    user_id, username = user[0], user[1]
                    if remember_me:
                        raw_token = issue_remember_token(user_id)
                        st.session_state["_remember_token"] = raw_token
                        _set_remember_param(raw_token)
                    else:
                        old_token = _qp("remember")
                        if old_token:
                            forget_remember_token(old_token)
                        st.session_state.pop("_remember_token", None)
                        _set_remember_param()
                    st.session_state["username"] = username
                    st.rerun()
                else:
                    st.error("Incorrect username or password.")

        with signup_tab:
            with st.form("signup_form"):
                signup_username = st.text_input("Username", key="signup_username")
                signup_password = st.text_input(
                    "Password", type="password", key="signup_password"
                )
                confirm_password = st.text_input(
                    "Confirm password", type="password", key="confirm_password"
                )
                signup_submitted = st.form_submit_button("Create account")

            if signup_submitted:
                if not signup_username.strip():
                    st.error("Enter a username.")
                elif signup_password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(signup_password) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    ok, message = create_user(signup_username, signup_password)
                    if ok:
                        st.success("Account created. You can now log in.")
                    else:
                        st.error(message or "Could not create the account.")

        with st.expander("Forgot your password?"):
            st.caption(
                "Ask your teacher or administrator for a one-time reset code. "
                "Codes expire after 30 minutes and work once."
            )
            with st.form("forgot_password_form"):
                reset_username = st.text_input("Username", key="reset_username")
                reset_code = st.text_input("Reset code", key="reset_code")
                reset_password_val = st.text_input(
                    "New password", type="password", key="reset_new_password"
                )
                reset_confirm = st.text_input(
                    "Confirm new password", type="password", key="reset_confirm_password"
                )
                reset_submitted = st.form_submit_button("Reset password")

            if reset_submitted:
                if reset_password_val != reset_confirm:
                    st.error("Passwords do not match.")
                else:
                    ok, message = reset_password_with_code(
                        reset_username, reset_code, reset_password_val
                    )
                    (st.success if ok else st.error)(message)

        st.stop()

# --- 4. SIDEBAR: BRANDING, ROLE, NAVIGATION, RATINGS, LOGOUT ---

st.sidebar.markdown(
    f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 0 18px">
      {LOGO_SVG}
      <div>
        <div style="color:#D4AF37;font-weight:800;font-size:1.1rem">STEAM APP</div>
        <div style="color:#bbb;font-size:.8rem">STEAM Learning · South Africa</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

user_role = st.sidebar.selectbox("Select Your Role", ["Student", "Teacher"])

if user_role == "Teacher":
    with st.sidebar.expander("🔑 Issue password reset code"):
        admin_user = st.text_input("Username", key="admin_reset_user")
        if st.button("Generate code", key="admin_reset_btn"):
            code, err = issue_reset_code(admin_user)
            if err:
                st.sidebar.warning(err)
            else:
                st.sidebar.code(code)

menu = st.sidebar.radio(
    "Navigation Menu",
    [
        "Dashboard Overview",
        "Translation & Live Class Hub",
        "Study Vault & History",
    ],
 
)
if st.session_state.get("username"):
    st.sidebar.info(
        f"Currently logged in as **{st.session_state.get('username', '')}** ({user_role}). "
        f"Empowering education across {len(OFFICIAL_LANGUAGES)} South African languages."
)

if st.sidebar.button("Log out", key="sidebar_logout"):
    token = st.session_state.pop("_remember_token", None) or _qp("remember")
    if token:
        forget_remember_token(token)
    st.session_state.pop("username", None)
    _set_remember_param()
    st.rerun()

st.sidebar.markdown("---")

try:
    average, count = get_rating_summary()
except Exception:
    average, count = 0.0, 0

if count:
    filled = round(average)
    stars = "★" * filled + "☆" * (5 - filled)
    st.sidebar.markdown(
        f'<span style="color:#D4AF37">{stars}</span> '
        f'<span style="color:#F5F5F5">{average:.1f}/5 · {count} ratings</span>',
        unsafe_allow_html=True,
    )
else:
    st.sidebar.caption("No ratings yet — be the first!")

if st.session_state.get("rated_this_session"):
    st.sidebar.caption("Thanks for rating STEAM APP!")
else:
    with st.sidebar.form("app_rating_form"):
        rating_value = st.radio(
            "Rate this app",
            [1, 2, 3, 4, 5],
            format_func=lambda n: f"{'★' * n} ({n})",
            horizontal=True,
        )
        rating_comment = st.text_area("Optional comment", max_chars=500)
        rating_submitted = st.form_submit_button("Submit rating")

    if rating_submitted:
        try:
            add_rating(rating_value, rating_comment)
            st.session_state["rated_this_session"] = True
            st.rerun()
        except Exception as e:
            st.sidebar.warning(f"Couldn't save your rating right now ({e}).")

# --- 5. MODULES ---

# MODULE A: Dashboard Overview
if menu == "Dashboard Overview":
    st.title(f"STEAM App Dashboard - {user_role} Portal")
    st.write(
        "Welcome to the indigenous language translation, study slide management, "
        "and live classroom streaming workspace."
    )

    if user_role == "Teacher":
        st.success(
            "**Teacher Mode Active:** You can paste your virtual class links "
            "(Zoom, Teams, Meet), manage curriculum domains, and broadcast "
            "real-time subtitles directly to students in their preferred languages."
        )
    else:
        st.info(
            f"**Student Mode Active:** You can input custom words, upload lecture "
            f"slide texts, images, or short videos, pick any of the "
            f"{len(OFFICIAL_LANGUAGES)} supported languages, and save translation "
            "logs into your personal study vault."
        )

    st.markdown(
        '<div style="color:#D4AF37;font-size:.72rem;font-weight:700;'
        'letter-spacing:.22em;margin-bottom:2px;">STEAM DOMAINS</div>',
        unsafe_allow_html=True,
    )
    st.markdown("### Covered STEAM Fields & Domains")
    steam_field_cards = ["Arts", "Science", "Technology", "Engineering", "Mathematics"]
    field_cols = st.columns(5)
    for col, field_name in zip(field_cols, steam_field_cards):
        with col:
            st.markdown(
                f"""
                <div style="
                    box-sizing:border-box;
                    text-align:center;
                    padding:14px 6px;
                    border-radius:10px;
                    background-color:#151515;
                    border:1px solid #3B321E;
                    border-top:3px solid #D4AF37;
                    box-shadow:0 4px 14px rgba(0,0,0,.22);
                ">
                    <div style="font-size:0.78rem; color:#B9A45E; margin-bottom:4px;">
                        Field
                    </div>
                    <div style="font-size:1.05rem; font-weight:600; line-height:1.25; color:#F5F5F5;">
                        {field_name}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

# MODULE B: Translation & Live Class Hub
elif menu == "Translation & Live Class Hub":
    st.markdown('<div class="module-kicker">TRANSLATION HUB</div>', unsafe_allow_html=True)
    st.title("STEAM Translation & Live Session Hub")

    col_f, col_l = st.columns(2)
    with col_f:
        selected_field = st.selectbox("Select STEAM Field", STEAM_FIELDS)
    with col_l:
        target_lang = st.selectbox("Select Preferred / Target Language", OFFICIAL_LANGUAGES)

    st.markdown("---")

    if user_role == "Student":
        st.subheader("Student Custom Word & Slide Notes Translator")
        st.write(
            "Enter any vocabulary word, concept phrase, or paste text extracted "
            "from lecture slides below - or upload a file to extract the text "
            "automatically."
        )

        @st.fragment(run_every="5s")
        def student_class_link_panel():
            try:
                active_link = get_class_link()
                db_available = True
            except Exception:
                active_link = None
                db_available = False

            if not db_available:
                st.info(
                    "Live class status is temporarily unavailable. You can still "
                    "paste a link below."
                )
            elif active_link:
                st.success("Your teacher has started an online class.")
                st.link_button("Join Online Class", active_link)
            else:
                st.info(
                    "No live class right now. You can still paste a link to join "
                    "another session."
                )

            manual_link = st.text_input(
                "Or paste an online class link",
                placeholder="https://zoom.us/j/example",
                key="student_class_link",
            )
            if manual_link.strip():
                parsed = urlparse(manual_link.strip())
                if parsed.scheme in ("http", "https") and parsed.netloc:
                    st.link_button("Open Pasted Link", manual_link.strip())
                else:
                    st.warning("Enter a complete link beginning with https://")

        student_class_link_panel()

        st.markdown("""
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 10px">
          <span style="background:#151515;border:1px solid #514321;border-radius:7px;padding:5px 9px;color:#D4AF37;font-size:.75rem;font-weight:700">📄 PDF</span>
          <span style="background:#151515;border:1px solid #514321;border-radius:7px;padding:5px 9px;color:#D4AF37;font-size:.75rem;font-weight:700">📊 PPTX</span>
          <span style="background:#151515;border:1px solid #514321;border-radius:7px;padding:5px 9px;color:#D4AF37;font-size:.75rem;font-weight:700">🖼️ IMAGE</span>
          <span style="background:#151515;border:1px solid #514321;border-radius:7px;padding:5px 9px;color:#D4AF37;font-size:.75rem;font-weight:700">🎬 VIDEO</span>
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Upload a PDF, PowerPoint, image, or video",
            type=["pdf", "pptx", "png", "jpg", "jpeg", "mp4", "mov", "webm", "mkv"],
        )

        video_types = {"mp4", "mov", "webm", "mkv"}
        image_types = {"png", "jpg", "jpeg"}

        if uploaded_file is None:
            # Uploader was cleared - drop any stale status from a previous file.
            st.session_state.pop("extraction_status", None)
            st.session_state.pop("last_uploaded_name", None)
        else:
            file_bytes = uploaded_file.getvalue()
            suffix = uploaded_file.name.lower().rsplit(".", 1)[-1]

            # Visual preview for media files
            if suffix in image_types:
                st.image(file_bytes, caption=uploaded_file.name, use_container_width=True)
            elif suffix in video_types:
                st.video(file_bytes)

            if st.session_state.get("last_uploaded_name") != uploaded_file.name:
                if suffix in video_types:
                    st.session_state["extraction_status"] = (
                        "warning",
                        f"{uploaded_file.name} uploaded and ready to play above. "
                        "Text extraction from video is not enabled - type or paste "
                        "the text you want to translate below.",
                    )
                else:
                    with st.spinner(f"Extracting text from {uploaded_file.name}..."):
                        if suffix == "pdf":
                            extracted = extract_text_from_pdf(file_bytes)
                        elif suffix == "pptx":
                            extracted = extract_text_from_pptx(file_bytes)
                        else:
                            extracted = extract_text_from_image(file_bytes)

                    if extracted:
                        st.session_state["source_input"] = extracted
                        st.session_state["extraction_status"] = (
                            "success",
                            f"Extracted text from {uploaded_file.name}. Review or edit it "
                            "below before translating.",
                        )
                    elif suffix in image_types and not _TESSERACT_IMPORTED:
                        st.session_state["extraction_status"] = (
                            "warning",
                            "Image text extraction (OCR) needs the Tesseract OCR engine "
                            "installed on this computer, and the `pytesseract` Python "
                            "package. Install Tesseract from "
                            "https://github.com/UB-Mannheim/tesseract/wiki (Windows), "
                            "then run `pip install pytesseract` and restart the app. "
                            "In the meantime, you can type or paste the notes manually below.",
                        )
                    else:
                        st.session_state["extraction_status"] = (
                            "warning",
                            f"Couldn't find readable text in {uploaded_file.name}. "
                            "It may be a scanned/image-only PDF, an empty slide deck, "
                            "a password-protected/corrupted file, or too blurry to "
                            "read. Try another file or type the notes manually below.",
                        )

                st.session_state["last_uploaded_name"] = uploaded_file.name

        # Keep showing the last extraction result as long as that file is
        # still selected in the uploader, instead of only on the run it
        # happened - otherwise clicking Translate makes the message vanish
        # even though nothing about the extraction changed.
        if uploaded_file is not None and st.session_state.get("extraction_status"):
            level, message = st.session_state["extraction_status"]
            getattr(st, level)(message)

        with st.expander("Or speak instead of typing (voice input)"):
            spoken_lang_student = st.selectbox(
                "Language you'll be speaking",
                SPOKEN_LANGUAGE_OPTIONS,
                key="spoken_lang_student",
            )
            recording = st.audio_input("Record your word or notes", key="student_recording")
            if recording is not None and st.button("Transcribe Recording", key="transcribe_student"):
                with st.spinner("Transcribing..."):
                    text, error = speech_to_text(recording.getvalue(), spoken_lang_student)
                if text:
                    st.session_state["source_input"] = text
                    st.success("Transcribed! Review or edit it below before translating.")
                else:
                    st.warning(error)

        source_input = st.text_area(
            "Source Text / Study Notes:",
            placeholder="Type word or paste slide notes here, or upload a file above...",
            key="source_input",
        )

        source_tts_lang = st.selectbox(
            "Source text language",
            OFFICIAL_LANGUAGES,
            key="student_source_tts_lang",
        )
        read_aloud_button(
            source_input, source_tts_lang,
            "🔊 Listen to Source Text", "listen_student_source",
        )

        translated_output = None
        if st.button("Translate Term / Notes", type="primary"):
            if source_input.strip():
                with st.spinner("Translating text..."):
                    translated_result = perform_translation(source_input, target_lang)
                    translated_output = (
                        f"[{target_lang.upper()} Translation | Field: {selected_field}]\n\n"
                        f"Source Content: {source_input}\n\n"
                        f"Translated Result:\n{translated_result}"
                    )
                st.session_state["last_translation"] = translated_output
                st.session_state["last_translation_text"] = translated_result
                st.session_state["last_translation_lang"] = target_lang
                st.success("Translation generated successfully.")
                st.code(translated_output, language="text")
            else:
                st.warning("Please enter text or notes to translate.")

        if st.session_state.get("last_translation_text"):
            if st.button("🔊 Listen to Translation"):
                with st.spinner("Generating audio..."):
                    audio_bytes, tts_error = text_to_speech(
                        st.session_state["last_translation_text"],
                        st.session_state["last_translation_lang"],
                    )
                if audio_bytes:
                    st.audio(audio_bytes, format="audio/mp3")
                else:
                    st.info(tts_error)

        if st.button("Save Translation to Study Vault"):
            saved_output = st.session_state.get("last_translation")
            if saved_output:
                save_to_db(
                    "Student",
                    selected_field,
                    source_input,
                    saved_output,
                    target_lang,
                )
                st.toast("Saved successfully to your study vault!")
            else:
                st.warning("Translate something first before saving.")

    else:  # Teacher Portal
        st.subheader("Teacher Live Class & Subtitle Broadcaster")
        st.write(
            "Paste your online class link and stream live text-based lecture "
            "subtitles to student devices."
        )
        class_link = st.text_input(
            "Online Class Link (Zoom, Microsoft Teams, Google Meet)",
            placeholder="https://zoom.us/j/example",
            key="teacher_class_link",
        )

        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("Start Live Class Session", type="primary"):
                if class_link.strip():
                    try:
                        save_class_link(class_link)
                        st.success(
                            f"Live session active. Class link published to all "
                            f"students, with subtitle feed set to {target_lang}."
                        )
                    except ValueError as e:
                        st.warning(str(e))
                    except Exception as e:
                        st.warning(f"Couldn't publish the link right now ({e}).")
                else:
                    st.warning("Please enter a valid class URL first.")
        with col_btn2:
            if st.button("End Session"):
                try:
                    clear_class_link()
                except Exception:
                    pass
                st.info("Class session ended and the shared link was cleared.")

        st.markdown("---")
        st.markdown("### Live Lecture Subtitle Feed")

        with st.expander("Or speak the sentence instead of typing (voice input)"):
            spoken_lang_teacher = st.selectbox(
                "Language you're speaking",
                SPOKEN_LANGUAGE_OPTIONS,
                key="spoken_lang_teacher",
            )
            teacher_recording = st.audio_input("Record the current sentence", key="teacher_recording")
            if teacher_recording is not None and st.button("Transcribe Recording", key="transcribe_teacher"):
                with st.spinner("Transcribing..."):
                    text, error = speech_to_text(teacher_recording.getvalue(), spoken_lang_teacher)
                if text:
                    st.session_state["speech_input"] = text
                    st.success("Transcribed! Review it below, then broadcast.")
                else:
                    st.warning(error)

        speech_input = st.text_area(
            "Type current spoken sentence or lecture excerpt:",
            placeholder="Type sentences here to broadcast real-time translated subtitles...",
            key="speech_input",
        )

        source_tts_lang = st.selectbox(
            "Spoken text language",
            OFFICIAL_LANGUAGES,
            key="teacher_source_tts_lang",
        )
        read_aloud_button(
            speech_input, source_tts_lang,
            "🔊 Listen to Source Text", "listen_teacher_source",
        )

        if st.button(f"Broadcast Subtitle in {target_lang}"):
            if speech_input.strip():
                with st.spinner("Translating and broadcasting..."):
                    sub_translated = perform_translation(speech_input, target_lang)
                    sub_output = f"[LIVE SUBTITLE - {target_lang.upper()}] {sub_translated}"
                    save_to_db(
                        "Teacher",
                        selected_field,
                        speech_input,
                        sub_output,
                        target_lang,
                    )
                st.session_state["last_subtitle_text"] = sub_translated
                st.session_state["last_subtitle_lang"] = target_lang
                st.success("Live subtitle broadcasted and synced to student vaults!")
                st.code(sub_output, language="text")
            else:
                st.warning("Please type a phrase to broadcast.")

        if st.session_state.get("last_subtitle_text"):
            if st.button("🔊 Listen to Broadcasted Subtitle"):
                with st.spinner("Generating audio..."):
                    audio_bytes, tts_error = text_to_speech(
                        st.session_state["last_subtitle_text"],
                        st.session_state["last_subtitle_lang"],
                    )
                if audio_bytes:
                    st.audio(audio_bytes, format="audio/mp3")
                else:
                    st.info(tts_error)

# MODULE C: Study Vault & History
elif menu == "Study Vault & History":
    st.markdown('<div class="module-kicker">STUDY VAULT</div>', unsafe_allow_html=True)
    st.title("Offline Study Vault & Saved Records")
    st.write(
        "Access all your archived slide notes, custom word lookups, and "
        "broadcasted class transcripts."
    )

    records = get_all_records()

    if not records:
        st.info(
            "Your vault is currently empty. Start translating notes or broadcasting "
            "sessions to save items here."
        )
    else:
        for row in records:
            record_id, role, field, src, translated, lang, timestamp = row
            with st.expander(f"✦  {field}  ·  {lang}  ·  {role}  ·  {timestamp}"):
                st.write(f"**Source Text / Input:** {src}")
                st.markdown(f"**Stored Translation / Subtitle:**\n```text\n{translated}\n```")

                source_tts_lang = st.selectbox(
                    "Source text language",
                    OFFICIAL_LANGUAGES,
                    key=f"vault_source_lang_{record_id}",
                )
                read_aloud_button(
                    src, source_tts_lang,
                    "🔊 Listen to Source", f"listen_src_{record_id}",
                )

                speakable_translation = (
                    translated.split("Translated Result:\n", 1)[-1].strip()
                )
                read_aloud_button(
                    speakable_translation, lang,
                    "🔊 Listen to Translation", f"listen_out_{record_id}",
                )

                if st.button("Delete Record", key=f"del_{record_id}"):
                    delete_record(record_id)
                    st.success("Record deleted from vault!")
                    st.rerun()
