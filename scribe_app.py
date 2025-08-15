# test deployment
import streamlit as st
import whisper
import os
from openai import AzureOpenAI
import tempfile
from audio_recorder_streamlit import audio_recorder 
import time

from io import BytesIO
from reportlab.pdfgen import canvas

import hashlib
import datetime
import base64

import bcrypt
import json

def get_secret(key, default=None):
    """
    Read config from Streamlit secrets first, then environment variables.
    Works on Streamlit Cloud (st.secrets) and Azure (App Settings env vars).
    """
    try:
        return st.secrets[key]
    except Exception:
        return os.environ.get(key, default)

DATA_DIR = os.getenv("APP_DATA_DIR", "/home/site/data")  # Azure persistent path; locally we'll create ./data
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR, exist_ok=True)

USERS_FILE = os.path.join(DATA_DIR, "users.json")
LOG_FILE = os.path.join(DATA_DIR, "audit_log.txt")

def load_users():
    # Load users dictionary from users.json file
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    # Save users dictionary to users.json file
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def hash_password(password: str) -> str:
    # Hash plain password
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    # Compare plain password with hashed password
    return bcrypt.checkpw(password.encode(), hashed.encode())

LOG_FILE = "audit_log.txt"

os.makedirs(DATA_DIR, exist_ok=True)

def log_event(username, action):
    """Encrypt and write an audit log entry with timestamp, username, and action."""
    plaintext = f"{datetime.datetime.now()} - {username} - {action}\n"
    encrypted_entry = fernet.encrypt(plaintext.encode())  # encrypt bytes
    b64_encrypted = base64.b64encode(encrypted_entry).decode()  # convert to base64 string
    
    with open(LOG_FILE, "a") as log:
        log.write(b64_encrypted + "\n")

def read_audit_log():
    with open(LOG_FILE, "r") as log:
        for line in log:
            line = line.strip()
            encrypted_entry = base64.b64decode(line)
            decrypted_entry = fernet.decrypt(encrypted_entry).decode()
            print(decrypted_entry)

from cryptography.fernet import Fernet

FERNET_KEY = get_secret("FERNET_KEY")  # put this in .streamlit/secrets.toml locally and in Azure App Settings later
if not FERNET_KEY:
    st.error("Missing FERNET_KEY. Please set it in .streamlit/secrets.toml (local) or Azure App Settings.")
    st.stop()

# Accept either plain string or bytes
fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def encrypt_file(data: bytes) -> bytes:
    """Encrypt audio bytes."""
    return fernet.encrypt(data)

def decrypt_file(data: bytes) -> bytes:
    """Decrypt encrypted audio bytes."""
    return fernet.decrypt(data)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

SESSION_TIMEOUT = 15 * 60  # 15 minutes
if "last_activity" not in st.session_state:
    st.session_state.last_activity = time.time()

if not st.session_state.authenticated:
    if "show_registration" not in st.session_state:
        st.session_state.show_registration = False

    if st.button("➕ Register New Provider"):
        st.session_state.show_registration = not st.session_state.show_registration  # Toggle visibility

    ACCESS_KEY = get_secret("PROVIDER_ACCESS_KEY", "")

    if st.session_state.show_registration:
        st.markdown("---")
        st.subheader("Register New Provider")

        access_key_input = st.text_input("Access Key (required)", type="password", key="access_key")
        new_user = st.text_input("New Username", key="new_user")
        new_pass = st.text_input("New Password", type="password", key="new_pass")

        if st.button("Create Account"):
            if access_key_input != ACCESS_KEY:
                st.error("❌ Invalid access key. Contact admin for access.")
            else:
                users = load_users()
                if new_user in users:
                    st.error("Username already exists.")
                elif not new_user or not new_pass:
                    st.error("Please provide both username and password.")
                else:
                    users[new_user] = hash_password(new_pass)
                    save_users(users)
                    st.success("✅ Provider account created successfully!")
                    st.session_state.show_registration = False

def login():
    st.title("🔒 Provider Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    users = load_users()

    if st.button("Login"):
        if username in users and check_password(password, users[username]):
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.last_activity = time.time()
            st.success(f"✅ Welcome {username}!")
            log_event(username, "Successful login")
        else:
            st.error("❌ Invalid username or password.")
            log_event(username, "Failed login attempt")

if not st.session_state.authenticated:
    login()
    st.stop()

if st.session_state.authenticated:
    if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
        st.warning("⚠️ Session timed out due to inactivity. Please log in again.")
        st.session_state.authenticated = False
        if "soap_note" in st.session_state:
            del st.session_state["soap_note"]
        if "recorded_audio_path" in st.session_state:
            del st.session_state["recorded_audio_path"]
        st.stop()

def delete_old_audio():
    old_path = st.session_state.get("recorded_audio_path")
    if 'decrypted_audio_path' in locals() and decrypted_audio_path and os.path.exists(decrypted_audio_path):
        try:
            os.remove(decrypted_audio_path)
        except Exception as e:
            st.warning(f"Could not delete decrypted file: {e}")

def clear_old_session_data():
    keys_to_clear = ["recorded_audio_path", "soap_note"]
    for key in keys_to_clear:
        if key in st.session_state:
            del st.session_state[key]

if "last_audio_hash" not in st.session_state:
    st.session_state.last_audio_hash = None

def get_audio_hash(audio_path):
    with open(audio_path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()

client = AzureOpenAI(
    api_key=get_secret("AZURE_OPENAI_API_KEY"),
    api_version=get_secret("AZURE_OPENAI_API_VERSION", "2024-08-01-preview"),  # or whatever version you’re using
    azure_endpoint=get_secret("AZURE_OPENAI_ENDPOINT")
)
deployment_name = get_secret("AZURE_OPENAI_DEPLOYMENT_NAME")

@st.cache_resource
def load_model():
    return whisper.load_model("base")

model = load_model()

if st.session_state.authenticated:
    st.session_state.last_activity = time.time()


st.markdown(
    """
    <div style="background-color:#0052cc; padding: 20px; border-radius: 8px; text-align:center; color:white; font-family:sans-serif;">
        <h1 style="margin-bottom:0; font-weight:700; font-size:3rem;">
            MedScriptor
        </h1>
        <p style="margin-top:5px; font-size:1.2rem;">
            Your AI-Powered Medical Scribe
        </p>
    </div>
    """, 
    unsafe_allow_html=True
)

st.markdown("<br>", unsafe_allow_html=True)

# --- Visit Type Selection Card ---
with st.container():
    st.markdown(
        """
        <div style="background:#f0f4ff; padding:15px; border-radius:6px; box-shadow: 0 2px 6px rgb(0 0 0 / 0.1);">
            <h3 style="color:#0052cc;">Select Visit Type</h3>
        </div>
        """, unsafe_allow_html=True
    )
visit_type = st.selectbox(
    "",  # no label since header above
    ["General", "Urgent Care", "Pediatrics", "Psychiatry", "Dermatology", "Cardiology"]
)

st.markdown("<br>", unsafe_allow_html=True)

with st.container():
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(
            """
            <div style="background:#f9fafb; padding:20px; border-radius:6px; box-shadow: 0 1px 4px rgb(0 0 0 / 0.05);">
                <h3 style="color:#0052cc;">Record Audio</h3>
                <p>Use the button below to start or stop recording patient audio (max 20 minutes).</p>
                <br>
            """, unsafe_allow_html=True
        )

        if st.button("Record Audio"):
            st.session_state.recording = not st.session_state.get("recording", False)
            if not st.session_state.recording:
                delete_old_audio()
                clear_old_session_data()
        if "recording" not in st.session_state:
            st.session_state.recording = False
        audio_bytes = None
        if st.session_state.recording:
            audio_bytes = audio_recorder(
                pause_threshold=1200,   # Up to 20 minutes
                sample_rate=44100,
                energy_threshold=-1
            )
        if audio_bytes:
            delete_old_audio()
            clear_old_session_data()
            audio_buffer = audio_bytes  # Read once and save to variable
            with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmpfile:
                encrypted_data = encrypt_file(audio_buffer)
                tmpfile.write(encrypted_data)
                st.session_state["recorded_audio_path"] = tmpfile.name
                st.session_state["recorded_audio_encrypted"] = True
            st.success("✅ Recording saved. Ready for transcription.")
            st.audio(audio_buffer, format="audio/wav")
            log_event(st.session_state.get("username", "Unknown"), "Recorded new audio")

        st.markdown("</div>", unsafe_allow_html=True)

    with col2:
        st.markdown(
            """
            <div style="background:#f9fafb; padding:20px; border-radius:6px; box-shadow: 0 1px 4px rgb(0 0 0 / 0.05);">
                <h3 style="color:#0052cc;">Upload Audio File</h3>
                <p>Upload an existing audio file (wav, mp3, m4a) of the patient visit.</p>
            """, unsafe_allow_html=True
        )
        audio_file = st.file_uploader("", type=["wav", "mp3", "m4a"])
        audio_path = None
        if audio_file is not None:
            delete_old_audio()
            clear_old_session_data()
            audio_bytes = audio_file.read()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmpfile:
                encrypted_data = encrypt_file(audio_bytes)
                tmpfile.write(encrypted_data)
                audio_path = tmpfile.name
                log_event(st.session_state.get("username", "Unknown"), "Uploaded audio file")
                st.session_state["recorded_audio_encrypted"] = True
        elif st.session_state.get("recorded_audio_path"):
            audio_path = st.session_state["recorded_audio_path"]
        else:
            audio_path = None
        st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)

if audio_path:
    current_hash = get_audio_hash(audio_path)

if audio_path:
    st.info("Transcribing and generating SOAP note...")
    decrypted_audio_path = None  # Initialize variable
    
    if st.session_state.get("recorded_audio_encrypted", False):
        # decrypt only if encrypted
        with open(audio_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_file(encrypted_data)
        # Save decrypted data to temp file for Whisper
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as decrypted_file:
            decrypted_file.write(decrypted_data)
            decrypted_audio_path = decrypted_file.name
        audio_for_transcription = decrypted_audio_path
    else:
        # uploaded file is not encrypted
        audio_for_transcription = audio_path
    
    result = model.transcribe(audio_for_transcription)
    
    # Clean up decrypted file after use (only if it exists)
    if decrypted_audio_path and os.path.exists(decrypted_audio_path):
        try:
            os.remove(decrypted_audio_path)
        except Exception as e:
            st.warning(f"Could not delete decrypted file: {e}")
    formatted_transcript = result["text"] 
    st.success("✅ Transcription and SOAP note complete!")

    # Now build GPT prompt using formatted transcript with speakers
    prompt = f"""
    You are a professional medical scribe.

    This is a {visit_type} clinical visit between a doctor and a patient.

    The following transcript may include back and forth converesation, questions, answers, and information about the patient. 

    This transcript is a continuous dialogue between a doctor and a patient. The doctor typically asks questions, performs assessments, and provides instructions. The patient describes symptoms, medical history, and answers the doctor’s questions. There may be occasional input from other healthcare personnel or family members.

    Your task is to:

    1. Identify and differentiate what information comes from the doctor versus the patient or others.

    2. Organize the information clearly into the SOAP note sections: Subjective, Objective, Assessment, and Plan.

    3. Be detailed and precise, including relevant symptoms, clinical observations, and treatment plans.

    4. Avoid including filler words or irrelevant chatter.

    5. If uncertain about the speaker, use context clues to infer the role, but focus on medical relevance.

    6. Do not add in information that is not found in the conversation/visit

    7. Most importantly make sure it is written as if the Doctor themself had written it.    

    Format your output exactly as follows:

    Subjective:

    Patient’s reported symptoms, feelings, complaints, history, and concerns.

    Objective:

    Observable clinical findings, vitals, physical exam results, lab or test data, and doctor’s observations.

    Assessment:

    Doctor’s clinical impressions, diagnoses, and differential diagnosis.

    Plan:

    Recommended treatments, tests, referrals, patient instructions, and follow-up plans.


    Transcript:
    {formatted_transcript}
    """
    with st.container():
        st.markdown(
            """
            <div style="background:#f9fafb; padding:15px 20px; border-radius:6px; box-shadow: 0 1px 3px rgb(0 0 0 / 0.1);">
                <h3 style="color:#0052cc;">Transcript</h3>
            </div>
            """, unsafe_allow_html=True
        )
        st.text_area("Transcript Prompt", formatted_transcript, height=300)
    st.markdown("<br>", unsafe_allow_html=True)

else:
    st.info("Please upload or record an audio file to begin.")


if audio_path:
    if (
        "soap_note" not in st.session_state
        or st.session_state.last_audio_hash != current_hash
    ):
        with st.spinner("Generating SOAP note with GPT-4o..."):
            try:
                response = client.chat.completions.create(
                    model=deployment_name,
                    messages=[
                        {"role": "system", "content": "You are a professional medical scribe."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3,
                )
                st.session_state.soap_note = response.choices[0].message.content
                log_event(st.session_state.get("username", "Unknown"), "Generated SOAP note")
                st.session_state.last_audio_hash = current_hash
            except Exception as e:
                st.error(f"❌ GPT-4o failed to generate the SOAP note: {e}")
                st.session_state.soap_note = "SOAP generation failed due to an error."

    # Display note in browser
    with st.container():
        st.markdown(
            """
            <div style="background:#f9fafb; padding:15px 20px; border-radius:6px; box-shadow: 0 1px 3px rgb(0 0 0 / 0.1);">
            <h3 style="color:#0052cc;">SOAP Note</h3>
            </div>
            """, unsafe_allow_html=True
        )
        edited_note = st.text_area(
            "Edit your SOAP note below:",
            value=st.session_state.soap_note,
            height=400,
            key="edited_note"
        ) 

    st.download_button(
        label="Download SOAP Note as .txt",
        data=edited_note,
        file_name="soap_note.txt",
        mime="text/plain"
    ) 


    # PDF download
    pdf_buffer = BytesIO()
    pdf_canvas = canvas.Canvas(pdf_buffer)
    text_object = pdf_canvas.beginText(40, 800)

    # Split long notes into multiple lines
    for line in edited_note.split('\n'):
        text_object.textLine(line)

    pdf_canvas.drawText(text_object)
    pdf_canvas.showPage()
    pdf_canvas.save()
    pdf_buffer.seek(0)

    st.download_button(
        label="Download SOAP Note as PDF",
        data=pdf_buffer,
        file_name="soap_note.pdf",
        mime="application/pdf"
    )
