import streamlit as st
import hashlib
import json
import time
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Add custom CSS for styling
st.markdown("""
<style>
/* Background and text */
body {
    background-color: #f4f4f9;
    color: #333;
}

/* Streamlit override */
.stApp {
    background: linear-gradient(135deg, #ffffff, #e9ecef);
    font-family: 'Segoe UI', sans-serif;
}

h1, h2, h3 {
    color: #3c3c3c;
    font-weight: 600;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background-color: #002b36;
    color: white;
}
section[data-testid="stSidebar"] h1, 
section[data-testid="stSidebar"] h2, 
section[data-testid="stSidebar"] h3, 
section[data-testid="stSidebar"] .css-1v3fvcr {
    color: white;
}

/* Buttons */
div.stButton > button {
    background-color: #005f73;
    color: white;
    border-radius: 8px;
    padding: 0.5rem 1.2rem;
    border: none;
    font-weight: bold;
}
div.stButton > button:hover {
    background-color: #0a9396;
    color: white;
}

/* Text input boxes */
input, textarea {
    border-radius: 6px !important;
    padding: 8px !important;
}

/* Success messages */
.stAlert.success {
    background-color: #d3f9d8;
    color: #1b4332;
}

/* Error messages */
.stAlert.error {
    background-color: #ffe5e5;
    color: #721c24;
}

/* Warning messages */
.stAlert.warning {
    background-color: #fff3cd;
    color: #856404;
}
</style>
""", unsafe_allow_html=True)


# File to store encrypted data and user info
DATA_FILE = "data.json"

# Load or initialize data
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump({"users": {}, "data": {}}, f)

with open(DATA_FILE, "r") as f:
    db = json.load(f)

# Load session state variables
if "username" not in st.session_state:
    st.session_state.username = None
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = {}
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = {}

# Key generation (should remain fixed)
FERNET_KEY = urlsafe_b64encode(hashlib.sha256(b"your_secret_encryption_key").digest())
cipher = Fernet(FERNET_KEY)

# Save data to JSON file
def save_db():
    with open(DATA_FILE, "w") as f:
        json.dump(db, f)

# Hash password using PBKDF2
def hash_password(password, salt):
    return pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()

# Registration
def register_user(username, password):
    if username in db["users"]:
        return False
    salt = os.urandom(16).hex()
    hashed = hash_password(password, salt)
    db["users"][username] = {"password": hashed, "salt": salt}
    save_db()
    return True

# Authenticate user
def authenticate(username, password):
    user = db["users"].get(username)
    if not user:
        return False
    hashed = hash_password(password, user["salt"])
    return hashed == user["password"]

# Encrypt user data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt user data
def decrypt_data(token):
    return cipher.decrypt(token.encode()).decode()

# Lockout check
def is_locked_out(username):
    lockout = st.session_state.lockout_time.get(username, 0)
    return time.time() < lockout

# Streamlit UI
st.title("🔐 Secure Data Encryption System (Advanced)")

menu = ["Login", "Register", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

# LOGIN PAGE
if choice == "Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if is_locked_out(username):
        st.error("⏳ Account is locked. Please wait a minute before retrying.")
        st.stop()

    if st.button("Login"):
        if authenticate(username, password):
            st.session_state.username = username
            st.success(f"✅ Logged in as {username}")
            st.session_state.login_attempts[username] = 0
        else:
            attempts = st.session_state.login_attempts.get(username, 0) + 1
            st.session_state.login_attempts[username] = attempts
            st.error(f"❌ Login failed. Attempt {attempts}/3")
            if attempts >= 3:
                st.session_state.lockout_time[username] = time.time() + 60  # 1 minute lockout
                st.error("🔒 Too many failed attempts. Locked out for 1 minute.")

# REGISTER PAGE
elif choice == "Register":
    st.subheader("📝 Register New Account")
    new_user = st.text_input("Choose a Username")
    new_pass = st.text_input("Choose a Password", type="password")

    if st.button("Register"):
        if register_user(new_user, new_pass):
            st.success("✅ Registration successful! Go to Login.")
        else:
            st.error("⚠️ Username already exists.")

# STORE DATA
elif choice == "Store Data":
    if not st.session_state.username:
        st.warning("🚫 Please login first.")
        st.stop()

    st.subheader("📂 Store Encrypted Data")
    data_input = st.text_area("Enter data to encrypt:")
    if st.button("Encrypt & Store"):
        if data_input:
            encrypted = encrypt_data(data_input)
            db["data"].setdefault(st.session_state.username, []).append(encrypted)
            save_db()
            st.success("✅ Data encrypted and saved.")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter some data.")

# RETRIEVE DATA
elif choice == "Retrieve Data":
    if not st.session_state.username:
        st.warning("🚫 Please login first.")
        st.stop()

    st.subheader("🔍 Retrieve Your Encrypted Data")
    user_data = db["data"].get(st.session_state.username, [])
    if not user_data:
        st.info("📭 No data found.")
    else:
        for i, enc in enumerate(user_data, 1):
            with st.expander(f"Data {i}"):
                try:
                    decrypted = decrypt_data(enc)
                    st.code(decrypted, language="text")
                except:
                    st.error("⚠️ Could not decrypt data.")
