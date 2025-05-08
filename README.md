# 🛡️ Secure Data Encryption System using Streamlit

A Python-based secure data storage and retrieval system with user authentication, encryption, and a friendly Streamlit interface. Users can store and decrypt their sensitive data using a passkey, with additional security features such as hashed credentials, lockouts, and persistent storage.

---

## 🚀 Features

✅ **User Registration & Login**  
✅ **Symmetric Encryption with Fernet**  
✅ **PBKDF2 Password Hashing** (more secure than SHA-256)  
✅ **Data Persistence** using JSON file  
✅ **Time-based Lockout after 3 Failed Attempts**  
✅ **Multi-User Support**  
✅ **Streamlit-Based UI** with Enhanced Styling  
✅ **In-Memory Session Tracking**  
✅ **Secure Decryption Only With Correct Passkey**

---

## 📋 Requirements

- Python 3.7+
- Streamlit
- cryptography

Install dependencies:

```bash
pip install streamlit cryptography
