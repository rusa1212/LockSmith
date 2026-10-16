"""Streamlit GUI. 실행: streamlit run app.py"""
import base64

import streamlit as st

import crypto_tool as ct

st.set_page_config(page_title="암호/복호화 도구", page_icon="🔐")
st.title("🔐 암호/복호화 도구")

tab_classic, tab_aes, tab_hybrid = st.tabs(["고전 암호", "AES-256-GCM", "RSA + AES 키 교환"])

# --- 고전 암호 ---
with tab_classic:
    algo = st.radio("알고리즘", ["Caesar", "Vigenère"], horizontal=True)
    text = st.text_area("입력 텍스트", "Hello, World", key="c_text")
    mode = st.radio("모드", ["암호화", "복호화"], horizontal=True, key="c_mode")
    dec = mode == "복호화"
    if algo == "Caesar":
        shift = st.slider("Shift", 1, 25, 3)
        result = ct.caesar(text, shift, dec)
    else:
        key = st.text_input("키 (알파벳)", "LEMON")
        try:
            result = ct.vigenere(text, key, dec)
        except ValueError as e:
            result = ""
            st.error(str(e))
    st.code(result)

# --- AES ---
with tab_aes:
    if "aes_key" not in st.session_state:
        st.session_state.aes_key = ct.aes_generate_key()
    if st.button("새 AES 키 생성"):
        st.session_state.aes_key = ct.aes_generate_key()
    st.text_input("현재 키 (base64)", base64.b64encode(st.session_state.aes_key).decode(), disabled=True)

    plain = st.text_area("평문", "안녕하세요, 비밀 메시지입니다.")
    if st.button("암호화"):
        blob = ct.aes_encrypt(plain, st.session_state.aes_key)
        st.session_state.aes_ct = base64.b64encode(blob).decode()

    cipher_b64 = st.text_area("암호문 (base64)", st.session_state.get("aes_ct", ""))
    if st.button("복호화"):
        try:
            st.success(ct.aes_decrypt(base64.b64decode(cipher_b64), st.session_state.aes_key))
        except Exception:
            st.error("복호화 실패: 키가 다르거나 암호문이 변조되었습니다.")

# --- 하이브리드 ---
with tab_hybrid:
    st.caption("수신자의 RSA 공개키로 일회용 AES 키를 전달하고, 그 키로 메시지를 암호화합니다.")
    msg = st.text_input("보낼 메시지", "키 교환 테스트 메시지")
    if st.button("전체 과정 실행"):
        priv, pub = ct.rsa_generate_keypair()
        session_key = ct.aes_generate_key()
        ciphertext = ct.aes_encrypt(msg, session_key)
        wrapped = ct.rsa_encrypt(session_key, pub)
        recovered = ct.rsa_decrypt(wrapped, priv)
        plaintext = ct.aes_decrypt(ciphertext, recovered)

        st.subheader("1. 수신자: RSA 공개키 공개")
        st.code(ct.export_public_pem(pub))
        st.subheader("2. 송신자: AES로 메시지 암호화")
        st.code(base64.b64encode(ciphertext).decode())
        st.subheader("3. 송신자: RSA 공개키로 AES 키 암호화 후 전송")
        st.code(base64.b64encode(wrapped).decode())
        st.subheader("4. 수신자: 개인키로 AES 키 복원 → 복호화")
        st.success(f"{plaintext}  (원문 일치: {plaintext == msg})")
