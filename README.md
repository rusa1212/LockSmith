Python으로 구현한 암호/복호화 도구. Caesar, Vigenère, AES-256-GCM, RSA-2048과 RSA + AES 하이브리드 키 교환을 지원
 
## 구성
 
```
crypto_tool.py     # 암호 로직 + CLI
app.py             # Streamlit 웹 GUI
requirements.txt
```
 
## 설치
 
```bash
pip install -r requirements.txt
```
 
## 사용법
 
```bash
# 하이브리드 키 교환 데모
python crypto_tool.py demo
 
# 고전 암호
python crypto_tool.py caesar enc "Hello" --shift 3
python crypto_tool.py vigenere enc "Attack at dawn" --key LEMON
 
# AES-256-GCM
python crypto_tool.py aes enc "비밀 메시지"
python crypto_tool.py aes dec "<암호문>" --key "<키>"
 
# 웹 GUI (localhost:8501)
streamlit run app.py
```
 
## 키 교환 흐름
 
1. 수신자: RSA 키 쌍 생성, 공개키 공개
2. 송신자: 일회용 AES 키로 메시지 암호화
3. 송신자: AES 키를 RSA 공개키로 암호화해 전송
4. 수신자: RSA 개인키로 AES 키 복원 후 복호화
## 설정
 
| 알고리즘 | 설정 |
|---|---|
| AES | 256비트, GCM, 암호화마다 새 12바이트 nonce |
| RSA | 2048비트, OAEP (SHA-256) |
 
AES-GCM은 암호문이 변조되면 복호화에 실패(`InvalidTag`)함.
