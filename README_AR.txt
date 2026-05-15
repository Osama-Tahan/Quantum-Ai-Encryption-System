
Data Encryption System Based on Quantum Computing
With AI Performance Enhancer
Local Web App - Phase 1

طريقة التشغيل:

1) افتح التيرمنال داخل مجلد المشروع

2) أنشئ بيئة افتراضية:
python -m venv venv

3) فعل البيئة:
venv\Scripts\activate

4) ثبت المكتبات:
pip install -r requirements.txt

5) شغل السيرفر:
python main.py

6) افتح المتصفح:
http://127.0.0.1:8000

بيانات الدخول:
Admin:
username: admin
password: admin123

Encrypter:
username: encrypter
password: encrypt123

Viewer:
username: viewer
password: viewer123

ملاحظات:
- هذه نسخة Web App محلية Local وليست Cloud بعد.
- Qiskit يعمل في Backend وليس في المتصفح.
- AES المستخدم هو AES-256-GCM فقط.
- Embedded Key Mode هو الوضع الأساسي، ويمكن فك التشفير لاحقاً بكلمة المرور فقط.
