import os
import importlib.util

# Enable OTP debug fallback so failed SMTP attempts write the OTP to otp_debug.log
os.environ.setdefault('OTP_DEBUG', '1')

p = r"c:\Users\sumis\Queen-s-Gambit\v15. single python code\app.py"
spec = importlib.util.spec_from_file_location("app_v15", p)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
print('Calling send_otp_email...')
res = app.send_otp_email('shreyanshsinhaatoz@gmail.com')
print('Result:', res)
