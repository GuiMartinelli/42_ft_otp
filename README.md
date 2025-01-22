# FT_OTP

In this project, the aim is to implement a TOTP (Time-based One-Time Password) system based on RFC 6238, which will be capable of generating ephemeral passwords from a master key. This master key is provided by the user and stored in a encrypted file, that will be decrypted when the OTP is generated. I also took the opportunity to learn more about Python programming
<br/><br/>

### WHAT IS OTP?
OTP stands for One-Time Password. It's a temporary, secure PIN-code that's sent to a user for a single login attempt or transaction. OTPs are a strong authentication method that's often used as part of two-factor authentication (2FA).
<br/><br/>

### WHAT IS TOTP?
TOTP stands for Time-based One-Time Passwords and is a common form of two-factor authentication (2FA). Unique numeric passwords are generated with a standardized algorithm that uses the current time as an input.
<br/><br/>

### USAGE

- Clone the repository `git clone`
- Generate a 64-character hexadecimal secret and save it to a file (e.g., key.txt).
- Encrypt the secret with `ft_otp.py -g key.txt`. This will generate a file named `ft_otp.key` containing the encrypted secret.
- Generate a TOTP with `ft_otp.py -k ft_otp.key`. I also used the `pyotp` Python library to compare the generated tokens. Since both use the same algorithm, the tokens should be identical.
<br/><br/>

### RESOURCES
https://datatracker.ietf.org/doc/html/rfc6238
https://www.comparitech.com/blog/information-security/what-is-fernet/
https://medium.com/analytics-vidhya/understanding-totp-in-python-bbe994606087
https://gist.github.com/frasertweedale/607c2e80683c36d576d2
