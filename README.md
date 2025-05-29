# YOUR PROJECT TITLE

## Video Demo  

Checkout the demo video over at [Youtube](https://www.youtube.com/watch?v=Why1PzBJU40)

## Description

This is a simple web application that allows users to manage their OTPs (one-time passwords). It is built using Flask, SQLite, and a little bit of JavaScript.

### a new encryption paradigm

The database doesn't store users' passwords either in plain text or hashed. Instead, it stores users' secrets encrypted with their own hashed passwords only. This way, a login attempt will only be successful if the user provides the correct password that decrypts his secrets successfully.

## Files rundown

- `app.py`: The main Flask application file.
- `init.py`: This is where HMR is configured.
- `helpers.py`: This is where the helper functions for access filters are defined.
- `encryption.py`: This is where the encryption and decryption functions are defined.
- `templates/`: Contains the HTML templates for the application.
  - `layout.html`: The extensible base template for the application.
  - `index.html`: The main page of the application (Where OTPs are displayed).
  - `account.hml`: The page where users can view and manage their username and password.
  - `add_secret.html`: The page where users can add new OTPs by providing a secret and account details.
  - `login.html`: The page where users can login to their account.
  - `register.html`: The page where users can register for a new account.
- `static/`: only contains a little bit of basic CSS, all other styling is done in the HTML files by Bootstrap basically.
- `data.db`: The SQLite database file.
- `dev.bat` A simple script that you can run with `./dev` to start the development server and keep HMR.

## OTPs?

One-time passwords (OTPs) are a type of authentication mechanism that is used to verify the identity of a user. They are typically used in situations where a user needs to provide a password or a one-time code to access a service or resource.
This is accomplished securely by giving the user a simple secret of some arbitrary characters, along with some other metadata, through a URI usually in the form of a QR code that the user can scan with applications like this very very application, if only it was able to capture URI intents. But for simplicity, we are just using the secrets that the websites can offer, or basically you can extract them if from the QR code, if you could scan it with something other than your Authenticator app.

## The flow

Storing such sensitive data should be done securely, and the best way to do that is to encrypt it with a key that is known only to the user. This is the user's password in our case.
But to add an extra layer of security, we can hash the user's password with a key that is known only to the server.
In our case, the server's key is the user's password, and his secrets are encrypted with the hashed password. And the only way to obtain the secrets is to enter the write password at login time.

## `POST` endpoints

There are a few endpoints that are used to handle users' actions.

- `/login`: This endpoint is used to handle user login. It accepts a POST request with the user's username and password. If the login is successful (through the successful decryption of users' secrets), the user is redirected to the home page (`'/'`). If the login is unsuccessful, the user is redirected to the login page.
- `/register`: This endpoint is used to handle user registration. It accepts a POST request with the user's username and password (and password confirmation). If the registration is successful, the user is redirected to the `login` page. If the registration is unsuccessful, the user is redirected to the register page for a second try.
- `/add_secret`: This endpoint is used to handle the addition of new OTPs. It accepts a POST request with the secret details. If the addition is successful, the user is redirected to the home page to see all his available OTPs.
- `/account`: This endpoint is used to handle the viewing of the user's account through a `GET` request. Two other endpoints handle the `change_username` and `change_password` respectively, with a `POST` request.
- `/delete_secret`: This endpoint is used to handle the deletion of OTPs. It accepts a POST request with the ID of the secret. If the deletion is successful, the user is redirected to the home page again.
- `/logout`: This endpoint is used to handle user logout. It can also accepts a GET request and redirects the user to the login page.
- `next_counter`: This endpoint is used to change the counter of a counter-based OTPs. It accepts a POST request with the ID of the secret.

## Anatomy of an OTP

The OTP can be generated using only the secret, but other information is also required, most of them are optional and only help organize your secrets.
The URI for an OTP looks something like this:

```bash
otpauth://totp/Example.com%20USER_123?secret=ABCD123EFG&issuer=example.com&algorithm=sha1&digits=6&period=30
```

Remember that the only required field is the `secret`.

Namely, the following information is can be used to generate an OTP:

- `type`: The type of the OTP. It can be:
  - `hotp` or `counter`-based OTP (The `h` comes from `HMAC`, which is the name of the algorithm used to generate the OTP).
  - `totp` (default) or `time`-based OTP, and this is the most common type.
- `secret`: The secret is the only <strong>required</strong> field. It is the actual secret that is used to generate the OTP.
- `label`: The label is the name of the OTP. It is usually a combination of the website name and the account name (e.g. `Google: Jason@example.com`).
- `issuer`: The issuer is the name of the service that is using the OTP. It is usually the name of the website that required you to obtain an OTP for your future sign-in attempts.
- `name`: The name is the name of your account on that website that is requiring the OTP. Both name and issuer can be used to generate the label for your OTP in OTP managers like Google Authenticator and 1Password.
- `algorithm`: The algorithm used to generate the OTP. It can either be `SHA1` (default), `SHA256`, or `SHA512` only.
- `digits`: The number of digits in the OTP. It can be either `6` (default), `7`, or `8`.
- `counter`: (`hotp` only) The counter is used to generate the OTP for counter-based OTPs. It is usually a number that is incremented every time the OTP is generated.
- `period`: (`totp` only) The period is used to generate the OTP for time-based OTPs. It is usually a number that is used to calculate the time difference between the current time and the time of the last OTP generation. It can either be `15`, `30` (default), or `60` seconds.

<style>
  h1,h2,h3,h4,h5,h6 {
    text-transform: capitalize;
  }
</style>
