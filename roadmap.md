# MFA Manager

This app will serve as an alternative to Google Authenticator.

## Features

- [x] Save secrets encrypted to generate 2FA codes
- [x] display OTP tokens for each account
- [x] Allow adding new accounts
- [ ] Allow editing of accounts
- [x] all stored data are encrypted by user's password
- [ ] Allow import of data from a text file
- [ ] Allow export of data to a text file
- [ ] Add QR-Code reveal button to allow import to Google Authenticator or the likes
- [ ] Allow updating counter-based tokens by the button

## Flow

- Sign in
  - Decrypt data
    - Success? -> Home
    - Fail? -> Sign in

## Running `Dev`

To run the app in debug mode, simply, run the following command:

```bash
./dev
```

This essentially runs:

```bash
python -m flask --app init.py --debug run
```

This will start the Flask development server and allow `live reload` when you make changes to `python` code or HTML `template files`.

Alternatively, you can run the app in development mode by running the following command:

```bash
python -m flask run
```

This will start the Flask development server but without the `module reload`ing feature.
