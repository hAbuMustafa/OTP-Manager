# MFA Manager

This app will serve as an alternative to Google Authenticator.

## Features

- [ ] Save secrets encrypted to generate 2FA codes
- [ ] display OTP tokens for each account
- [ ] Allow adding new accounts
- [ ] Allow editing of accounts
- [ ] all stored data are encrypted by user's salted password
- [ ] Allow import of data from a text file
- [ ] Allow export of data to a text file

## Flow

- Sign in
  - Decrypt data
    - Success? -> Home
    - Fail? -> Sign in
