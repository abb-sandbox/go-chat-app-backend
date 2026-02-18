# Go Chat App Backend

[![CI Status](https://github.com/AzimBB/go-chat-app-backend/actions/workflows/tests.yml/badge.svg)](https://github.com/AzimBB/go-chat-app-backend/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/AzimBB/go-chat-app-backend)](https://goreportcard.com/report/github.com/AzimBB/go-chat-app-backend)
![Go Version](https://img.shields.io/github/go-mod/go-version/AzimBB/go-chat-app-backend)

## go-chat-app-backend 
Backend API service for chat app 


## Prerequisits 
### Generate the One-Line Hex Key by commands below (Linux/Ubuntu)

Run this command to generate your ECDSA key and immediately output it as a single line of Hex:

```Bash
openssl ecparam -name prime256v1 -genkey -noout -outform DER | xxd -p -c 256
```

What this does:

openssl ... -outform DER: Instead of a PEM file (which has headers and newlines), this creates a binary format.

xxd -p -c 256: This converts that binary data into one long "Plain Hex" string.
