# Vulnerability Scanner Backend

Complete backend API for web vulnerability scanning application.

## Features

- User authentication (JWT)
- Vulnerability scanning (20+ checks)
- Scan history management
- Rate limiting
- DynamoDB storage
- Freemium model (3 scans/month)

## Setup

### 1. Install Dependencies

npm install
pip3 install -r requirements.txt


### 2. Configure Environment

Copy `.env.example` to `.env` and fill in values:

cp .env.example .env


### 3. Create DynamoDB Tables

