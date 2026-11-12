# Kobra Follow API — starter

A small local API foundation for the Android starter project.

## Run locally
- Install Node.js 20+
- Run `npm install`
- Run `npm start`
- Health check: `GET http://localhost:3000/health`

## Endpoints
- `POST /api/users` — create a demo user: `{ "username": "kobra_user" }`
- `GET /api/users/:id/wallet` — wallet and recent transactions
- `GET /api/tasks?platform=instagram` — active task list
- `POST /api/requests` — queue a campaign request
- `GET /api/requests/:userId` — list a user's requests

## Important
This is a development scaffold, not production-ready. It has no login/session system, admin authentication, payment integration, deployment configuration, or rate limiting. Do not expose it publicly or store real user data until those are added and reviewed.

The request endpoint only queues records. It does not automate fake engagement, bulk follows/likes, credential collection, or bypass platform safeguards. Any Instagram/TikTok integration must use official permitted APIs and user-authorized flows.
