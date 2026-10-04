# Surveyra backend

Node.js 22 or newer. No npm install needed (zero dependencies, SQLite built in).

## Run
    node server.js          # http://localhost:3000
    node --no-warnings test.js   # 28 automatic tests

## Environment variables
| Name | Meaning |
|---|---|
| ADMIN_KEY | Secret for admin APIs (send as header `x-admin-key`). Required to use admin. |
| POSTBACK_SECRET_<PROVIDER> | Secret from your survey provider, e.g. POSTBACK_SECRET_CPX |
| TRUST_PROXY=1 | Set when behind Nginx / Render / Railway so real visitor IPs are used |
| NODE_ENV=production | Makes login cookie `Secure` (needs HTTPS) |
| PORT, DATA_DIR | Port and folder for the database (back up DATA_DIR!) |

## API
Users: POST /api/signup, /api/login, /api/logout; GET /api/me, /api/ledger, /api/surveys, /api/leaderboard;
POST /api/surveys/:id/start, /api/surveys/:id/complete {answers:[0,1,2]}; POST /api/bonus;
POST /api/withdraw {method,coins,account}; GET /api/withdrawals

Admin (header x-admin-key): GET /api/admin/withdrawals?status=pending;
POST /api/admin/withdrawals/:id {status:"paid"|"rejected"} (rejected refunds coins);
POST /api/admin/surveys {title,cat,minutes,coins,questions}; POST /api/admin/surveys/:id {active:0|1};
POST /api/admin/users/:id/ban {banned:true}

## Real surveys from a provider
1. Join a provider (CPX Research, BitLabs, TheoremReach...) as a publisher.
2. Set their postback URL to `https://YOURDOMAIN/postback/cpx?user_id={user_id}&trans_id={trans_id}&amount={amount}&status={status}&hash={secure_hash}`
   (use the provider's own placeholder names) and set 1 provider-coin = 1 Surveyra coin.
3. Put the same secret in POSTBACK_SECRET_CPX. Check the provider docs: the signature check in `verifyPostback` may need a small change.
4. Show the provider's survey wall/iframe in the website, passing the logged-in user's id.

## Before going live
- Use HTTPS. Pay withdrawals manually from the admin list, then mark them paid.
- Back up the data folder. Keep ADMIN_KEY and provider secrets private.
- Add Terms, Privacy, and check the rules in the countries of your users.

## Put it online (to get a public test link)
Easiest: Render.com or Railway.app (both have free/cheap plans).
1. Upload this folder to a GitHub repository.
2. Create a new "Web Service" from that repo. Build command: (empty). Start command: `npm start`.
3. Environment variables: `ADMIN_KEY`, `NODE_ENV=production`, `TRUST_PROXY=1`.
4. IMPORTANT: add a persistent disk and set `DATA_DIR` to its path, otherwise the database is erased on every restart.
5. Open the URL they give you. That link is your real test link.

## Run on your own computer
Install Node.js 22+, open a terminal in this folder, run `npm start`, then open http://localhost:3000
