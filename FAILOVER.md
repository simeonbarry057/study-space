# Study Space failover plan

**Purpose.** If Vercel suspends the account, the site can run on another host (Render, free plan) using the data kept at Upstash, until the Vercel problem is cleared. Then you move back.

## Prepare now (once)

1. **Save these secrets in your password manager.** Vercel hides "Sensitive" values, so you cannot read them back later. The standby needs the same values: `SESSION_SECRET` (it also protects the stored security codes, so it must be identical), `OWNER_EMAIL`, `OWNER_SETUP_CODE`, `NOTIFY_TOKEN`, `CRON_SECRET`, `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`, `RESEND_API_KEY`, `GMAIL_USER`, `GMAIL_APP_PASSWORD` (when set).
2. **Optional: create a free Render account** (render.com, sign in with GitHub) so it is ready.
3. **Strongly recommended: get your own web address** (for example gdthat.com). A `vercel.app` address stops working when Vercel suspends you, so learners would need a new link. With your own address you only change one DNS record to point at the standby, and learners notice nothing. The same domain is also needed for learner emails.

## If Vercel suspends the site

1. In Render choose **New, then Blueprint**, pick the `study-space` GitHub repo, and it reads `render.yaml`.
2. Fill in the secret values from your password manager. Set `SITE_URL` to the standby's address (or your own domain).
3. Wait for it to go live. Open `/healthz` (should say `ok`), then sign in as yourself.
4. Point learners at the new address (or switch your domain's DNS record to Render).
5. Ask Claude to repoint the scheduled tasks (alerts, 3-hourly backup, review) at the new address.

Notes: the free Render plan sleeps after 15 minutes without visits (the first visit takes about a minute to wake it). For a long outage use a paid plan (about $7 a month). While on the standby, only Upstash receives changes; the 3-hourly Drive backups continue once repointed.

## Moving back to Vercel

1. Clear the suspension with Vercel and confirm the site is up again.
2. On your computer run the resync (it copies everything from Upstash into the two Vercel stores and removes records deleted meanwhile). First a dry run, then the real thing:
   ```
   UPSTASH_REDIS_REST_URL=... UPSTASH_REDIS_REST_TOKEN=... \
   BLOB_READ_WRITE_TOKEN=... BLOB_MIRROR_READ_WRITE_TOKEN=... \
   node scripts/resync.js
   node scripts/resync.js --go
   ```
3. Point learners (or your domain) back at Vercel, and have Claude repoint the scheduled tasks.
4. Pause or delete the Render service.

## Files

`standby/server.js` (the standby server), `render.yaml`, `Dockerfile` (for any other host), `scripts/resync.js` (move back), `scripts/restore.js` (restore from a Drive backup file).
