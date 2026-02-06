# Deploying backend on Railway

## 1. Set environment variables in Railway

The `.env` file is **not** in the repo, so you **must** set all variables in Railway:

- **Railway** → your project → **backend service** → **Variables** (or **Settings** → **Variables**).

Add these (replace with your real values):

| Variable | Example / notes |
|----------|------------------|
| `JWT_SECRET` | Any long random string (e.g. `your-super-secret-key-here`) |
| `FIREBASE_PROJECT_ID` | Your Firebase project ID |
| `FIREBASE_CLIENT_EMAIL` | From Firebase service account JSON, e.g. `firebase-adminsdk-xxxxx@project.iam.gserviceaccount.com` |
| `FIREBASE_PRIVATE_KEY` | See below |

**Do not** set `PORT` unless you need to; Railway sets it (e.g. 8080).

---

## 2. FIREBASE_PRIVATE_KEY format (fixes "DECODER routines::unsupported")

The private key must be a **single string** with **newlines as `\n`** (backslash + n), not actual line breaks.

**Option A – One line (recommended)**  
From your Firebase service account JSON, the `private_key` value looks like:

```
"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq...\n-----END PRIVATE KEY-----\n"
```

In Railway Variables, paste that **entire value** including the quotes, or paste **without** the outer quotes but **keep every `\n`** so it stays one line. Example:

```
-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANB...\n-----END PRIVATE KEY-----\n
```

**Option B – Multi-line**  
If Railway allows multi-line variables, you can paste the key with real newlines (each line on its own). The code will still work.

**What goes wrong**  
- Pasting the key with real newlines can break if the platform strips or changes them.  
- Extra or wrong quotes can cause `DECODER routines::unsupported`.  
- So prefer **one line with `\n`** in Railway.

---

## 3. Redeploy

After saving the variables, Railway will redeploy. Check **Deployments** → latest deployment → **View logs**. You should see:

`QSafe backend listening on port 8080`

and no Firebase/grpc errors.

---

## 4. Quick check

Open in a browser (or curl):

`https://quantum-auth-mobile-backend-production.up.railway.app/health`

You should get: `{"status":"ok","service":"qsafe-backend"}`.
