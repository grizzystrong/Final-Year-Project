# Setup: Google login + database (about 15 minutes, all free)

The site runs in **demo mode** (two fake users, data kept in your browser) until you do this.

## 1. Create the Supabase project
1. Go to https://supabase.com, sign in, **New project** (any name, pick a region near you, set a database password).
2. Open **SQL Editor -> New query**, paste the whole of `supabase/schema.sql`, click **Run**.

## 2. Create a Google OAuth client
1. Go to https://console.cloud.google.com -> create/select a project.
2. **APIs & Services -> OAuth consent screen**: choose *External*, fill the app name and your email, save. (Add your test users while the app is in *Testing*, or publish it.)
3. **Credentials -> Create credentials -> OAuth client ID -> Web application**.
4. Under **Authorized redirect URIs** add: `https://<your-project-ref>.supabase.co/auth/v1/callback`
   (Supabase shows this exact URL on the Google provider page, copy it from there.)
5. Copy the **Client ID** and **Client secret**.

## 3. Turn Google on in Supabase
1. **Authentication -> Providers -> Google**: enable, paste Client ID and secret, save.
2. **Authentication -> URL Configuration**:
   - **Site URL**: `https://<username>.github.io/<repo-name>/app.html`
   - **Redirect URLs**: add the same URL, plus `http://localhost:8000/app.html` if you test locally.

## 4. Connect the website
1. Supabase -> **Project Settings -> API**: copy the **Project URL** and the **anon public** key.
2. Paste them into `docs/config.js`, commit and push. GitHub Pages redeploys in about a minute.

The anon key is safe to publish: row-level security in the schema means a signed-in user can only read and write their own rows.

## What gets saved per user
`profiles` (name, designated zone), `devices` (the fleet and each device's slot), `device_state` (live trust factors, so scoring resumes where it stopped) and `trust_history` (time series for the charts).
