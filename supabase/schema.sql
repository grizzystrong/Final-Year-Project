-- Run once in Supabase: SQL Editor -> New query -> paste -> Run.
create sequence if not exists zone_seq start 10;

create table if not exists profiles (
  id uuid primary key references auth.users on delete cascade,
  email text, name text, avatar text,
  zone int not null default nextval('zone_seq') unique,   -- each user's designated network segment 10.<zone>.0.0/24
  threat real not null default 0,
  created_at timestamptz not null default now());

create table if not exists devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  name text not null, archetype text not null, criticality real, exposure text, mfa boolean, cert_age int, mac text,
  slot int not null,                                       -- stable position inside the user's zone
  created_at timestamptz not null default now(),
  unique (user_id, slot));

create table if not exists device_state (
  device_id uuid primary key references devices on delete cascade,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  trust real, identity real, reputation real, incident_weight real, in_incident boolean,
  baseline_rpm real, susp real, events int, action text,
  updated_at timestamptz not null default now());

create table if not exists trust_history (
  id bigint generated always as identity primary key,
  device_id uuid not null references devices on delete cascade,
  user_id uuid not null default auth.uid() references auth.users on delete cascade,
  ts timestamptz not null default now(),
  trust real, action text, identity real, behavior real, reputation real, context real, note text);
create index if not exists trust_history_device_ts on trust_history (device_id, ts desc);

-- Row-level security: every user can only ever see and change their own rows.
alter table profiles enable row level security;
alter table devices enable row level security;
alter table device_state enable row level security;
alter table trust_history enable row level security;

create policy "own profile"  on profiles      for all using (id = auth.uid())      with check (id = auth.uid());
create policy "own devices"  on devices       for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own state"    on device_state  for all using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own history"  on trust_history for all using (user_id = auth.uid()) with check (user_id = auth.uid());
