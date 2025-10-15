-- ABC MUN Supabase Schema (public)
-- Run this in Supabase SQL editor. Ensure a Storage bucket named 'documents' exists and is public.

-- Enable UUID extension if needed
create extension if not exists "uuid-ossp";

-- Profiles table extending auth.users
create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  surname text not null,
  phone_number text,
  is_admin boolean not null default false,
  assigned_country text unique,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;$$;

drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch before update on public.profiles
for each row execute function public.touch_updated_at();

-- Countries reference table with unique assignment
create table if not exists public.countries (
  name text primary key,
  assigned_user uuid unique references auth.users(id) on delete set null
);

-- Seed common MUN countries (extend as needed)
insert into public.countries(name)
values
  ('Azerbaijan'),('United Kingdom'),('United States'),('Turkey'),('France'),('Germany'),('Russia'),('China'),('India'),('Japan'),('Italy'),('Spain'),('Brazil'),('Canada'),('Australia')
on conflict do nothing;

-- Documents
create table if not exists public.documents (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  file_name text not null,
  file_url text not null,
  created_at timestamp with time zone default now()
);

-- Messages (private between assigned countries / users)
create table if not exists public.messages (
  id uuid primary key default uuid_generate_v4(),
  sender_user_id uuid not null references auth.users(id) on delete cascade,
  recipient_user_id uuid not null references auth.users(id) on delete cascade,
  sender_country text,
  recipient_country text,
  content text not null check (length(trim(content)) > 0),
  created_at timestamp with time zone default now()
);

-- Notifications (global)
create table if not exists public.notifications (
  id uuid primary key default uuid_generate_v4(),
  content text not null,
  created_at timestamp with time zone default now()
);

-- View for admin documents listing with user names and countries
create or replace view public.documents_with_users as
select d.id,
       d.file_name,
       d.file_url,
       d.created_at,
       p.user_id,
       p.name as user_name,
       p.surname as user_surname,
       p.assigned_country
from public.documents d
join public.profiles p on p.user_id = d.user_id;

-- RLS Policies
alter table public.profiles enable row level security;
alter table public.countries enable row level security;
alter table public.documents enable row level security;
alter table public.messages enable row level security;
alter table public.notifications enable row level security;

-- profiles: users can read their own, admin can read all
create policy "profiles_self_select" on public.profiles
for select using (auth.uid() = user_id or exists (select 1 from public.profiles ap where ap.user_id = auth.uid() and ap.is_admin));

create policy "profiles_self_update" on public.profiles
for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy "profiles_insert_by_service" on public.profiles
for insert with check (true);

-- countries: read all; updates via RPC only (block direct updates)
create policy "countries_select_all" on public.countries for select using (true);
create policy "countries_no_direct_modify" on public.countries for all using (false) with check (false);

-- documents: owner can CRUD own, admin can read all
create policy "documents_owner_crud" on public.documents
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy "documents_admin_read" on public.documents
for select using (exists (select 1 from public.profiles ap where ap.user_id = auth.uid() and ap.is_admin));

-- messages: participants can read, sender can insert
create policy "messages_participants_read" on public.messages
for select using (auth.uid() in (sender_user_id, recipient_user_id) or exists (select 1 from public.profiles ap where ap.user_id = auth.uid() and ap.is_admin));

create policy "messages_sender_insert" on public.messages
for insert with check (auth.uid() = sender_user_id);

-- notifications: everyone can read, admin inserts
create policy "notifications_read" on public.notifications for select using (true);
create policy "notifications_admin_insert" on public.notifications for insert with check (exists (select 1 from public.profiles ap where ap.user_id = auth.uid() and ap.is_admin));

-- Random unique country assignment helper
create or replace function public.assign_random_country(p_user uuid)
returns text
language plpgsql
security definer
as $$
declare
  chosen text;
begin
  select name into chosen from public.countries c
  where c.assigned_user is null
  order by random()
  limit 1;
  if chosen is null then
    raise exception 'No countries available';
  end if;
  update public.countries set assigned_user = p_user where name = chosen and assigned_user is null;
  if not found then
    -- race; try again
    return assign_random_country(p_user);
  end if;
  update public.profiles set assigned_country = chosen where user_id = p_user;
  return chosen;
end$$;

-- RPC: create profile (called from client if missing)
create or replace function public.create_profile(
  p_user_id uuid,
  p_name text,
  p_surname text,
  p_phone text
)
returns public.profiles
language plpgsql
security definer
as $$
declare
  prof public.profiles;
begin
  insert into public.profiles(user_id,name,surname,phone_number)
  values (p_user_id, p_name, p_surname, p_phone)
  on conflict (user_id) do update set name=excluded.name, surname=excluded.surname, phone_number=excluded.phone_number
  returning * into prof;
  perform public.assign_random_country(p_user_id);
  select * into prof from public.profiles where user_id = p_user_id;
  return prof;
end$$;

-- RPC: admin send notification
create or replace function public.admin_send_notification(p_content text)
returns void
language plpgsql
security definer
as $$
begin
  if not exists (select 1 from public.profiles where user_id = auth.uid() and is_admin) then
    raise exception 'Not authorized';
  end if;
  insert into public.notifications(content) values (p_content);
end$$;

-- RPC: admin set country for a user with uniqueness enforcement
create or replace function public.admin_set_country(p_user_id uuid, p_country text)
returns void
language plpgsql
security definer
as $$
declare
  cur text;
begin
  if not exists (select 1 from public.profiles where user_id = auth.uid() and is_admin) then
    raise exception 'Not authorized';
  end if;

  -- Free previous assignment for this user
  select assigned_country into cur from public.profiles where user_id = p_user_id;
  if cur is not null then
    update public.countries set assigned_user = null where name = cur;
  end if;

  if p_country is null then
    update public.profiles set assigned_country = null where user_id = p_user_id;
    return;
  end if;

  -- Ensure target country free
  update public.countries set assigned_user = p_user_id where name = p_country and assigned_user is null;
  if not found then
    raise exception 'Country is already assigned';
  end if;

  update public.profiles set assigned_country = p_country where user_id = p_user_id;
end$$;

-- Trigger: when a user is deleted, free the country (on cascade handles profiles, but free mapping too)
create or replace function public.free_country_on_profile_delete()
returns trigger language plpgsql as $$
begin
  if old.assigned_country is not null then
    update public.countries set assigned_user = null where name = old.assigned_country;
  end if;
  return old;
end$$;

drop trigger if exists profiles_free_country on public.profiles;
create trigger profiles_free_country after delete on public.profiles
for each row execute function public.free_country_on_profile_delete();


