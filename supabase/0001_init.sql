-- ============================================================================
-- Shared Library Books — database setup (Supabase)
-- ----------------------------------------------------------------------------
-- HOW TO RUN: Supabase Dashboard → SQL Editor → New query → paste this whole
-- file → Run. Run it ONCE. It is safe to run twice (IF NOT EXISTS guards).
--
-- BEFORE YOU RUN IT: nothing to edit in this file. The one thing you do
-- afterwards is in step 2b below (make yourself the first admin).
--
-- AFTER YOU RUN IT:
--   2a. Create your own login: Dashboard → Authentication → Users →
--       Add user → your email + a password → tick "Auto Confirm User".
--   2b. Back in the SQL Editor, run this one line (with your email):
--       update public.profiles set role = 'admin'
--         where email = 'YOUR_EMAIL_HERE';
--       You are now the admin. From then on, accounts and roles are managed
--       inside the app's Users page — no dashboard needed.
--
-- WHAT THIS FILE CREATES:
--   profiles    one row per account = one child (nickname, age, role, active)
--   books       the shared catalogue (one row per book, one cover per book)
--   child_books which child has read which book + report-submitted flag
--   comments    one English + one Traditional Chinese comment per child/book
--   covers      Storage bucket holding one cover image per book
--   Row Level Security on everything, enforcing the roles table in the guide:
--     admin     everything, incl. users, roles, CSV import, clear library
--     moderator edit/delete any book and book data; remove (not edit) comments
--     user      add books; edit books they added (never delete); tag own child;
--               own comments + report flag; read all parents' comments
--   Profile changes (role, active, nickname, age) go through the small
--   functions at the end — there is no direct UPDATE on profiles, so a user
--   can never promote themselves by editing their own row.
--
-- ORDER MATTERS (fixed 2026-11-05): the tables are created FIRST. The helper
-- functions below read the profiles table, and PostgreSQL checks those
-- functions when they are created — creating them first failed with
-- "relation public.profiles does not exist" and nothing was created.
--
-- NOTE ON COVERS: the covers bucket is PUBLIC for reading. A book cover is a
-- public catalogue image (the same picture Open Library shows anyone), so
-- the shelf can load it with a plain <img> tag. Everything about children —
-- names, tags, comments, report flags — stays behind login + Row Level
-- Security and is never in the bucket. Uploading, replacing and deleting
-- covers are still permission-checked (see the storage policies below).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Tables (first — everything else refers to them)
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null,
  child_nickname text not null default '',
  child_age int,
  role text not null default 'user'
    check (role in ('admin', 'moderator', 'user')),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.books (
  id uuid primary key default gen_random_uuid(),
  title_en text not null default '',
  title_zh text not null default '',
  author text not null default '',
  illustrator text default '',
  translator text default '',
  publisher text default '',
  isbn text default '',
  hkpl_serial_number text default '',
  story_en text default '',
  story_zh text default '',
  notes text default '',
  cover_key text,
  cover_status text not null default 'needs_review'
    check (cover_status in ('ok', 'needs_review', 'placeholder')),
  added_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint title_present check (title_en <> '' or title_zh <> '')
);

-- One copy of a book (one HKPL serial number) can only be in the catalogue
-- once. Blank serials are exempt, so books added without one are unaffected.
create unique index if not exists books_serial_unique
  on public.books (hkpl_serial_number)
  where hkpl_serial_number <> '';
create index if not exists books_isbn_idx on public.books (isbn);
create index if not exists books_added_by_idx on public.books (added_by);
create index if not exists books_cover_status_idx on public.books (cover_status);

create table if not exists public.child_books (
  child_id uuid not null references public.profiles (id) on delete cascade,
  book_id uuid not null references public.books (id) on delete cascade,
  report_submitted boolean not null default false,
  report_updated_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (child_id, book_id)
);
create index if not exists child_books_book_idx on public.child_books (book_id);

create table if not exists public.comments (
  id uuid primary key default gen_random_uuid(),
  child_id uuid not null references public.profiles (id) on delete cascade,
  book_id uuid not null references public.books (id) on delete cascade,
  comment_en text not null default '',
  comment_tc text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint one_comment_per_child_book unique (child_id, book_id)
);
create index if not exists comments_book_idx on public.comments (book_id);

create or replace function public.set_updated_at()
returns trigger
language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();
drop trigger if exists books_set_updated_at on public.books;
create trigger books_set_updated_at
  before update on public.books
  for each row execute function public.set_updated_at();
drop trigger if exists comments_set_updated_at on public.comments;
create trigger comments_set_updated_at
  before update on public.comments
  for each row execute function public.set_updated_at();

-- ---------------------------------------------------------------------------
-- Helper functions (SECURITY DEFINER so they can read profiles without
-- tripping over Row Level Security; they only ever answer about the caller)
-- ---------------------------------------------------------------------------
create or replace function public.my_role()
returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid();
$$;

create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'admin'
  );
$$;

create or replace function public.is_mod()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role in ('admin', 'moderator')
  );
$$;

create or replace function public.is_active()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and active is true
  );
$$;

-- ---------------------------------------------------------------------------
-- New account → profile row (runs when a login is created, in the dashboard
-- or by the admin inside the app; the app then fills in nickname and age)
-- ---------------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.books enable row level security;
alter table public.child_books enable row level security;
alter table public.comments enable row level security;

-- profiles: any active logged-in user can read the list (names are needed to
-- show who wrote each comment). No direct UPDATE/INSERT/DELETE policies:
-- changes go through the functions at the end of this file.
drop policy if exists "profiles readable by active users" on public.profiles;
create policy "profiles readable by active users"
  on public.profiles for select to authenticated
  using (public.is_active());

-- books: everyone logged in reads; anyone active adds; edit = admin/mod or
-- the parent who added it; delete = admin/mod only.
drop policy if exists "books readable by active users" on public.books;
create policy "books readable by active users"
  on public.books for select to authenticated
  using (public.is_active());

drop policy if exists "books added by active users" on public.books;
create policy "books added by active users"
  on public.books for insert to authenticated
  with check (public.is_active() and added_by = auth.uid());

drop policy if exists "books edited by admin, moderator or adder" on public.books;
create policy "books edited by admin, moderator or adder"
  on public.books for update to authenticated
  using (public.is_active() and (public.is_mod() or added_by = auth.uid()))
  with check (public.is_active() and (public.is_mod() or added_by = auth.uid()));

drop policy if exists "books deleted by admin or moderator" on public.books;
create policy "books deleted by admin or moderator"
  on public.books for delete to authenticated
  using (public.is_mod());

-- child_books (tags + report flag): a parent sees and changes only their own
-- child's rows; admin/mod see and change all.
drop policy if exists "tags readable by owner, admin or moderator" on public.child_books;
create policy "tags readable by owner, admin or moderator"
  on public.child_books for select to authenticated
  using (public.is_active() and (child_id = auth.uid() or public.is_mod()));

drop policy if exists "tags added for own child" on public.child_books;
create policy "tags added for own child"
  on public.child_books for insert to authenticated
  with check (public.is_active() and child_id = auth.uid());

drop policy if exists "tags changed for own child" on public.child_books;
create policy "tags changed for own child"
  on public.child_books for update to authenticated
  using (public.is_active() and child_id = auth.uid())
  with check (child_id = auth.uid());

drop policy if exists "tags removed by owner, admin or moderator" on public.child_books;
create policy "tags removed by owner, admin or moderator"
  on public.child_books for delete to authenticated
  using (public.is_active() and (child_id = auth.uid() or public.is_mod()));

-- comments: every logged-in parent reads every comment (reference, per the
-- plan); only the author writes or edits their own; author, admin or
-- moderator can delete.
drop policy if exists "comments readable by active users" on public.comments;
create policy "comments readable by active users"
  on public.comments for select to authenticated
  using (public.is_active());

drop policy if exists "comments added for own child" on public.comments;
create policy "comments added for own child"
  on public.comments for insert to authenticated
  with check (public.is_active() and child_id = auth.uid());

drop policy if exists "comments edited by their author" on public.comments;
create policy "comments edited by their author"
  on public.comments for update to authenticated
  using (public.is_active() and child_id = auth.uid())
  with check (child_id = auth.uid());

drop policy if exists "comments deleted by author, admin or moderator" on public.comments;
create policy "comments deleted by author, admin or moderator"
  on public.comments for delete to authenticated
  using (public.is_active() and (child_id = auth.uid() or public.is_mod()));

-- ---------------------------------------------------------------------------
-- Cover storage (bucket 'covers', one file per book: <book-id>.jpg)
-- Reading is public (covers are public catalogue images — see the note at the
-- top). Writing is permission-checked: anyone active may ADD a cover where a
-- book has none; replacing or removing one is admin/mod only.
-- ---------------------------------------------------------------------------
insert into storage.buckets (id, name, public)
values ('covers', 'covers', true)
on conflict (id) do nothing;

-- NOTE: there is deliberately NO "alter table storage.objects enable row
-- level security" line here. Supabase already enables RLS on
-- storage.objects by default, and since a 2025 platform change, altering
-- tables in the storage schema is no longer permitted ("must be owner of
-- table objects"). Creating the policies below still works.

drop policy if exists "covers readable by anyone" on storage.objects;
create policy "covers readable by anyone"
  on storage.objects for select to public
  using (bucket_id = 'covers');

drop policy if exists "covers added where a book has none" on storage.objects;
create policy "covers added where a book has none"
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'covers'
    and public.is_active()
    and storage.filename(name) ~ '^[0-9a-f-]{36}\.jpg$'
    and exists (
      select 1 from public.books
      where id::text = regexp_replace(storage.filename(name), '\.jpg$', '')
        and cover_key is null
    )
  );

drop policy if exists "covers replaced by admin or moderator" on storage.objects;
create policy "covers replaced by admin or moderator"
  on storage.objects for update to authenticated
  using (bucket_id = 'covers' and public.is_mod())
  with check (bucket_id = 'covers' and public.is_mod());

drop policy if exists "covers removed by admin or moderator" on storage.objects;
create policy "covers removed by admin or moderator"
  on storage.objects for delete to authenticated
  using (bucket_id = 'covers' and public.is_mod());

-- ---------------------------------------------------------------------------
-- Profile changes — the only way roles, active flags and names change.
-- The app calls these; nobody updates profiles directly.
-- ---------------------------------------------------------------------------
-- A parent edits their own child's nickname and age.
create or replace function public.update_own_profile(nickname text, age int)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not logged in'; end if;
  update public.profiles
  set child_nickname = nickname, child_age = age
  where id = auth.uid();
end;
$$;

-- Admin: change a user's role (admin / moderator / user).
create or replace function public.admin_set_role(target_id uuid, new_role text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if new_role not in ('admin', 'moderator', 'user') then
    raise exception 'unknown role';
  end if;
  -- The last admin cannot demote themselves.
  if target_id = auth.uid() and new_role <> 'admin' then
    if (select count(*) from public.profiles where role = 'admin') <= 1 then
      raise exception 'cannot remove the last admin';
    end if;
  end if;
  update public.profiles set role = new_role where id = target_id;
end;
$$;

-- Admin: disable or re-enable an account (a disabled account can read
-- nothing until it is re-enabled; its data is kept).
create or replace function public.admin_set_active(target_id uuid, make_active boolean)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  if target_id = auth.uid() and not make_active then
    raise exception 'cannot disable your own account';
  end if;
  update public.profiles set active = make_active where id = target_id;
end;
$$;

-- Admin: correct a child's nickname and age.
create or replace function public.admin_update_child(target_id uuid, nickname text, age int)
returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'admin only'; end if;
  update public.profiles
  set child_nickname = nickname, child_age = age
  where id = target_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Done. Verify with: select count(*) from public.books;  (expect 0)
-- and: select * from storage.buckets where id = 'covers'; (expect 1 row)
-- Then do steps 2a–2b at the top of this file.
-- ---------------------------------------------------------------------------
