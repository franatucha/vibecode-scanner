create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  credit_card_last4 text
);

create table public.posts (
  id bigserial primary key,
  author uuid references public.profiles,
  body text
);

alter table public.posts enable row level security;
