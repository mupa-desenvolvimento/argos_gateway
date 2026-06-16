create table if not exists remote_sessions (
  id bigserial primary key,
  device_id text not null,
  user_id text not null,
  started_at timestamptz not null default now(),
  ended_at timestamptz null,
  duration integer null,
  ip inet null,
  status text not null default 'started'
);

create index if not exists idx_remote_sessions_device_started on remote_sessions (device_id, started_at desc);
create index if not exists idx_remote_sessions_user_started on remote_sessions (user_id, started_at desc);
