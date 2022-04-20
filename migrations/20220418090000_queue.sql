-- See https://kerkour.com/rust-job-queue-with-postgresql

create table queue (
  id uuid primary key,
  created_at timestamp with time zone not null,
  updated_at timestamp with time zone not null,

  scheduled_for timestamp with time zone not null,
  failed_attempts int not null,
  status int not null,
  message jsonb not null
);

create index index_queue_on_scheduled_for on queue (scheduled_for);
create index index_queue_on_status on queue (status);