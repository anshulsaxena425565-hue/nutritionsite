ALTER TABLE app_users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'client' CHECK (account_type IN ('client', 'dietitian'));
