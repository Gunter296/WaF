ALTER TABLE finance_accounts
  ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conname = 'finance_accounts_role_check'
       AND conrelid = 'finance_accounts'::regclass
  ) THEN
    ALTER TABLE finance_accounts
      ADD CONSTRAINT finance_accounts_role_check CHECK (role IN ('user', 'admin'));
  END IF;
END $$;
