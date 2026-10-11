CREATE TABLE IF NOT EXISTS finance_accounts (
  id text PRIMARY KEY,
  email text NOT NULL UNIQUE,
  owner_name text NOT NULL,
  account_number text NOT NULL UNIQUE,
  password_salt text NOT NULL,
  password_hash text NOT NULL,
  balance bigint NOT NULL CHECK (balance >= 0),
  currency char(3) NOT NULL DEFAULT 'VND',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finance_beneficiaries (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES finance_accounts(id) ON DELETE CASCADE,
  display_name text NOT NULL,
  account_number text NOT NULL,
  bank_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (account_id, account_number)
);

CREATE TABLE IF NOT EXISTS finance_transactions (
  id text PRIMARY KEY,
  account_id text NOT NULL REFERENCES finance_accounts(id) ON DELETE CASCADE,
  transfer_id text,
  kind text NOT NULL CHECK (kind IN ('salary', 'purchase', 'refund', 'transfer_in', 'transfer_out', 'bill')),
  merchant text NOT NULL,
  description text NOT NULL,
  amount bigint NOT NULL CHECK (amount <> 0),
  created_at timestamptz NOT NULL,
  reference text NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS finance_transactions_account_date_idx
  ON finance_transactions (account_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS finance_transactions_account_merchant_idx
  ON finance_transactions (account_id, merchant);

CREATE TABLE IF NOT EXISTS finance_sessions (
  token_hash text PRIMARY KEY,
  account_id text NOT NULL REFERENCES finance_accounts(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finance_sessions_expiry_idx ON finance_sessions (expires_at);

CREATE TABLE IF NOT EXISTS finance_transfer_requests (
  idempotency_key text PRIMARY KEY,
  account_id text NOT NULL REFERENCES finance_accounts(id) ON DELETE CASCADE,
  transfer_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO finance_accounts (id, email, owner_name, account_number, password_salt, password_hash, balance)
VALUES
  ('acct-an-2048', 'an.demo@northstar.test', 'Nguyễn Minh An', 'NS-2048-7712', 'northstar-demo-an-v1', '', 84560000),
  ('acct-linh-3106', 'linh.demo@northstar.test', 'Trần Khánh Linh', 'NS-3106-4821', 'northstar-demo-linh-v1', '', 32675000),
  ('acct-quang-5821', 'quang.demo@northstar.test', 'Lê Minh Quang', 'NS-5821-9064', 'northstar-demo-quang-v1', '', 120480000)
ON CONFLICT (id) DO NOTHING;

INSERT INTO finance_beneficiaries (id, account_id, display_name, account_number, bank_name)
VALUES
  ('bene-an-1', 'acct-an-2048', 'Công ty Điện lực miền Nam', 'EVN-4581-2903', 'Ngân hàng Phương Nam'),
  ('bene-an-2', 'acct-an-2048', 'O''Connor Market', 'NS-8831-1702', 'Northstar Bank'),
  ('bene-an-3', 'acct-an-2048', 'Trần Khánh Linh', 'NS-3106-4821', 'Northstar Bank'),
  ('bene-linh-1', 'acct-linh-3106', 'Nguyễn Minh An', 'NS-2048-7712', 'Northstar Bank'),
  ('bene-quang-1', 'acct-quang-5821', 'Nhà sách Bến Thành', 'NS-2914-6620', 'Ngân hàng Phương Nam')
ON CONFLICT (id) DO NOTHING;

INSERT INTO finance_transactions (id, account_id, kind, merchant, description, amount, created_at, reference)
VALUES
  ('tx-an-001', 'acct-an-2048', 'salary', 'Northstar Demo', 'Lương tháng 10', 48000000, '2026-10-01T02:30:00Z', 'REF-AN-20261001-01'),
  ('tx-an-002', 'acct-an-2048', 'purchase', 'O''Connor Market', 'Thực phẩm và nhu yếu phẩm', -186000, '2026-10-02T10:14:00Z', 'REF-AN-20261002-02'),
  ('tx-an-003', 'acct-an-2048', 'bill', 'Điện lực miền Nam', 'Hóa đơn điện tháng 9', -742500, '2026-10-03T04:22:00Z', 'REF-AN-20261003-03'),
  ('tx-an-004', 'acct-an-2048', 'refund', 'Mây Home', 'Hoàn tiền đơn hàng', 320000, '2026-10-04T08:05:00Z', 'REF-AN-20261004-04'),
  ('tx-an-005', 'acct-an-2048', 'purchase', 'Cà phê Sông Xanh', 'Thanh toán tại cửa hàng', -85000, '2026-10-05T01:48:00Z', 'REF-AN-20261005-05'),
  ('tx-an-006', 'acct-an-2048', 'transfer_out', 'Trần Khánh Linh', 'Chuyển khoản cá nhân', -2500000, '2026-10-06T13:17:00Z', 'REF-AN-20261006-06'),
  ('tx-an-007', 'acct-an-2048', 'purchase', 'Nhà sách Bến Thành', 'Sách và văn phòng phẩm', -234000, '2026-10-07T06:33:00Z', 'REF-AN-20261007-07'),
  ('tx-an-008', 'acct-an-2048', 'purchase', 'O''Connor Market', 'Đồ dùng gia đình', -128000, '2026-10-08T11:09:00Z', 'REF-AN-20261008-08'),
  ('tx-an-009', 'acct-an-2048', 'bill', 'Cấp nước thành phố', 'Hóa đơn nước tháng 9', -166000, '2026-10-09T03:51:00Z', 'REF-AN-20261009-09'),
  ('tx-linh-001', 'acct-linh-3106', 'salary', 'Mộc Design Studio', 'Thu nhập dự án tháng 10', 21500000, '2026-10-01T03:20:00Z', 'REF-LINH-20261001-01'),
  ('tx-linh-002', 'acct-linh-3106', 'purchase', 'Chợ Bến Thành', 'Thực phẩm', -394000, '2026-10-03T09:12:00Z', 'REF-LINH-20261003-02'),
  ('tx-linh-003', 'acct-linh-3106', 'refund', 'Nhà sách Bến Thành', 'Điều chỉnh đơn hàng', 115000, '2026-10-05T12:47:00Z', 'REF-LINH-20261005-03'),
  ('tx-quang-001', 'acct-quang-5821', 'salary', 'Đại học Nam Sài Gòn', 'Lương tháng 10', 36500000, '2026-10-01T01:15:00Z', 'REF-QUANG-20261001-01'),
  ('tx-quang-002', 'acct-quang-5821', 'purchase', 'Hải sản Cầu Mống', 'Mua thực phẩm', -648000, '2026-10-06T07:28:00Z', 'REF-QUANG-20261006-02')
ON CONFLICT (id) DO NOTHING;
