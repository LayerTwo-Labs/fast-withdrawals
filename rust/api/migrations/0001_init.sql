-- Receive address indexes for the Thunder xpub. Never reused, gaps are fine.
CREATE SEQUENCE l2_index_seq START 1;

-- Status values match fastwithdraw.v1.WithdrawalStatus.
CREATE TABLE withdrawals (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    request_hash BYTEA NOT NULL,
    -- Who asked for the quote (their rate-limit key: an IPv4 address or an
    -- IPv6 /64), to cap open quotes per client. Cleared once the quote is no
    -- longer open.
    client_key TEXT,
    sidechain TEXT NOT NULL,
    l2_index BIGINT NOT NULL UNIQUE,
    l2_address TEXT NOT NULL UNIQUE,
    l2_payment_sats BIGINT NOT NULL CHECK (l2_payment_sats > 0),
    l1_destination TEXT NOT NULL,
    l1_payout_sats BIGINT NOT NULL CHECK (l1_payout_sats > 0),
    service_fee_sats BIGINT NOT NULL CHECK (service_fee_sats >= 0),
    payout_reserve_sats BIGINT NOT NULL CHECK (payout_reserve_sats >= l1_payout_sats),
    required_confirmations INTEGER NOT NULL CHECK (required_confirmations > 0),
    status INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    payment_txid TEXT,
    payment_vout BIGINT,
    payment_confirmations INTEGER,
    -- Where the payment was mined; re-verified before use.
    payment_block_height BIGINT,
    payment_block_hash TEXT,
    -- When the payment reached its required confirmations, so a payout that
    -- doesn't follow can be noticed.
    confirmed_at TIMESTAMPTZ,
    -- Underpaid withdrawals: what the payment paid, and where the customer
    -- wants it refunded.
    received_sats BIGINT,
    refund_address TEXT,
    -- An underpayment a full payment replaced, restored if that payment
    -- leaves the chain.
    underpaid_txid TEXT,
    underpaid_vout BIGINT,
    payout_txid TEXT,
    -- The wallet stopped watching the payout; its txid is final.
    payout_settled BOOLEAN NOT NULL DEFAULT false,
    -- Why the wallet refused the payout, for FAILED withdrawals.
    failure_reason TEXT,
    quote_signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (payment_txid, payment_vout)
);

CREATE INDEX withdrawals_status ON withdrawals (status);
CREATE INDEX withdrawals_client_key ON withdrawals (client_key) WHERE client_key IS NOT NULL;

-- Quotes whose addresses tick watches for payments (`store::WATCHED`).
CREATE INDEX withdrawals_watched ON withdrawals (status, expires_at)
    WHERE status IN (1, 5) OR (status = 7 AND refund_address IS NULL);

-- Open alerts, one row per active condition (see the alerts crate).
CREATE TABLE alerts (
    key TEXT PRIMARY KEY,
    message TEXT NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
