-- BDK wallet state, as an append-only log of changesets merged on load.
CREATE TABLE bdk_changesets (
    id BIGSERIAL PRIMARY KEY,
    changeset JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- What each quote may be paid out to, registered when the quote is made.
CREATE TABLE bindings (
    withdrawal_id TEXT PRIMARY KEY,
    l2_index BIGINT NOT NULL UNIQUE,
    l1_destination TEXT NOT NULL,
    l1_sats BIGINT NOT NULL CHECK (l1_sats > 0),
    l2_sats BIGINT NOT NULL CHECK (l2_sats > l1_sats),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- One row per paid withdrawal. The signed transaction is stored before it is
-- broadcast, and each L2 payment and receive index can fund one payout only.
CREATE TABLE payouts (
    -- Signing order: a payout may spend an earlier one's change.
    id BIGSERIAL UNIQUE,
    withdrawal_id TEXT PRIMARY KEY,
    l2_index BIGINT NOT NULL UNIQUE,
    l2_txid TEXT NOT NULL,
    l2_vout BIGINT NOT NULL,
    l2_sats BIGINT NOT NULL CHECK (l2_sats > 0),
    l1_destination TEXT NOT NULL,
    l1_sats BIGINT NOT NULL CHECK (l1_sats > 0),
    fee_sats BIGINT NOT NULL CHECK (fee_sats >= 0),
    -- The current version; fee bumps replace it.
    txid TEXT NOT NULL UNIQUE,
    raw_tx BYTEA NOT NULL,
    -- Esplora tip height when the current version was signed.
    tip_height BIGINT NOT NULL,
    -- Tip height when the first version was signed. A fee bump doesn't reset
    -- it, so a payout that keeps being bumped but never mined still counts as
    -- stuck.
    signed_tip_height BIGINT NOT NULL,
    -- Settled: deep enough that it is no longer rebroadcast.
    confirmed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (l2_txid, l2_vout)
);

CREATE INDEX payouts_created_at ON payouts (created_at);
CREATE INDEX payouts_unconfirmed ON payouts (confirmed) WHERE NOT confirmed;

-- Every version of every payout, so whichever one confirms is recognized.
CREATE TABLE payout_versions (
    txid TEXT PRIMARY KEY,
    withdrawal_id TEXT NOT NULL REFERENCES payouts (withdrawal_id),
    raw_tx BYTEA NOT NULL,
    fee_sats BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX payout_versions_withdrawal ON payout_versions (withdrawal_id);

-- Open alerts, one row per active condition (see the alerts crate).
CREATE TABLE alerts (
    key TEXT PRIMARY KEY,
    message TEXT NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
