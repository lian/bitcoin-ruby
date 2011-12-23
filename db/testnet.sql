---------------------------------------------------------------------------
-- BASE TYPES
---------------------------------------------------------------------------

DROP DOMAIN IF EXISTS amount_type CASCADE;
CREATE DOMAIN amount_type AS NUMERIC(16, 8) CHECK (VALUE < 21000000 AND VALUE >= 0);
DROP DOMAIN IF EXISTS hash_type CASCADE;
CREATE DOMAIN hash_type AS bytea;  -- 32*3 because "aa 0f ca ..."

CREATE OR REPLACE FUNCTION internal_to_sql(value BIGINT) RETURNS amount_type AS $$
    BEGIN
        RETURN value / CAST(100000000 AS NUMERIC(17, 8));
    END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sql_to_internal(value amount_type) RETURNS BIGINT AS $$
    BEGIN
        RETURN CAST(value * 100000000 AS BIGINT);
    END;
$$ LANGUAGE plpgsql;

---------------------------------------------------------------------------
-- DIFFICULTY
---------------------------------------------------------------------------

-- 26959535291011309493156476344723991336010898738574164086137773096960 
-- That's the maximum target and the maximum difficulty

DROP DOMAIN IF EXISTS target_type CASCADE;
CREATE DOMAIN target_type AS NUMERIC(68, 0) CHECK (VALUE <= 26959535291011309493156476344723991336010898738574164086137773096960 AND VALUE >= 0);

CREATE OR REPLACE FUNCTION extract_target(bits_head INT, bits_body INT) RETURNS target_type AS $$
    BEGIN
        RETURN bits_body * (2^(8*(CAST(bits_head AS target_type) - 3)));
    END;
$$ LANGUAGE plpgsql;

DROP DOMAIN IF EXISTS difficulty_type CASCADE;
CREATE DOMAIN difficulty_type AS NUMERIC(76, 8) CHECK (VALUE <= 26959535291011309493156476344723991336010898738574164086137773096960 AND VALUE > 0);

CREATE OR REPLACE FUNCTION difficulty(bits_head INT, bits_body INT) RETURNS difficulty_type AS $$
    BEGIN
        RETURN extract_target(CAST(x'1d' AS INT), CAST(x'00ffff' AS INT)) / extract_target(bits_head, bits_body);
    END;
$$ LANGUAGE plpgsql;

---------------------------------------------------------------------------
-- BLOCS
---------------------------------------------------------------------------

DROP TABLE IF EXISTS blocks;
DROP SEQUENCE IF EXISTS blocks_block_id_sequence;
DROP SEQUENCE IF EXISTS blocks_space_sequence;
DROP TYPE IF EXISTS block_status_type;

CREATE SEQUENCE blocks_block_id_sequence;
CREATE SEQUENCE blocks_space_sequence;
-- Space 0 is always reserved for the main chain.
-- Other spaces contain orphan chains

CREATE TABLE blocks (
    block_id INT NOT NULL DEFAULT NEXTVAL('blocks_block_id_sequence') PRIMARY KEY,
    block_hash hash_type NOT NULL UNIQUE,
    space INT NOT NULL,
    depth INT NOT NULL,
    span_left INT NOT NULL,
    span_right INT NOT NULL,
    version BIGINT NOT NULL,
    prev_block_hash hash_type NOT NULL,
    merkle hash_type NOT NULL,
    when_created TIMESTAMP NOT NULL,
    bits_head INT NOT NULL,
    bits_body INT NOT NULL,
    nonce BIGINT NOT NULL,
    when_found TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    block_size INT NOT NULL
);

-- Genesis block
INSERT INTO blocks (
    block_hash,
    space,
    depth,
    span_left,
    span_right,
    version,
    prev_block_hash,
    merkle,
    when_created,
    bits_head,
    bits_body,
    nonce,
    block_size
) VALUES (
    decode('00 00 00 07 19 95 08 e3 4a 9f f8 1e 6e c0 c4 77 a4 cc cf f2 a4 76 7a 8e ee 39 c1 1d b3 67 b0 08', 'hex'),
    0,
    0,
    0,
    0,
    1,
    decode('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00', 'hex'),
    decode('08 b0 67 b3 1d c1 39 ee 8e 7a 76 a4 f2 cf cc a4 77 c4 c0 6e 1e f8 9f 4a e3 08 95 19 07 00 00 00', 'hex'),
    TO_TIMESTAMP(1231006505),
    29,
    65535,
    2083236893,
    215
);

CREATE INDEX blocks_hash_idx ON blocks (block_hash);
CREATE INDEX blocks_space_idx ON blocks (space);
CREATE INDEX blocks_depth_idx ON blocks (depth);

DROP TABLE IF EXISTS chains;
DROP VIEW IF EXISTS main_chain;

CREATE TABLE chains (
    work difficulty_type NOT NULL,
    chain_id INT NOT NULL,
    depth INT NOT NULL
);

INSERT INTO chains (
    work,
    chain_id,
    depth
) SELECT
    difficulty(bits_head, bits_body),
    0,
    0
FROM blocks
WHERE block_id=1;

CREATE VIEW main_chain AS
    WITH main_chain_id AS (
        SELECT 
            chain_id, 
            depth
        FROM chains
        ORDER BY work DESC
        LIMIT 1
    )
    SELECT blocks.*
    FROM blocks, main_chain_id
    WHERE
        space=0
        AND blocks.depth <= main_chain_id.depth
        AND span_left >= chain_id
        AND span_right <= chain_id;

---------------------------------------------------------------------------
-- INVENTORY QUEUE
---------------------------------------------------------------------------

DROP TABLE IF EXISTS inventory_requests;
DROP SEQUENCE IF EXISTS inventory_requests_inventory_id_sequence;
DROP TYPE IF EXISTS inventory_type;

CREATE SEQUENCE inventory_requests_inventory_id_sequence;

CREATE TYPE inventory_type AS ENUM ('block', 'transaction');

CREATE TABLE inventory_requests (
    inventory_id INT NOT NULL DEFAULT NEXTVAL('inventory_requests_inventory_id_sequence') PRIMARY KEY,
    type inventory_type NOT NULL,
    hash hash_type NOT NULL,
    when_discovered TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

---------------------------------------------------------------------------
-- TRANSACTIONS
---------------------------------------------------------------------------

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS transactions_parents;
DROP TABLE IF EXISTS outputs;
DROP TABLE IF EXISTS inputs;
DROP TABLE IF EXISTS spends;
DROP SEQUENCE IF EXISTS transactions_transaction_id_sequence;
DROP SEQUENCE IF EXISTS outputs_output_id_sequence;
DROP SEQUENCE IF EXISTS inputs_input_id_sequence;

-- Block 91842 contains the same coinbase as block 91812
-- Same for blocks 91880 and 91722
-- We use this function to create new txs.
DROP FUNCTION IF EXISTS insert_transaction(hash_type, BIGINT, BIGINT, BOOL);
CREATE OR REPLACE FUNCTION insert_transaction(tx_hash hash_type, tx_version BIGINT, tx_locktime BIGINT, tx_coinbase BOOL, tx_size BIGINT)
RETURNS INT AS $$
DECLARE
 retval INT;
BEGIN
    INSERT INTO transactions(transaction_hash, version, locktime, coinbase, transaction_size) 
    VALUES (tx_hash, tx_version, tx_locktime, tx_coinbase, tx_size) 
    RETURNING transaction_id INTO retval;

    RETURN retval;

    EXCEPTION
        WHEN unique_violation THEN
            RETURN 0;
END;
$$ LANGUAGE plpgsql;

CREATE SEQUENCE transactions_transaction_id_sequence;
CREATE SEQUENCE outputs_output_id_sequence;
CREATE SEQUENCE inputs_input_id_sequence;

CREATE TABLE transactions_parents (
    transaction_id INT NOT NULL,
    block_id INT NOT NULL,
    index_in_block INT NOT NULL
);

CREATE INDEX transactions_parents_transaction_idx ON transactions_parents (transaction_id);
CREATE INDEX transactions_parents_block_idx ON transactions_parents (block_id);

CREATE TABLE transactions (
    transaction_id INT NOT NULL DEFAULT NEXTVAL('transactions_transaction_id_sequence') PRIMARY KEY,
    transaction_hash hash_type NOT NULL UNIQUE,
    version BIGINT NOT NULL,
    locktime BIGINT NOT NULL,
    coinbase BOOL NOT NULL,
    when_found TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    transaction_size INT NOT NULL
);

DROP DOMAIN IF EXISTS script_type CASCADE;
CREATE DOMAIN script_type AS bytea;

CREATE TABLE outputs (
    output_id INT NOT NULL DEFAULT NEXTVAL('outputs_output_id_sequence') PRIMARY KEY,
    transaction_id INT NOT NULL,
    index_in_parent BIGINT NOT NULL,
    script script_type NOT NULL,
    value amount_type NOT NULL
);

CREATE INDEX outputs_transaction_idx ON outputs (transaction_id);
CREATE INDEX outputs_script_idx ON outputs (script);

CREATE TABLE inputs (
    input_id INT NOT NULL DEFAULT NEXTVAL('inputs_input_id_sequence') PRIMARY KEY,
    transaction_id INT NOT NULL,
    index_in_parent INT NOT NULL,
    script script_type NOT NULL,
    previous_output_hash hash_type NOT NULL,
    previous_output_index BIGINT NOT NULL,
    sequence BIGINT NOT NULL
);

CREATE INDEX inputs_transaction_idx ON inputs (transaction_id);
CREATE INDEX inputs_previous_output_idx ON inputs (previous_output_hash, previous_output_index);

