-- AgentShield Testbed Schema
-- 기존 AgentShield schema.sql 과 별개 파일 (충돌 없음)

CREATE TABLE IF NOT EXISTS customers (
    customer_id     VARCHAR(20) PRIMARY KEY,
    name            VARCHAR(100) NOT NULL,
    email           VARCHAR(150) NOT NULL,
    phone           VARCHAR(20),
    address         TEXT,
    vip_tier        VARCHAR(20) DEFAULT 'normal',  -- normal | silver | gold | platinum
    marketing_opt_in BOOLEAN DEFAULT true,
    notes           TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    order_id        VARCHAR(20) PRIMARY KEY,
    customer_id     VARCHAR(20) REFERENCES customers(customer_id),
    product_name    VARCHAR(200) NOT NULL,
    amount          NUMERIC(10,2) NOT NULL,
    payment_status  VARCHAR(30) DEFAULT 'paid',    -- paid | refund_pending | refund_requested | refunded
    shipping_status VARCHAR(30) DEFAULT 'preparing', -- preparing | shipped | delivered | returned
    tracking_number VARCHAR(50),
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS support_tickets (
    ticket_id       VARCHAR(20) PRIMARY KEY,
    customer_id     VARCHAR(20) REFERENCES customers(customer_id),
    subject         VARCHAR(200) NOT NULL,
    description     TEXT,
    status          VARCHAR(30) DEFAULT 'open',    -- open | in_progress | escalated | resolved | closed
    priority        VARCHAR(20) DEFAULT 'normal',  -- low | normal | high | critical
    assigned_to     VARCHAR(100),
    internal_note   TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_outbox (
    mail_id         SERIAL PRIMARY KEY,
    to_address      VARCHAR(150) NOT NULL,
    subject         VARCHAR(300),
    body            TEXT,
    status          VARCHAR(20) DEFAULT 'sent',
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    reset_id        SERIAL PRIMARY KEY,
    customer_id     VARCHAR(20) REFERENCES customers(customer_id),
    token           VARCHAR(64) NOT NULL,
    requested_at    TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP,
    used            BOOLEAN DEFAULT false
);

CREATE TABLE IF NOT EXISTS refund_requests (
    refund_id       VARCHAR(20) PRIMARY KEY,
    order_id        VARCHAR(20) REFERENCES orders(order_id),
    amount          NUMERIC(10,2),
    reason          TEXT,
    requested_by    VARCHAR(100),
    approved        BOOLEAN DEFAULT false,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id          SERIAL PRIMARY KEY,
    actor           VARCHAR(100),
    channel         VARCHAR(50),
    tool_name       VARCHAR(100),
    arguments_json  TEXT,
    result_summary  TEXT,
    created_at      TIMESTAMP DEFAULT NOW()
);
