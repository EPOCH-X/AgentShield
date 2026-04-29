-- AgentShield shared PostgreSQL schema.
-- Safe to re-run on an existing empty or partially initialized database.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── 인증/회원 ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ── 기능 A: 스캔/판정/방어 결과 ───────────────────────────────────

CREATE TABLE IF NOT EXISTS attack_patterns (
    id SERIAL PRIMARY KEY,
    prompt_text TEXT NOT NULL,
    category VARCHAR(10) NOT NULL,
    subcategory VARCHAR(50),
    severity VARCHAR(10) DEFAULT 'Medium',
    source VARCHAR(50),
    language VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS test_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_name VARCHAR(200),
    target_api_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    frr_total INTEGER DEFAULT 0,
    frr_false_refusals INTEGER DEFAULT 0,
    frr_rate NUMERIC(5, 4) DEFAULT 0
);

CREATE TABLE IF NOT EXISTS test_results (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES test_sessions(id),
    phase INT NOT NULL,
    attack_pattern_id INT REFERENCES attack_patterns(id),
    seed_id VARCHAR(36),
    round INT,
    attack_prompt TEXT,
    target_response TEXT,
    judgment VARCHAR(20),
    judgment_layer INT,
    judgment_confidence DOUBLE PRECISION,
    manual_review_needed BOOLEAN DEFAULT FALSE,
    severity VARCHAR(10),
    category VARCHAR(10),
    subcategory VARCHAR(50),
    detail TEXT,
    defense_code TEXT,
    defended_response TEXT,
    defense_reviewed BOOLEAN DEFAULT FALSE,
    verify_result VARCHAR(20),
    mitre_technique_id VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Existing DB upgrade path.
ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_total INTEGER DEFAULT 0;
ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_false_refusals INTEGER DEFAULT 0;
ALTER TABLE test_sessions ADD COLUMN IF NOT EXISTS frr_rate NUMERIC(5, 4) DEFAULT 0;
ALTER TABLE test_results ADD COLUMN IF NOT EXISTS mitre_technique_id VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_attack_category ON attack_patterns(category);
CREATE INDEX IF NOT EXISTS idx_results_session ON test_results(session_id);
CREATE INDEX IF NOT EXISTS idx_results_phase ON test_results(phase);
CREATE INDEX IF NOT EXISTS idx_results_review ON test_results(manual_review_needed);
CREATE INDEX IF NOT EXISTS idx_results_seed ON test_results(seed_id);
CREATE INDEX IF NOT EXISTS idx_results_judgment ON test_results(judgment);
CREATE INDEX IF NOT EXISTS idx_results_mitre ON test_results(mitre_technique_id);

-- ── 기능 B: 내부 정책/감사 로그 ──────────────────────────────────

CREATE TABLE IF NOT EXISTS employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id VARCHAR(50) UNIQUE NOT NULL,
    department VARCHAR(100),
    name VARCHAR(100),
    role VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS usage_logs (
    id BIGSERIAL PRIMARY KEY,
    employee_id UUID REFERENCES employees(id),
    request_content TEXT,
    response_content TEXT,
    target_service VARCHAR(50),
    policy_violation VARCHAR(20),
    severity VARCHAR(10),
    action_taken VARCHAR(20),
    request_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS violations (
    id SERIAL PRIMARY KEY,
    employee_id UUID REFERENCES employees(id),
    violation_type VARCHAR(20) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    description TEXT,
    evidence_log_id BIGINT REFERENCES usage_logs(id),
    sanction VARCHAR(50),
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100),
    rule_type VARCHAR(20),
    pattern TEXT,
    severity VARCHAR(10),
    action VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_employee ON usage_logs(employee_id);
CREATE INDEX IF NOT EXISTS idx_usage_violation ON usage_logs(policy_violation);
CREATE INDEX IF NOT EXISTS idx_violations_employee ON violations(employee_id);
