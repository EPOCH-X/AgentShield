-- AgentShield — 세부기획서 §6 DB 스키마 (기능 A + 기능 B)
-- 빈 데이터베이스(예: agentshield)에 postgres 등 슈퍼유저 또는 DB 소유자로 접속한 뒤 한 번 실행합니다.
-- PostgreSQL 13+ 권장 (gen_random_uuid() 내장).

-- ── 기능 A ──

CREATE TABLE attack_patterns (
    id SERIAL PRIMARY KEY,
    prompt_text TEXT NOT NULL,
    category VARCHAR(10) NOT NULL,
    subcategory VARCHAR(50),
    severity VARCHAR(10) DEFAULT 'Medium',
    source VARCHAR(50),
    language VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE test_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_name VARCHAR(200),
    target_api_url TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE TABLE test_results (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES test_sessions(id),
    phase INT NOT NULL,
    attack_pattern_id INT REFERENCES attack_patterns(id),
    attack_prompt TEXT,
    target_response TEXT,
    judgment VARCHAR(20),
    judgment_layer INT,
    judgment_confidence DOUBLE PRECISION,
    manual_review_needed BOOLEAN DEFAULT FALSE,
    severity VARCHAR(10),
    category VARCHAR(10),
    defense_code TEXT,
    defense_reviewed BOOLEAN DEFAULT FALSE,
    verify_result VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_attack_category ON attack_patterns(category);
CREATE INDEX idx_results_session ON test_results(session_id);
CREATE INDEX idx_results_phase ON test_results(phase);
CREATE INDEX idx_results_review ON test_results(manual_review_needed);

-- ── 기능 B ──

CREATE TABLE employees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    employee_id VARCHAR(50) UNIQUE NOT NULL,
    department VARCHAR(100),
    name VARCHAR(100),
    role VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE usage_logs (
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

CREATE TABLE violations (
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

CREATE TABLE policy_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100),
    rule_type VARCHAR(20),
    pattern TEXT,
    severity VARCHAR(10),
    action VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_usage_employee ON usage_logs(employee_id);
CREATE INDEX idx_usage_violation ON usage_logs(policy_violation);
CREATE INDEX idx_violations_employee ON violations(employee_id);
