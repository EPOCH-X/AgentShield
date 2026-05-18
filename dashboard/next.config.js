/** @type {import('next').NextConfig} */
const fs = require("fs");
const path = require("path");

// ── 부모 디렉토리의 AgentShield .env를 process.env에 미리 주입 ──
// next.config.js는 Next.js 시작 시 가장 먼저 실행되므로
// 이후 모든 API route에서 process.env.KEY 로 직접 읽을 수 있다.
const agentShieldRoot = path.resolve(__dirname, "..");
const parentEnvPath = path.join(agentShieldRoot, ".env");
if (fs.existsSync(parentEnvPath)) {
  const raw = fs.readFileSync(parentEnvPath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    const key = match[1];
    let value = match[2].trim();
    const commentIdx = value.search(/\s+#/);
    if (commentIdx >= 0) value = value.slice(0, commentIdx).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = value;
  }
}

// spawn() 인수의 크로스 모듈 호출 제거를 위해 정적 값으로 미리 주입
if (!process.env.AGENTSHIELD_ROOT) {
  process.env.AGENTSHIELD_ROOT = agentShieldRoot;
}
if (!process.env.PYTHON_BIN) {
  const venvPython = path.join(agentShieldRoot, "venv", "bin", "python");
  process.env.PYTHON_BIN = fs.existsSync(venvPython) ? venvPython : "python3";
}

const nextConfig = {
  /**
   * /api/* → `app/api/[...path]/route.ts`에서 백엔드로 프록시합니다.
   * 백엔드 URL: AGENTSHIELD_API_URL (기본 http://127.0.0.1:8000)
   */
};

module.exports = nextConfig;
