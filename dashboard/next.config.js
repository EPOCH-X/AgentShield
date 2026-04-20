/** @type {import('next').NextConfig} */
const nextConfig = {
/**
 * /api/* → `app/api/[...path]/route.ts`에서 백엔드로 프록시합니다.
 * 연결 실패 시 `lib/devBackendMock.ts`의 목(로그인·가입·스캔·보고서 PDF·모니터링·관리자 등)으로 폴백합니다.
 * 백엔드 URL: AGENTSHIELD_API_URL (기본 http://127.0.0.1:8000)
 */
};

module.exports = nextConfig;
