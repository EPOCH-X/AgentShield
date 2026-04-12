/** @type {import('next').NextConfig} */
const nextConfig = {
  // 백엔드 API 프록시
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "http://localhost:8000/api/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
