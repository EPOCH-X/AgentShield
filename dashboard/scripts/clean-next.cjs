/**
 * Windows/macOS/Linux 공통 — 손상된 Next 캐시로 인한
 * "Cannot find module './NNN.js'" 를 피하기 위해 .next 등을 삭제합니다.
 */
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const targets = [".next", path.join("node_modules", ".cache")];

for (const rel of targets) {
  const abs = path.join(root, rel);
  try {
    fs.rmSync(abs, { recursive: true, force: true });
    console.log("[clean-next] removed:", rel);
  } catch (e) {
    console.warn("[clean-next] skip:", rel, e && e.message);
  }
}
