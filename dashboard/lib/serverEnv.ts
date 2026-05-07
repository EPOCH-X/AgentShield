import fs from "node:fs";
import path from "node:path";

export function projectRoot() {
  const cwd = process.cwd();
  return path.basename(cwd) === "dashboard" ? path.resolve(cwd, "..") : cwd;
}

function parseDotenv(raw: string) {
  const values: Record<string, string> = {};
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
    values[key] = value;
  }
  return values;
}

export function loadAgentShieldEnv() {
  const envPath = path.join(projectRoot(), ".env");
  if (!fs.existsSync(envPath)) return {};
  return parseDotenv(fs.readFileSync(envPath, "utf8"));
}

export function mergedAgentShieldEnv() {
  return { ...loadAgentShieldEnv(), ...process.env };
}

export function envValue(key: string, fallback = "") {
  return String(mergedAgentShieldEnv()[key] || fallback);
}
