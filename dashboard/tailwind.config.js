/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Error
        "on-error-container": "#FFD0D0",
        "error": "#FF4D55",
        "error-container": "#8B0010",
        "on-error": "#FFFFFF",

        // Primary – Teal #0EA5A5
        "primary": "#0EA5A5",
        "primary-container": "#0A7272",
        "primary-fixed": "#7FDDDD",
        "primary-fixed-dim": "#3FC8C8",
        "on-primary": "#FFFFFF",
        "on-primary-container": "#CCEEEE",
        "on-primary-fixed": "#002222",
        "on-primary-fixed-variant": "#065555",
        "inverse-primary": "#5EDCDC",

        // Secondary – Cyan #2DD4D4
        "secondary": "#2DD4D4",
        "secondary-container": "#198080",
        "secondary-fixed": "#CCEEEE",
        "secondary-fixed-dim": "#2DD4D4",
        "on-secondary": "#FFFFFF",
        "on-secondary-container": "#AADEEE",
        "on-secondary-fixed": "#001A1A",
        "on-secondary-fixed-variant": "#0F5050",

        // Tertiary – Cyan variant
        "tertiary": "#3EC8C8",
        "tertiary-container": "#1A8A8A",
        "tertiary-fixed": "#C0E8E8",
        "tertiary-fixed-dim": "#3EC8C8",
        "on-tertiary": "#FFFFFF",
        "on-tertiary-container": "#AADDDD",
        "on-tertiary-fixed": "#001818",
        "on-tertiary-fixed-variant": "#0F5050",

        // Backgrounds – Dark Navy-Teal #071824
        "background": "#071824",
        "surface": "#071824",
        "surface-dim": "#041018",
        "surface-container-lowest": "#030C14",
        "surface-container-low": "#091E2C",
        "surface-container": "#0D2638",
        "surface-container-high": "#112E44",
        "surface-container-highest": "#163650",
        "surface-variant": "#143250",
        "surface-bright": "#1C4060",
        "surface-tint": "#0EA5A5",
        "inverse-surface": "#C8DEE8",
        "inverse-on-surface": "#102030",

        // Text / Outline – Teal-tinted
        "on-surface": "#D0E8F0",
        "on-background": "#D0E8F0",
        "on-surface-variant": "#8AA8B8",
        "outline": "#446080",
        "outline-variant": "#1A3848",
      },
      borderRadius: {
        DEFAULT: "0.125rem",
        sm: "0.25rem",
        md: "0.375rem",
        lg: "0.5rem",
        xl: "0.75rem",
        "2xl": "1rem",
        "3xl": "1.5rem",
        full: "9999px",
      },
      fontFamily: {
        headline: ["Manrope", "sans-serif"],
        body: ["Inter", "sans-serif"],
        label: ["Inter", "sans-serif"],
        mono: ["JetBrains Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
