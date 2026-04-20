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

        // Primary – Red #E62024
        "primary": "#E62024",
        "primary-container": "#B01018",
        "primary-fixed": "#FF8888",
        "primary-fixed-dim": "#E62024",
        "on-primary": "#FFFFFF",
        "on-primary-container": "#FFE0E0",
        "on-primary-fixed": "#3D0005",
        "on-primary-fixed-variant": "#8B0010",
        "inverse-primary": "#FF6B70",

        // Secondary – Blue #3A86FF
        "secondary": "#3A86FF",
        "secondary-container": "#1A5CC0",
        "secondary-fixed": "#C8DEFF",
        "secondary-fixed-dim": "#3A86FF",
        "on-secondary": "#FFFFFF",
        "on-secondary-container": "#C0D8FF",
        "on-secondary-fixed": "#001A3D",
        "on-secondary-fixed-variant": "#1040A0",

        // Tertiary – Blue (status/active indicators)
        "tertiary": "#3A86FF",
        "tertiary-container": "#1A5CC0",
        "tertiary-fixed": "#C8DEFF",
        "tertiary-fixed-dim": "#3A86FF",
        "on-tertiary": "#FFFFFF",
        "on-tertiary-container": "#C0D8FF",
        "on-tertiary-fixed": "#001A3D",
        "on-tertiary-fixed-variant": "#1040A0",

        // Backgrounds – Dark Navy #0A1A44
        "background": "#0A1A44",
        "surface": "#0A1A44",
        "surface-dim": "#071130",
        "surface-container-lowest": "#050C24",
        "surface-container-low": "#0D1E50",
        "surface-container": "#12245C",
        "surface-container-high": "#172B6A",
        "surface-container-highest": "#1D3278",
        "surface-variant": "#1A2E6E",
        "surface-bright": "#253980",
        "surface-tint": "#E62024",
        "inverse-surface": "#DCE6FF",
        "inverse-on-surface": "#182858",

        // Text / Outline – Silver/Navy-tinted
        "on-surface": "#E8ECF8",
        "on-background": "#E8ECF8",
        "on-surface-variant": "#A9B0B9",
        "outline": "#5A6888",
        "outline-variant": "#1E2E60",
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
