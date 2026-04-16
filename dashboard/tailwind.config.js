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
        "on-error-container": "#ffdad6",
        "error": "#ffb4ab",
        "error-container": "#93000a",
        "on-error": "#690005",

        // Primary – Neon Green #39FF14
        "primary": "#39FF14",
        "primary-container": "#1DA800",
        "primary-fixed": "#B8FFB0",
        "primary-fixed-dim": "#39FF14",
        "on-primary": "#002200",
        "on-primary-container": "#EAFFDE",
        "on-primary-fixed": "#001400",
        "on-primary-fixed-variant": "#135C00",
        "inverse-primary": "#156B00",

        // Secondary – Soft Purple #A084E8
        "secondary": "#A084E8",
        "secondary-container": "#5B3FA8",
        "secondary-fixed": "#E9DDFF",
        "secondary-fixed-dim": "#A084E8",
        "on-secondary": "#1A0050",
        "on-secondary-container": "#D4BBFF",
        "on-secondary-fixed": "#130038",
        "on-secondary-fixed-variant": "#4A2E96",

        // Tertiary – Neon Green (active/status indicators)
        "tertiary": "#39FF14",
        "tertiary-container": "#1DA800",
        "tertiary-fixed": "#B8FFB0",
        "tertiary-fixed-dim": "#39FF14",
        "on-tertiary": "#002200",
        "on-tertiary-container": "#EAFFDE",
        "on-tertiary-fixed": "#001400",
        "on-tertiary-fixed-variant": "#135C00",

        // Backgrounds – Deep Purple/Black #1A1026
        "background": "#1A1026",
        "surface": "#1A1026",
        "surface-dim": "#1A1026",
        "surface-container-lowest": "#0E0819",
        "surface-container-low": "#1C1232",
        "surface-container": "#221840",
        "surface-container-high": "#2A1F4A",
        "surface-container-highest": "#312558",
        "surface-variant": "#312558",
        "surface-bright": "#3D2E65",
        "surface-tint": "#39FF14",
        "inverse-surface": "#EDE6FF",
        "inverse-on-surface": "#2B1F44",

        // Text / Outline – Purple-tinted
        "on-surface": "#EDE6FF",
        "on-background": "#EDE6FF",
        "on-surface-variant": "#B8A4D4",
        "outline": "#7A6A9A",
        "outline-variant": "#3D2B5E",
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
