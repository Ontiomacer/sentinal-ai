/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Base colors
        white: "#ffffff",
        black: "#000000",
        // Sentinel AI monochrome forensic console
        "on-primary-container": "#d9d9d9",
        "primary-fixed": "#f5f5f5",
        "surface-container": "#111111",
        "on-error": "#050505",
        "tertiary-fixed-dim": "#a8a8a8",
        "secondary": "#f5f5f5",
        "inverse-on-surface": "#111111",
        "secondary-fixed-dim": "#d8d8d8",
        "on-tertiary": "#050505",
        "surface-container-high": "#181818",
        "background": "#020202",
        "error": "#ffffff",
        "success": "#e7e7e7",
        "secondary-container": "#e9e9e9",
        "surface-variant": "#202020",
        "on-primary": "#050505",
        "on-secondary-fixed": "#050505",
        "on-primary-fixed": "#050505",
        "on-primary-fixed-variant": "#3a3a3a",
        "primary-container": "#070707",
        "on-error-container": "#ffffff",
        "error-container": "#2a2a2a",
        "tertiary": "#b8b8b8",
        "outline-variant": "#333333",
        "surface-tint": "#f0f0f0",
        "secondary-fixed": "#f5f5f5",
        "surface": "#070707",
        "surface-container-lowest": "#000000",
        "primary": "#d8d8d8",
        "on-tertiary-container": "#eeeeee",
        "on-tertiary-fixed": "#050505",
        "surface-container-highest": "#242424",
        "surface-container-low": "#0b0b0b",
        "surface-dim": "#020202",
        "on-tertiary-fixed-variant": "#333333",
        "tertiary-container": "#101010",
        "on-background": "#f2f2f2",
        "tertiary-fixed": "#eeeeee",
        "on-surface": "#f2f2f2",
        "primary-fixed-dim": "#d8d8d8",
        "on-secondary": "#050505",
        "on-surface-variant": "#b9b9b9",
        "inverse-primary": "#1a1a1a",
        "on-secondary-fixed-variant": "#333333",
        "inverse-surface": "#f2f2f2",
        "on-secondary-container": "#050505",
        "surface-bright": "#2d2d2d",
        "outline": "#767676"
      },
      borderRadius: {
        DEFAULT: "0.125rem",
        lg: "0.25rem",
        xl: "0.5rem",
        full: "0.75rem"
      },
      spacing: {
        base: "8px",
        "section-gap": "120px",
        "container-padding-mobile": "24px",
        "container-padding-desktop": "64px",
        gutter: "24px"
      },
      fontFamily: {
        "headline-lg-mobile": ["Inter", "sans-serif"],
        "title-md": ["Inter", "sans-serif"],
        "label-sm": ["Geist Mono", "monospace"],
        "headline-lg": ["Inter", "sans-serif"],
        "body-lg": ["Inter", "sans-serif"],
        "display-xl": ["Inter", "sans-serif"],
        "body-md": ["Inter", "sans-serif"],
        sans: ["Inter", "sans-serif"],
        mono: ["Geist Mono", "monospace"]
      },
      fontSize: {
        "headline-lg-mobile": ["32px", { lineHeight: "40px", letterSpacing: "0", fontWeight: "700" }],
        "title-md": ["24px", { lineHeight: "32px", fontWeight: "600" }],
        "label-sm": ["12px", { lineHeight: "16px", letterSpacing: "0.05em", fontWeight: "500" }],
        "headline-lg": ["48px", { lineHeight: "56px", letterSpacing: "0", fontWeight: "700" }],
        "body-lg": ["18px", { lineHeight: "28px", fontWeight: "400" }],
        "display-xl": ["72px", { lineHeight: "80px", letterSpacing: "0", fontWeight: "800" }],
        "body-md": ["16px", { lineHeight: "24px", fontWeight: "400" }]
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scanline': 'scanline 8s linear infinite',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        }
      },
      backdropBlur: {
        xs: '2px',
        sm: '4px',
        DEFAULT: '12px',
        md: '16px',
        lg: '24px',
        xl: '40px',
      }
    },
  },
  plugins: [],
}
