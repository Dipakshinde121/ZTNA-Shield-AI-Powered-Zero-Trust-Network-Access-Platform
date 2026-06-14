/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#08090c',
          card: '#101216',
          panel: '#15181f',
          border: '#222834',
          text: '#f3f4f6',
          muted: '#9ca3af',
          primary: '#10b981', // Neon Green
          secondary: '#3b82f6', // Neon Blue
          danger: '#ef4444', // Red Alerts
          warning: '#f59e0b', // Amber Alerts
          glow: 'rgba(16, 185, 129, 0.15)',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'Outfit', 'sans-serif'],
      },
      boxShadow: {
        'cyber-glow': '0 0 15px rgba(16, 185, 129, 0.25)',
        'cyber-glow-blue': '0 0 15px rgba(59, 130, 246, 0.25)',
        'cyber-glow-red': '0 0 15px rgba(239, 68, 68, 0.25)',
        'cyber-glow-yellow': '0 0 15px rgba(245, 158, 11, 0.25)',
      }
    },
  },
  plugins: [],
}
