/** Pinned offline production CSS build; no runtime Tailwind interpreter. */
module.exports = {
  content: ['./static/index.html', './static/dashboard.js'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          900: '#0d1117', 800: '#161b22', 700: '#21262d',
          600: '#30363d', 500: '#484f58',
        },
      },
      fontFamily: { mono: ['JetBrains Mono', 'Consolas', 'monospace'] },
    },
  },
  plugins: [],
};
