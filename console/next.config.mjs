/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Static export so the console can be served by any static server (the
  // `scripts/console.py` launcher serves `out/` next to a live engagement's JSON).
  output: "export",
  trailingSlash: true,
  images: { unoptimized: true },
};

export default nextConfig;
