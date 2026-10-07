/** @type {import('next').NextConfig} */
const nextConfig = {
  // This one-locale setup is intentional for the CVE-2026-64642 lab fixture.
  i18n: { locales: ["en"], defaultLocale: "en", localeDetection: false },
  async rewrites() {
    if (process.env.LAB_BUILD === "patched") return [];
    return [{ source: "/lab/ssrf/:host/:path*", destination: "http://:host/:path*" }];
  }
};

export default nextConfig;
