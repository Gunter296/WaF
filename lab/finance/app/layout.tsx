import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = {
  title: "Northstar Demo Bank | WAF Lab",
  description: "Local-only financial security lab with fabricated accounts."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="vi"><body>{children}</body></html>;
}
