import Link from "next/link";

export function Brand({ href = "/" }: { href?: string }) {
  return <Link className="brand" href={href} aria-label="Northstar, trang chủ">
    <span className="brand-mark" aria-hidden="true">N</span>
    <span className="brand-name">Northstar</span>
    <span className="brand-tag">DEMO BANK</span>
  </Link>;
}
