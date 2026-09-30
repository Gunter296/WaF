// The single-locale lab fixture still uses Next.js's Pages Router 404 path.
// Keeping a Pages Router page makes its support entries available at build time.
export default function NotFound() {
  return <main><h1>404</h1><p>Page not found.</p></main>;
}

