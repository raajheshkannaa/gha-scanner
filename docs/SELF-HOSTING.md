# Self-Hosting

GHA Scanner is a Next.js application. Deploy it to Vercel, any Node.js host, or run it locally.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_TOKEN` | Recommended | GitHub personal access token for higher API rate limits (60/hr without, 5000/hr with) |
| `KV_REST_API_URL` | Optional | Vercel KV URL for rate limiting |
| `KV_REST_API_TOKEN` | Optional | Vercel KV token for rate limiting |
| `UPSTASH_REDIS_REST_URL` | Optional | Upstash Redis URL for rate limiting (alternative to Vercel KV) |
| `UPSTASH_REDIS_REST_TOKEN` | Optional | Upstash Redis token for rate limiting |

## Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/raajheshkannaa/gha-scanner)

1. Click the button above
2. Add `GITHUB_TOKEN` environment variable with a fine-grained PAT (Public Repositories, read-only)
3. Deploy

## Run Locally

```bash
git clone https://github.com/raajheshkannaa/gha-scanner.git
cd gha-scanner
npm install
GITHUB_TOKEN=ghp_your_token npm run dev
```

Open `http://localhost:3000`.

## Build the CLI

```bash
npm run build:cli
GITHUB_TOKEN=ghp_your_token node dist/cli.js owner/repo
```
