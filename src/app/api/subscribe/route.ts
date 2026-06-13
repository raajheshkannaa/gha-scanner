import { NextRequest, NextResponse } from 'next/server';

// POST /api/subscribe
//
// WHY A PROXY: the browser can't call Beehiiv's API directly without exposing
// the API key. This route proxies the call server-side, normalizes Beehiiv's
// error shapes, and adds abuse controls. Ported from the defensive-works-landing
// serverless function (api/subscribe.js) into App Router style.
//
// Double opt-in + welcome email fire from Beehiiv's publication settings.

const BEEHIIV_API_BASE = 'https://api.beehiiv.com/v2';
const FETCH_TIMEOUT_MS = 7000;

const MAX_EMAIL_LEN = 254;
const MAX_UTM_LEN = 100;
const MAX_REF_LEN = 255;
const MAX_HP_LEN = 200;

function cleanString(value: unknown, maxLen: number): string {
  return typeof value === 'string' ? value.trim().slice(0, maxLen) : '';
}

// UTM fields land in Beehiiv's dashboard. Constrain charset to block
// stored-XSS vectors and log noise.
function cleanUtm(value: unknown): string {
  const s = cleanString(value, MAX_UTM_LEN);
  return /^[\w.\-:/ ]*$/.test(s) ? s : '';
}

export async function POST(request: NextRequest) {
  const contentType = request.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return NextResponse.json(
      { error: 'Content-Type must be application/json' },
      { status: 400 }
    );
  }

  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body.' }, { status: 400 });
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return NextResponse.json({ error: 'Invalid payload.' }, { status: 400 });
  }

  // Honeypot: hidden field bots fill in; real humans never see it. Return a
  // fake success so bots can't tell they were caught. Name must match the
  // hidden input in CTABanner.tsx.
  const honeypot = cleanString(body.bot_check, MAX_HP_LEN);
  if (honeypot.length > 0) {
    return NextResponse.json({ success: true, status: 'pending' });
  }

  const email = cleanString(body.email, MAX_EMAIL_LEN).toLowerCase();
  if (
    email.length < 3 ||
    email.length > MAX_EMAIL_LEN ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
    /[\x00-\x1f\x7f]/.test(email)
  ) {
    return NextResponse.json(
      { error: 'Please enter a valid email address.' },
      { status: 400 }
    );
  }

  const apiKey = process.env.BEEHIIV_API_KEY;
  const pubId = process.env.BEEHIIV_PUBLICATION_ID;
  if (!apiKey || !pubId) {
    console.error('Missing Beehiiv env vars');
    return NextResponse.json(
      { error: 'Subscription is temporarily unavailable. Try again later.' },
      { status: 500 }
    );
  }

  const utm_source = cleanUtm(body.utm_source) || 'scan.defensive.works';
  const utm_medium = cleanUtm(body.utm_medium) || 'results-page';
  const utm_campaign = cleanUtm(body.utm_campaign) || 'scanner-funnel';
  const utm_content = cleanUtm(body.utm_content);
  const referring_site =
    cleanString(body.referring_site, MAX_REF_LEN) || 'scan.defensive.works';

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let beehiivResponse: Response;
  let data: {
    data?: { status?: string };
    errors?: Array<{ message?: string; detail?: string; code?: string }>;
    error?: string;
    message?: string;
  } = {};
  try {
    beehiivResponse = await fetch(
      `${BEEHIIV_API_BASE}/publications/${pubId}/subscriptions`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          reactivate_existing: true,
          send_welcome_email: true,
          utm_source,
          utm_medium,
          utm_campaign,
          ...(utm_content ? { utm_content } : {}),
          referring_site,
        }),
        signal: controller.signal,
      }
    );
    clearTimeout(timeoutId);

    try {
      data = await beehiivResponse.json();
    } catch {
      data = {};
    }
  } catch (err) {
    clearTimeout(timeoutId);
    if (err instanceof DOMException && err.name === 'AbortError') {
      return NextResponse.json(
        { error: 'Subscription service is slow. Try again in a moment.' },
        { status: 504 }
      );
    }
    console.error('Subscribe network error', (err as Error)?.message);
    return NextResponse.json(
      { error: 'Network error. Please try again.' },
      { status: 502 }
    );
  }

  if (!beehiivResponse.ok) {
    console.error('Beehiiv API error', {
      status: beehiivResponse.status,
      code: data?.errors?.[0]?.code,
    });

    const rawError = (
      data?.errors?.[0]?.message ||
      data?.errors?.[0]?.detail ||
      data?.error ||
      data?.message ||
      ''
    ).toLowerCase();

    if (beehiivResponse.status >= 400 && beehiivResponse.status < 500) {
      if (rawError.includes('already') || rawError.includes('exist')) {
        return NextResponse.json({
          success: true,
          status: 'existing',
          message: "You're already on the list. Check your inbox for the latest issue.",
        });
      }
      return NextResponse.json(
        { error: "We couldn't subscribe that address. Try another?" },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: 'Subscription service is having trouble. Try again shortly.' },
      { status: 502 }
    );
  }

  // With reactivate_existing, Beehiiv returns 200 + status 'active' for an
  // already-confirmed subscriber. Surface a friendlier message.
  const subscriptionStatus = data?.data?.status || 'pending';
  if (subscriptionStatus === 'active') {
    return NextResponse.json({
      success: true,
      status: 'existing',
      message: "You're already on the list. Check your inbox for the latest issue.",
    });
  }

  return NextResponse.json({ success: true, status: subscriptionStatus });
}
