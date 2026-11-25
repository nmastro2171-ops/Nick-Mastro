import { WorkerMailer } from 'worker-mailer';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (/^\/(wp-admin|wp-login\.php|xmlrpc\.php|wp-includes)/.test(url.pathname)) return new Response('Gone', { status: 410 });
    if (url.pathname.replace(/\/+$/, '') === '/api/form') {
      if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
      return handleForm(request, env, ctx);
    }
    return env.ASSETS.fetch(request);
  },
};

const HONEYPOTS = ['website', '_gotcha'];

async function handleForm(request, env, ctx) {
  const wantsJson = (request.headers.get('Accept') || '').includes('application/json');
  const back = request.headers.get('Referer') || '/';
  let form;
  try { form = await request.formData(); } catch { return reply(false, 'Invalid request.'); }

  function reply(ok, message, status) {
    if (wantsJson) return Response.json({ ok, message }, { status: status ?? (ok ? 200 : 400) });
    const target = ok ? (form?.get('_redirect') || env.THANK_YOU_PATH || addParam(back, 'sent', '1')) : addParam(back, 'error', '1');
    return Response.redirect(new URL(target, request.url), 303);
  }

  // Spam checks
  for (const h of HONEYPOTS) if ((form.get(h) || '').toString().trim()) return reply(false, 'Your message could not be sent.');
  if (form.has('_ts')) {
    const age = Math.floor(Date.now() / 1000) - parseInt(form.get('_ts'), 10);
    if (!(age >= 3 && age <= 86400)) return reply(false, 'Please reload the page and try again.');
  }
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ipHash = await sha256(ip + '|forms');
  try {
    const row = await env.DB.prepare("SELECT COUNT(*) AS n FROM submissions WHERE ip_hash = ? AND created_at > datetime('now','-1 hour')").bind(ipHash).first();
    if (row && row.n >= parseInt(env.MAX_PER_HOUR || '5', 10)) return reply(false, 'Too many submissions. Please try again later.', 429);
  } catch (e) { console.error(e); }

  // Collect every field the form sent
  const fields = {};
  for (const key of new Set(form.keys())) {
    if (key.startsWith('_') || HONEYPOTS.includes(key)) continue;
    const vals = form.getAll(key).filter((v) => typeof v === 'string').map((v) => v.trim()).filter(Boolean);
    if (vals.length) fields[label(key)] = vals.join(', ').slice(0, 8000);
  }
  const find = (re) => Object.entries(fields).find(([k]) => re.test(k))?.[1] || '';
  const email = find(/e-?mail/i);
  const name = find(/name/i);
  const phone = find(/phone|tel/i);
  if (!Object.keys(fields).length) return reply(false, 'The form was empty.');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply(false, 'Please enter a valid email address.');

  const formName = (form.get('_form') || 'Website contact').toString().slice(0, 60);
  const subject = `[${env.SITE_LABEL}] ${formName}: ${name || email || 'website visitor'}`.slice(0, 200);
  let body = Object.entries(fields).map(([k, v]) => (v.includes('\n') ? `${k}:\n${v}\n` : `${k}: ${v}`)).join('\n');
  body += `\n\n--\nSent from the ${env.SITE_LABEL} website (${new URL(request.url).host}) on ${new Date().toLocaleString('en-US', { timeZone: 'America/New_York' })}\nPage: ${back}\n`;

  let id = null;
  try {
    const r = await env.DB.prepare('INSERT INTO submissions (form, name, email, phone, summary, fields, ip_hash, email_status) VALUES (?,?,?,?,?,?,?,?)')
      .bind(formName, name, email, phone, subject, JSON.stringify(fields), ipHash, 'pending').run();
    id = r.meta?.last_row_id ?? null;
  } catch (e) { console.error('save failed', e); }

  let status = 'failed';
  try {
    const password = (await env.GMAIL_APP_PASSWORD.get()).replace(/\s+/g, '');
    const mailer = await WorkerMailer.connect({ credentials: { username: env.FORM_FROM, password }, authType: 'plain', host: 'smtp.gmail.com', port: 465, secure: true });
    try {
      await mailer.send({ from: { name: `${env.SITE_LABEL} Website`, email: env.FORM_FROM }, to: { email: env.FORM_TO }, ...(email ? { reply: { name: name || email, email } } : {}), subject, text: body });
    } finally { await mailer.close().catch(() => {}); }
    status = 'sent:gmail';
  } catch (e) { status = 'failed:gmail:' + (e?.message || 'error'); console.error(status); }
  if (id !== null) ctx.waitUntil(env.DB.prepare('UPDATE submissions SET email_status = ? WHERE id = ?').bind(status.slice(0, 300), id).run().catch(() => {}));

  if (id === null && !status.startsWith('sent')) return reply(false, 'Sorry, your message could not be sent. Please call or email us directly.', 500);
  return reply(true, 'Thanks! Your message was sent. We will get back to you shortly.');
}

function label(key) { return key.replace(/\[\]$/, '').replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()).trim(); }
function addParam(u, k, v) { try { const x = new URL(u); x.searchParams.set(k, v); return x.pathname + x.search; } catch { return '/'; } }
async function sha256(s) { const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join(''); }
