/**
 * Houston Roofing & Construction - Main Server Entry Point
 * File: index.js
 */

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { MongoClient, ObjectId } = require('mongodb');
const { createAdminRouter } = require('./admin');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware & Parsers
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());

// Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Database Connection Manager (never throws; returns null when unavailable)
let cachedClient = null;
let cachedDb = null;
let connectingPromise = null;
let lastDbError = null;
let lastFailAt = 0;
const RETRY_COOLDOWN_MS = 15000; // after a failure, wait before retrying so pages stay fast

async function connectToDatabase() {
  if (cachedDb) return cachedDb;

  const uri = process.env.MONGODB_URI;
  if (!uri) {
    lastDbError = 'MONGODB_URI is not set';
    return null;
  }

  // Skip retry storms: if we failed very recently, answer instantly
  if (lastFailAt && Date.now() - lastFailAt < RETRY_COOLDOWN_MS) return null;

  // Share one in-flight connection attempt between concurrent requests
  if (connectingPromise) return connectingPromise;

  connectingPromise = (async () => {
    let client = null;
    try {
      client = new MongoClient(uri, {
        serverSelectionTimeoutMS: 4000,
        connectTimeoutMS: 4000,
        maxPoolSize: 10
      });
      await client.connect();
      const db = client.db();
      cachedClient = client;
      cachedDb = db;
      lastDbError = null;
      lastFailAt = 0;
      // Index/seed setup must never block or break requests
      initDb(db).catch(e => console.error('initDb failed:', e));
      return db;
    } catch (err) {
      console.error('MongoDB Connection Error:', err && err.message);
      lastDbError = (err && err.message ? err.message : String(err)).split('\n')[0].slice(0, 200);
      lastFailAt = Date.now();
      try { if (client) await client.close(); } catch (e) {}
      cachedClient = null;
      cachedDb = null;
      return null;
    } finally {
      connectingPromise = null;
    }
  })();

  return connectingPromise;
}

function getDb() {
  return cachedDb;
}

// Database Initializer & Schema Index Setup
async function initDb(db) {
  if (!db) return;
  try {
    await db.collection('slotOccupancy').createIndex({ slotKey: 1 }, { unique: true });
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('sessions').createIndex({ tokenHash: 1 }, { unique: true });
    await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    await db.collection('bookings').createIndex({ bookingRef: 1 }, { unique: true });
    await db.collection('bookings').createIndex({ email: 1 });
    await db.collection('projects').createIndex({ customerEmail: 1 });

    // Seed default settings if not exists
    const existingSettings = await db.collection('settings').findOne({ type: 'global' });
    if (!existingSettings) {
      await db.collection('settings').insertOne({
        type: 'global',
        timezone: 'America/Chicago',
        slotIntervalMinutes: 30,
        minLeadTimeHours: 12,
        maxHorizonDays: 60,
        cancelCutoffHours: 24,
        businessHours: {
          mon_fri: '08:00-18:00',
          saturday: '08:00-16:00',
          sunday: '10:00-16:00'
        },
        appointmentTypes: {
          'Free roof inspection': { duration: 60, buffer: 30, capacity: 2 },
          'Free estimate': { duration: 60, buffer: 30, capacity: 2 },
          'Storm or hail damage assessment': { duration: 90, buffer: 30, capacity: 2 },
          'Roof repair visit': { duration: 60, buffer: 30, capacity: 1 },
          'Commercial or multi-family walkthrough': { duration: 90, buffer: 30, capacity: 1 },
          'Phone consultation': { duration: 20, buffer: 10, capacity: 3 }
        },
        blackoutDates: ['2026-11-26', '2026-12-25', '2027-01-01'],
        updatedAt: new Date()
      });
    }

    // Seed initial verification checklist items
    const factCount = await db.collection('siteContent').countDocuments({ type: 'fact_verification' });
    if (factCount === 0) {
      await db.collection('siteContent').insertMany([
        { type: 'fact_verification', key: 'Business Legal Name', description: 'Houston Roofing & Construction', verified: true, notes: 'Confirmed' },
        { type: 'fact_verification', key: 'Street Address', description: '11330 West Rd, Houston, TX 77065', verified: true, notes: 'Verified location' },
        { type: 'fact_verification', key: 'Phone Number', description: '(832) 237-3737', verified: true, notes: 'Verified phone' },
        { type: 'fact_verification', key: 'GAF Master Elite Certification', description: 'Contractor certification status', verified: false, notes: 'Awaiting client documentation approval' },
        { type: 'fact_verification', key: 'BBB A+ Rating', description: 'Better Business Bureau rating display', verified: false, notes: 'Pending verification' },
        { type: 'fact_verification', key: 'Financing Terms', description: 'Partnered zero-down financing promotional copy', verified: false, notes: 'Pending terms confirmation' },
        { type: 'fact_verification', key: 'Warranty Terms & Names', description: 'Lifetime material warranty guarantees', verified: false, notes: 'Under client legal review' }
      ]);
    }
  } catch (err) {
    console.error('Error during db initialization:', err);
  }
}

// Authentication & Session Middleware
app.use(async (req, res, next) => {
  req.session = null;
  try {
    const db = await connectToDatabase();
    const token = req.cookies.admin_session || req.cookies.user_session;

    if (token && db) {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const session = await db.collection('sessions').findOne({
        tokenHash,
        expiresAt: { $gt: new Date() }
      });
      if (session) {
        req.session = session;
      }
    }
  } catch (err) {
    console.error('Session middleware error:', err);
  }
  next();
});

function requireAdminAuth(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized administrative access required.' });
}

function requireUserAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: 'Authentication required.' });
}

// Layout helper for HTML pages
function renderPage(title, content, currentPath = '/') {
  /*
   * CLIENT APPROVAL STATUS: PREVIEW MODE
   * To enable search engine indexing after client sign-off:
   * 1. Change 'noindex, nofollow' below to 'index, follow'.
   * 2. Verify all claims in the Admin Fact Verification checklist.
   */
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | Houston Roofing &amp; Construction</title>
  <meta name="robots" content="noindex, nofollow">
  <meta name="description" content="Houston Roofing &amp; Construction - Honest, transparent roofing inspections, repairs, and replacements in Houston, TX. Call (832) 237-3737 or book online.">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --navy: #102238;
      --navy-light: #1A365D;
      --bg-light: #F7F9FC;
      --surface-white: #FFFFFF;
      --text-main: #102238;
      --text-muted: #65748B;
      --border-color: #E2E8F0;
      --accent-orange: #F47738;
      --accent-orange-hover: #E06326;
      --accent-blue: #32A7E8;
      --accent-teal: #42C6B1;
      --accent-gold: #F5C36B;
      --radius-sm: 8px;
      --radius-md: 14px;
      --radius-lg: 24px;
      --shadow-soft: 0 10px 30px -5px rgba(16, 34, 56, 0.06), 0 8px 15px -6px rgba(16, 34, 56, 0.04);
      --glass-bg: rgba(255, 255, 255, 0.82);
      --glass-border: rgba(255, 255, 255, 0.4);
      --glass-shadow: 0 12px 40px 0 rgba(16, 34, 56, 0.08);
      --clay-btn: linear-gradient(145deg, #f58245, #dc6b32);
      --clay-shadow: 4px 4px 10px #c55d28, -4px -4px 10px #ff9148;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; }
    body { background-color: var(--bg-light); color: var(--text-main); line-height: 1.6; min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }

    /* Header & Navigation */
    .site-header {
      background: var(--glass-bg);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      position: sticky; top: 0; z-index: 900;
      transition: all 0.3s ease;
    }
    .header-inner {
      max-width: 1200px; margin: 0 auto; padding: 1rem 1.5rem;
      display: flex; align-items: center; justify-content: space-between;
    }
    .brand-logo {
      display: flex; align-items: center; gap: 0.6rem;
      text-decoration: none; font-size: 1.25rem; font-weight: 800; color: var(--navy);
    }
    .brand-logo span { color: var(--accent-orange); }
    .nav-links { display: flex; gap: 1.75rem; list-style: none; align-items: center; }
    .nav-link {
      text-decoration: none; color: var(--navy); font-weight: 600; font-size: 0.95rem;
      transition: color 0.2s ease; position: relative;
    }
    .nav-link:hover, .nav-link.active { color: var(--accent-orange); }
    .nav-link.active::after {
      content: ''; position: absolute; bottom: -6px; left: 0; right: 0; height: 2px;
      background: var(--accent-orange); border-radius: 2px;
    }
    .nav-cta-group { display: flex; align-items: center; gap: 1rem; }
    .phone-link {
      color: var(--navy); text-decoration: none; font-weight: 700; font-size: 0.95rem;
      display: flex; align-items: center; gap: 0.4rem;
    }

    /* Buttons */
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
      padding: 0.75rem 1.5rem; border-radius: var(--radius-sm); font-weight: 700; font-size: 0.95rem;
      text-decoration: none; border: none; cursor: pointer; transition: all 0.25s ease;
    }
    .btn-clay {
      background: var(--clay-btn); color: #FFFFFF;
      box-shadow: 0 4px 12px rgba(244, 119, 56, 0.35);
    }
    .btn-clay:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(244, 119, 56, 0.45); }
    .btn-navy { background: var(--navy); color: #FFFFFF; }
    .btn-navy:hover { background: var(--navy-light); transform: translateY(-1px); }
    .btn-outline { border: 2px solid var(--navy); color: var(--navy); background: transparent; }
    .btn-outline:hover { background: var(--navy); color: #FFFFFF; }

    /* Layout Components */
    .container { max-width: 1200px; margin: 0 auto; padding: 3rem 1.5rem; flex: 1; }
    .section-title { font-size: 2.2rem; font-weight: 800; color: var(--navy); margin-bottom: 0.75rem; text-align: center; }
    .section-subtitle { text-align: center; color: var(--text-muted); max-width: 650px; margin: 0 auto 3rem; font-size: 1.05rem; }

    /* Glass Cards */
    .glass-card {
      background: var(--glass-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-md);
      box-shadow: var(--glass-shadow);
      padding: 2rem;
    }

    /* Hero Section */
    .hero {
      position: relative; background: linear-gradient(135deg, var(--navy) 0%, #173254 100%);
      color: #FFFFFF; padding: 5rem 1.5rem 6rem; overflow: hidden;
    }
    .hero-container { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: 1fr 420px; gap: 3rem; align-items: center; }
    .hero-eyebrow { color: var(--accent-orange); font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.85rem; margin-bottom: 1rem; }
    .hero-title { font-size: 3rem; font-weight: 800; line-height: 1.15; margin-bottom: 1.25rem; }
    .hero-desc { font-size: 1.15rem; color: #CBD5E1; margin-bottom: 2rem; line-height: 1.6; }

    /* Footer */
    .site-footer { background: var(--navy); color: #94A3B8; padding: 4rem 1.5rem 2rem; margin-top: auto; font-size: 0.9rem; }
    .footer-grid { max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 2.5rem; margin-bottom: 3rem; }
    .footer-title { color: #FFFFFF; font-weight: 700; font-size: 1.05rem; margin-bottom: 1.25rem; }
    .footer-links { list-style: none; display: flex; flex-direction: column; gap: 0.6rem; }
    .footer-links a { color: #94A3B8; text-decoration: none; transition: color 0.2s ease; }
    .footer-links a:hover { color: var(--accent-orange); }
    .legal-disclosure { max-width: 1200px; margin: 0 auto; padding-top: 2rem; border-top: 1px solid rgba(255,255,255,0.1); font-size: 0.8rem; color: #64748B; line-height: 1.5; }

    /* Mobile Menu */
    .mobile-toggle { display: none; background: none; border: none; cursor: pointer; color: var(--navy); }
    @media (max-width: 900px) {
      .hero-container { grid-template-columns: 1fr; }
      .nav-links { display: none; }
      .mobile-toggle { display: block; }
      .nav-links.mobile-open {
        display: flex; flex-direction: column; position: absolute; top: 100%; left: 0; right: 0;
        background: #FFFFFF; padding: 1.5rem; box-shadow: var(--shadow-soft); border-bottom: 1px solid var(--border-color);
      }
    }
  </style>
</head>
<body>

  <!-- Announcement Bar if active -->
  <div id="announcement-bar" style="display:none; background: var(--accent-orange); color: #FFFFFF; text-align: center; padding: 0.5rem 1rem; font-size: 0.85rem; font-weight: 600;"></div>

  <header class="site-header">
    <div class="header-inner">
      <a href="/" class="brand-logo">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#F47738" stroke-width="2.5"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
        Houston<span>Roofing</span>
      </a>

      <button class="mobile-toggle" onclick="document.querySelector('.nav-links').classList.toggle('mobile-open')">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
      </button>

      <ul class="nav-links">
        <li><a href="/" class="nav-link ${currentPath === '/' ? 'active' : ''}">Home</a></li>
        <li><a href="/services" class="nav-link ${currentPath.startsWith('/services') ? 'active' : ''}">Services</a></li>
        <li><a href="/why-us" class="nav-link ${currentPath === '/why-us' ? 'active' : ''}">Why Us</a></li>
        <li><a href="/reviews" class="nav-link ${currentPath === '/reviews' ? 'active' : ''}">Reviews</a></li>
        <li><a href="/updates" class="nav-link ${currentPath === '/updates' ? 'active' : ''}">Resources</a></li>
        <li><a href="/faq" class="nav-link ${currentPath === '/faq' ? 'active' : ''}">FAQ</a></li>
        <li><a href="/contact" class="nav-link ${currentPath === '/contact' ? 'active' : ''}">Contact</a></li>
      </ul>

      <div class="nav-cta-group">
        <a href="tel:+18322373737" class="phone-link">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#F47738" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path></svg>
          (832) 237-3737
        </a>
        <a href="/book" class="btn btn-clay">Book Inspection</a>
      </div>
    </div>
  </header>

  ${content}

  <footer class="site-footer">
    <div class="footer-grid">
      <div>
        <div class="brand-logo" style="color: #FFFFFF; margin-bottom: 1rem;">
          Houston<span>Roofing</span>
        </div>
        <p style="margin-bottom: 1rem;">“We inspect. We show you. You decide.”</p>
        <p>11330 West Rd<br>Houston, TX 77065<br>United States</p>
        <p style="margin-top: 0.5rem;"><strong>Phone:</strong> <a href="tel:+18322373737" style="color:#FFFFFF; text-decoration:none;">(832) 237-3737</a></p>
      </div>

      <div>
        <h4 class="footer-title">Services</h4>
        <ul class="footer-links">
          <li><a href="/services/roof-repair">Roof Repair</a></li>
          <li><a href="/services/roof-replacement">Asphalt Roof Replacement</a></li>
          <li><a href="/services/metal-roofing">Metal Roofing Systems</a></li>
          <li><a href="/services/storm-damage">Storm &amp; Hail Assessment</a></li>
          <li><a href="/services/commercial-roofing">Commercial &amp; Flat Roofing</a></li>
        </ul>
      </div>

      <div>
        <h4 class="footer-title">Company &amp; Portal</h4>
        <ul class="footer-links">
          <li><a href="/why-us">Why Choose Us</a></li>
          <li><a href="/reviews">Customer Reviews</a></li>
          <li><a href="/updates">Roofing Resources &amp; Articles</a></li>
          <li><a href="/dashboard">Customer Dashboard</a></li>
          <li><a href="/admin">Admin Portal</a></li>
        </ul>
      </div>

      <div>
        <h4 class="footer-title">Social Profiles</h4>
        <ul class="footer-links">
          <li><a href="https://www.facebook.com/HoustonRC/" target="_blank" rel="noopener">Facebook</a></li>
          <li><a href="https://www.instagram.com/houstonroofingandconstruction/" target="_blank" rel="noopener">Instagram</a></li>
          <li><a href="https://www.youtube.com/channel/UCJNuWBlfl3octGxktiYmT8g/" target="_blank" rel="noopener">YouTube</a></li>
          <li><a href="https://g.page/HoustonRC" target="_blank" rel="noopener">Google Business Profile</a></li>
          <li><a href="https://x.com/roofinghouston" target="_blank" rel="noopener">X (Twitter)</a></li>
        </ul>
      </div>
    </div>

    <div class="legal-disclosure">
      <p style="margin-bottom: 0.75rem;">
        “We are roofing contractors, not public insurance adjusters. We do not negotiate or settle claims on your behalf. You are responsible for your insurance deductible. Texas law prohibits contractors from waiving, rebating or absorbing a deductible.”
      </p>
      <p style="margin-bottom: 0.75rem;">
        Resource: <a href="https://www.tdi.texas.gov/Consumer/storms/roofing-and-insurance-know-the-law.html" target="_blank" rel="noopener" style="color:var(--accent-blue);">Texas Department of Insurance — Roofing and Insurance: Know the Law</a>
      </p>
      <p style="display: flex; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
        <span>&copy; ${new Date().getFullYear()} Houston Roofing &amp; Construction. All rights reserved.</span>
        <span><a href="/privacy" style="color:#94A3B8;">Privacy Policy</a> | <a href="/terms" style="color:#94A3B8;">Terms of Service</a></span>
      </p>
    </div>
  </footer>

  <script>
    // Fetch active announcements
    fetch('/api/announcements/active')
      .then(res => res.json())
      .then(data => {
        if (data && data.length > 0) {
          const bar = document.getElementById('announcement-bar');
          bar.innerText = data[0].title + ': ' + data[0].message;
          bar.style.display = 'block';
        }
      }).catch(e => console.log('No announcements'));
  </script>
</body>
</html>`;
}

// ------------------- PUBLIC HTML ROUTES -------------------

// Homepage - "/"
app.get('/', (req, res) => {
  const content = `
  <section class="hero">
    <div class="hero-container">
      <div>
        <div class="hero-eyebrow">Houston roofing, done honestly</div>
        <h1 class="hero-title">A roof you can trust. A process you can see.</h1>
        <p class="hero-desc">Book a roof inspection online, receive clear information about your options, and follow your project's progress from your own customer dashboard.</p>
        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
          <a href="/book" class="btn btn-clay" style="padding: 0.9rem 1.8rem; font-size: 1.05rem;">Book a Free Inspection</a>
          <a href="tel:+18322373737" class="btn btn-outline" style="border-color: #FFFFFF; color: #FFFFFF;">Call (832) 237-3737</a>
        </div>
      </div>

      <div class="glass-card" style="background: rgba(255, 255, 255, 0.12); border-color: rgba(255, 255, 255, 0.25); color: #FFFFFF;">
        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; color: #FFFFFF;">Schedule Your Inspection</h3>
        <p style="font-size: 0.85rem; color: #CBD5E1; margin-bottom: 1.25rem;">Select your required service and property type to find available times.</p>
        <form action="/book" method="GET">
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-size: 0.8rem; font-weight: 600; margin-bottom: 0.3rem;">Service Needed</label>
            <select name="service" style="width: 100%; padding: 0.65rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.3); background: rgba(16, 34, 56, 0.8); color: #FFFFFF;">
              <option value="Free roof inspection">Free Roof Inspection</option>
              <option value="Free estimate">Free Estimate</option>
              <option value="Storm or hail damage assessment">Storm / Hail Damage Assessment</option>
              <option value="Roof repair visit">Roof Repair Visit</option>
              <option value="Commercial or multi-family walkthrough">Commercial Walkthrough</option>
            </select>
          </div>
          <div style="margin-bottom: 1.25rem;">
            <label style="display: block; font-size: 0.8rem; font-weight: 600; margin-bottom: 0.3rem;">Property Type</label>
            <select name="propertyType" style="width: 100%; padding: 0.65rem; border-radius: 6px; border: 1px solid rgba(255,255,255,0.3); background: rgba(16, 34, 56, 0.8); color: #FFFFFF;">
              <option value="Single-family home">Single-family home</option>
              <option value="Townhome">Townhome</option>
              <option value="Commercial building">Commercial building</option>
              <option value="Multi-family community">Multi-family community</option>
            </select>
          </div>
          <button type="submit" class="btn btn-clay" style="width: 100%;">Find Available Times</button>
        </form>
      </div>
    </div>
  </section>

  <div class="container">
    <h2 class="section-title">Our 4-Step Process</h2>
    <p class="section-subtitle">We believe in complete transparency from start to finish.</p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem; margin-bottom: 4rem;">
      <div style="background: #FFFFFF; padding: 1.75rem; border-radius: 12px; border: 1px solid #E2E8F0; text-align: center;">
        <div style="width: 50px; height: 50px; background: #E0F2FE; color: #0284C7; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-weight: 800; font-size: 1.2rem;">1</div>
        <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--navy);">1. Inspect</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">Thorough hands-on evaluation of your entire roofing system and attic ventilation.</p>
      </div>

      <div style="background: #FFFFFF; padding: 1.75rem; border-radius: 12px; border: 1px solid #E2E8F0; text-align: center;">
        <div style="width: 50px; height: 50px; background: #E0F2FE; color: #0284C7; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-weight: 800; font-size: 1.2rem;">2</div>
        <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--navy);">2. Show</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">Detailed high-resolution photo documentation so you see exactly what we see.</p>
      </div>

      <div style="background: #FFFFFF; padding: 1.75rem; border-radius: 12px; border: 1px solid #E2E8F0; text-align: center;">
        <div style="width: 50px; height: 50px; background: #E0F2FE; color: #0284C7; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-weight: 800; font-size: 1.2rem;">3</div>
        <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--navy);">3. Explain</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">Clear repair vs. replacement options with itemized material specifications.</p>
      </div>

      <div style="background: #FFFFFF; padding: 1.75rem; border-radius: 12px; border: 1px solid #E2E8F0; text-align: center;">
        <div style="width: 50px; height: 50px; background: #E0F2FE; color: #0284C7; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1rem; font-weight: 800; font-size: 1.2rem;">4</div>
        <h3 style="font-size: 1.1rem; margin-bottom: 0.5rem; color: var(--navy);">4. Install</h3>
        <p style="font-size: 0.9rem; color: var(--text-muted);">Professional execution, rigorous job site cleanup, and live project portal tracking.</p>
      </div>
    </div>
  </div>
  `;
  res.send(renderPage('Home', content, '/'));
});

// Services - "/services"
app.get('/services', (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Roofing Services in Houston</h1>
    <p class="section-subtitle">Comprehensive residential, commercial, and emergency roof repair services built for Gulf Coast weather.</p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem; margin-bottom: 3rem;">
      
      <div style="background: #FFFFFF; border-radius: 14px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: var(--shadow-soft);">
        <div style="padding: 1.75rem;">
          <span style="font-size: 0.75rem; font-weight: 700; color: var(--accent-orange); text-transform: uppercase;">Residential</span>
          <h3 style="font-size: 1.3rem; margin: 0.4rem 0 0.8rem; color: var(--navy);">Roof Repair &amp; Maintenance</h3>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1rem;">Fixing active leaks, damaged shingles, pipe boot failures, and valley wear before major water damage occurs.</p>
          <a href="/services/roof-repair" style="color: var(--accent-orange); font-weight: 700; text-decoration: none; font-size: 0.9rem;">Learn More &rarr;</a>
        </div>
      </div>

      <div style="background: #FFFFFF; border-radius: 14px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: var(--shadow-soft);">
        <div style="padding: 1.75rem;">
          <span style="font-size: 0.75rem; font-weight: 700; color: var(--accent-orange); text-transform: uppercase;">Residential</span>
          <h3 style="font-size: 1.3rem; margin: 0.4rem 0 0.8rem; color: var(--navy);">Asphalt Shingle Replacement</h3>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1rem;">Architectural and heavy-duty shingle roof replacements designed to withstand severe Houston rain and wind.</p>
          <a href="/services/roof-replacement" style="color: var(--accent-orange); font-weight: 700; text-decoration: none; font-size: 0.9rem;">Learn More &rarr;</a>
        </div>
      </div>

      <div style="background: #FFFFFF; border-radius: 14px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: var(--shadow-soft);">
        <div style="padding: 1.75rem;">
          <span style="font-size: 0.75rem; font-weight: 700; color: var(--accent-orange); text-transform: uppercase;">Residential</span>
          <h3 style="font-size: 1.3rem; margin: 0.4rem 0 0.8rem; color: var(--navy);">Standing Seam Metal Roofing</h3>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1rem;">Energy-efficient, ultra-durable metal roof systems engineered for maximum heat reflection and longevity.</p>
          <a href="/services/metal-roofing" style="color: var(--accent-orange); font-weight: 700; text-decoration: none; font-size: 0.9rem;">Learn More &rarr;</a>
        </div>
      </div>

      <div style="background: #FFFFFF; border-radius: 14px; border: 1px solid #E2E8F0; overflow: hidden; box-shadow: var(--shadow-soft);">
        <div style="padding: 1.75rem;">
          <span style="font-size: 0.75rem; font-weight: 700; color: var(--accent-blue); text-transform: uppercase;">Commercial</span>
          <h3 style="font-size: 1.3rem; margin: 0.4rem 0 0.8rem; color: var(--navy);">Commercial &amp; Flat Roofing</h3>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1rem;">TPO, modified bitumen, and flat roof maintenance and walkthrough inspections for commercial facilities.</p>
          <a href="/services/commercial-roofing" style="color: var(--accent-blue); font-weight: 700; text-decoration: none; font-size: 0.9rem;">Learn More &rarr;</a>
        </div>
      </div>

    </div>
  </div>
  `;
  res.send(renderPage('Roofing Services', content, '/services'));
});

// Individual Service Pages
app.get('/services/:slug', (req, res) => {
  const slug = req.params.slug;
  const content = `
  <div class="container">
    <h1 class="section-title" style="text-transform: capitalize;">${slug.replace(/-/g, ' ')}</h1>
    <p class="section-subtitle">Dedicated roofing solutions engineered for performance and long-term durability in Houston.</p>

    <div style="background: #FFFFFF; padding: 2.5rem; border-radius: 16px; border: 1px solid #E2E8F0; max-width: 800px; margin: 0 auto 3rem;">
      <h2 style="color: var(--navy); margin-bottom: 1rem;">Service Scope &amp; Deliverables</h2>
      <p style="color: var(--text-muted); margin-bottom: 1.5rem;">
        Every ${slug.replace(/-/g, ' ')} project starts with a comprehensive on-site assessment. We provide photo-documented inspection reports and transparent itemized options so you remain in complete control.
      </p>

      <div style="background: var(--bg-light); padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem;">
        <h4 style="color: var(--navy); margin-bottom: 0.5rem;">Why Schedule with Houston Roofing?</h4>
        <ul style="padding-left: 1.2rem; color: var(--text-muted); font-size: 0.95rem;">
          <li>Real-time online appointment scheduling</li>
          <li>Customer progress portal with live milestone tracking</li>
          <li>Clear written scopes with no hidden charges</li>
        </ul>
      </div>

      <a href="/book?service=${encodeURIComponent(slug.replace(/-/g, ' '))}" class="btn btn-clay" style="width: 100%;">Book This Service Online</a>
    </div>
  </div>
  `;
  res.send(renderPage('Service Details', content, '/services'));
});

// Why Us - "/why-us"
app.get('/why-us', (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Why Choose Houston Roofing</h1>
    <p class="section-subtitle">“We inspect. We show you. You decide.” — Built on honesty and clear customer communication.</p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">Photo-Documented Inspections</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">We don't expect you to take our word for it. Our team captures detailed photographs of your roof's condition so you see exactly what needs attention.</p>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">Online Customer Portal</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">Track your project stage from inspection request to final warranty registration directly from your online customer dashboard.</p>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">Fair &amp; Honest Communication</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">If your roof only needs a minor repair, we will tell you. We never push full replacements when a repair is the right solution.</p>
      </div>
    </div>
  </div>
  `;
  res.send(renderPage('Why Choose Us', content, '/why-us'));
});

// Reviews - "/reviews"
app.get('/reviews', (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Customer Feedback &amp; Reviews</h1>
    <p class="section-subtitle">Read real feedback or leave your review on our official Google Business Profile.</p>

    <div style="text-align: center; margin-bottom: 3rem;">
      <a href="https://g.page/HoustonRC" target="_blank" rel="noopener" class="btn btn-navy">View Official Google Business Profile &rarr;</a>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
      <div style="background: #FFFFFF; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
        <span style="font-size: 0.75rem; font-weight: 700; background: #FEF3C7; color: #92400E; padding: 0.2rem 0.5rem; border-radius: 4px;">Sample Review</span>
        <p style="font-style: italic; margin: 1rem 0; color: var(--text-muted);">“The inspection process was completely clear. They showed me high-res photos of the damage before offering repair options.”</p>
        <strong>- Local Houston Resident</strong>
      </div>

      <div style="background: #FFFFFF; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
        <span style="font-size: 0.75rem; font-weight: 700; background: #FEF3C7; color: #92400E; padding: 0.2rem 0.5rem; border-radius: 4px;">Sample Review</span>
        <p style="font-style: italic; margin: 1rem 0; color: var(--text-muted);">“Having a customer portal to follow project stages was great. Fast service and clean crew.”</p>
        <strong>- Northwest Houston Homeowner</strong>
      </div>
    </div>
  </div>
  `;
  res.send(renderPage('Reviews', content, '/reviews'));
});

// Resources / Updates - "/updates"
app.get('/updates', (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Roofing Resources &amp; Guides</h1>
    <p class="section-subtitle">Educational guidance for homeowners and property managers in the greater Houston area.</p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem;">
      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">After a Hailstorm: Homeowner Checklist</h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">Steps to inspect your property safely and document storm damage after severe Texas weather.</p>
        <span style="font-size: 0.8rem; color: var(--accent-orange); font-weight: 700;">Educational Guide</span>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">Repair or Replace: How to Decide</h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">Key factors including roof age, shingle condition, and leak history to evaluate replacement timing.</p>
        <span style="font-size: 0.8rem; color: var(--accent-orange); font-weight: 700;">Educational Guide</span>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 0.75rem;">Texas Roof Insurance Laws Explained</h3>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">Understanding homeowner responsibilities, statutory deductible requirements, and working with your carrier.</p>
        <span style="font-size: 0.8rem; color: var(--accent-orange); font-weight: 700;">Compliance Notice</span>
      </div>
    </div>
  </div>
  `;
  res.send(renderPage('Roofing Resources', content, '/updates'));
});

// FAQ - "/faq"
app.get('/faq', (req, res) => {
  const content = `
  <div class="container" style="max-width: 800px;">
    <h1 class="section-title">Frequently Asked Questions</h1>
    <p class="section-subtitle">Answers to common questions about roof inspections, repairs, and scheduling.</p>

    <div style="display: flex; flex-direction: column; gap: 1.25rem;">
      <div style="background: #FFFFFF; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); font-size: 1.1rem; margin-bottom: 0.5rem;">How does online appointment booking work?</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">Select your service, choose a property type, and pick an available date and time. Our system reserves your slot immediately and provides a unique booking reference.</p>
      </div>

      <div style="background: #FFFFFF; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); font-size: 1.1rem; margin-bottom: 0.5rem;">What is your policy on insurance deductibles?</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">Under Texas HB 2102, contractors are strictly prohibited from absorbing, waiving, or rebating insurance deductibles. Homeowners are legally responsible for paying their policy deductible.</p>
      </div>

      <div style="background: #FFFFFF; padding: 1.5rem; border-radius: 12px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); font-size: 1.1rem; margin-bottom: 0.5rem;">Can I reschedule or cancel my appointment?</h3>
        <p style="color: var(--text-muted); font-size: 0.95rem;">Yes, you can cancel or reschedule through your customer dashboard up to 24 hours prior to your scheduled time slot.</p>
      </div>
    </div>
  </div>
  `;
  res.send(renderPage('FAQ', content, '/faq'));
});

// Contact - "/contact"
app.get('/contact', (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Contact Houston Roofing &amp; Construction</h1>
    <p class="section-subtitle">Get in touch with our team or request a call back.</p>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 3rem;">
      <div style="background: #FFFFFF; padding: 2rem; border-radius: 16px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Office Location &amp; Contact</h3>
        <p style="margin-bottom: 0.75rem;"><strong>Address:</strong><br>11330 West Rd, Houston, TX 77065</p>
        <p style="margin-bottom: 1.25rem;"><strong>Phone:</strong><br><a href="tel:+18322373737" style="color: var(--accent-orange); font-weight: 700; text-decoration: none;">(832) 237-3737</a></p>
        <p style="margin-bottom: 1.5rem;"><strong>Directions:</strong><br><a href="https://maps.google.com/?q=11330+West+Rd,+Houston,+TX+77065" target="_blank" rel="noopener" style="color: var(--accent-blue); text-decoration: none; font-weight: 600;">Get Directions on Google Maps &rarr;</a></p>

        <a href="/book" class="btn btn-clay" style="width: 100%;">Book an Online Inspection</a>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 16px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Send a Message</h3>
        <form id="contact-form" onsubmit="handleContactSubmit(event)">
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem;">Full Name</label>
            <input type="text" id="contact-name" required style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem;">Phone Number</label>
            <input type="tel" id="contact-phone" required style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem;">Email Address</label>
            <input type="email" id="contact-email" required style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          <div style="margin-bottom: 1.25rem;">
            <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem;">Message / Inquiry</label>
            <textarea id="contact-message" rows="4" required style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;"></textarea>
          </div>
          <div id="contact-msg-status" style="margin-bottom: 1rem; font-size: 0.85rem;"></div>
          <button type="submit" class="btn btn-navy" style="width: 100%;">Submit Message</button>
        </form>
      </div>
    </div>
  </div>

  <script>
    async function handleContactSubmit(e) {
      e.preventDefault();
      const statusEl = document.getElementById('contact-msg-status');
      statusEl.innerText = 'Submitting message...'; statusEl.style.color = '#32A7E8';

      try {
        const res = await fetch('/api/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fullName: document.getElementById('contact-name').value,
            phone: document.getElementById('contact-phone').value,
            email: document.getElementById('contact-email').value,
            message: document.getElementById('contact-message').value
          })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          statusEl.innerText = 'Thank you! Your message has been received.'; statusEl.style.color = '#42C6B1';
          document.getElementById('contact-form').reset();
        } else {
          statusEl.innerText = data.error || 'Submission failed.'; statusEl.style.color = '#E53E3E';
        }
      } catch (err) {
        statusEl.innerText = 'Error connecting to server.'; statusEl.style.color = '#E53E3E';
      }
    }
  </script>
  `;
  res.send(renderPage('Contact Us', content, '/contact'));
});

// Privacy & Terms
app.get('/privacy', (req, res) => {
  res.send(renderPage('Privacy Policy', `<div class="container"><h1>Privacy Policy</h1><p style="margin-top:1rem;">Information collected via booking forms is strictly used for service scheduling and project updates.</p></div>`, '/privacy'));
});
app.get('/terms', (req, res) => {
  res.send(renderPage('Terms of Service', `<div class="container"><h1>Terms of Service</h1><p style="margin-top:1rem;">Appointments subject to confirmation and server-side availability checking.</p></div>`, '/terms'));
});

// Booking Route - "/book"
app.get('/book', (req, res) => {
  const content = `
  <div class="container" style="max-width: 850px;">
    <h1 class="section-title">Schedule Your Inspection</h1>
    <p class="section-subtitle">Real-time appointment scheduling with instant confirmation.</p>

    <div style="background: #FFFFFF; border-radius: 18px; border: 1px solid #E2E8F0; padding: 2.5rem; box-shadow: var(--shadow-soft);">
      
      <form id="booking-wizard" onsubmit="handleBookingSubmit(event)">
        <!-- Step 1 -->
        <div id="step-1" class="wizard-step">
          <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Step 1: Select Required Service</h3>
          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
            <label style="border: 2px solid #E2E8F0; padding: 1rem; border-radius: 8px; cursor: pointer; display: block;">
              <input type="radio" name="serviceType" value="Free roof inspection" checked> <strong>Free Roof Inspection</strong>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">60 min comprehensive inspection</div>
            </label>
            <label style="border: 2px solid #E2E8F0; padding: 1rem; border-radius: 8px; cursor: pointer; display: block;">
              <input type="radio" name="serviceType" value="Free estimate"> <strong>Free Estimate</strong>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">60 min project evaluation</div>
            </label>
            <label style="border: 2px solid #E2E8F0; padding: 1rem; border-radius: 8px; cursor: pointer; display: block;">
              <input type="radio" name="serviceType" value="Storm or hail damage assessment"> <strong>Storm Damage Assessment</strong>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">90 min detailed assessment</div>
            </label>
            <label style="border: 2px solid #E2E8F0; padding: 1rem; border-radius: 8px; cursor: pointer; display: block;">
              <input type="radio" name="serviceType" value="Roof repair visit"> <strong>Roof Repair Visit</strong>
              <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem;">60 min targeted leak repair evaluation</div>
            </label>
          </div>
          <button type="button" class="btn btn-clay" onclick="goToStep(2)">Continue to Property Info &rarr;</button>
        </div>

        <!-- Step 2 -->
        <div id="step-2" class="wizard-step" style="display: none;">
          <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Step 2: Property &amp; Address</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Property Type</label>
            <select id="prop-type" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
              <option value="Single-family home">Single-family home</option>
              <option value="Townhome">Townhome</option>
              <option value="Commercial building">Commercial building</option>
              <option value="Multi-family community">Multi-family community</option>
            </select>
          </div>
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Street Address</label>
            <input type="text" id="prop-street" required placeholder="123 Main St" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
            <div>
              <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">City / State</label>
              <input type="text" id="prop-city" value="Houston, TX" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
            </div>
            <div>
              <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">ZIP Code</label>
              <input type="text" id="prop-zip" required placeholder="77065" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
            </div>
          </div>
          <div style="display: flex; gap: 1rem;">
            <button type="button" class="btn btn-outline" onclick="goToStep(1)">&larr; Back</button>
            <button type="button" class="btn btn-clay" onclick="fetchSlotsAndNext()">Select Date &amp; Time &rarr;</button>
          </div>
        </div>

        <!-- Step 3 -->
        <div id="step-3" class="wizard-step" style="display: none;">
          <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Step 3: Select Date &amp; Available Time Slot</h3>
          <div style="margin-bottom: 1.5rem;">
            <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Select Date</label>
            <input type="date" id="booking-date" onchange="loadSlotsForSelectedDate()" style="padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          
          <div id="slots-container" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(110px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem;">
            <p style="color: var(--text-muted); grid-column: 1/-1;">Select a date above to check available slots...</p>
          </div>

          <div style="display: flex; gap: 1rem;">
            <button type="button" class="btn btn-outline" onclick="goToStep(2)">&larr; Back</button>
            <button type="button" class="btn btn-clay" id="step3-next-btn" disabled onclick="goToStep(4)">Customer Details &rarr;</button>
          </div>
        </div>

        <!-- Step 4 -->
        <div id="step-4" class="wizard-step" style="display: none;">
          <h3 style="color: var(--navy); margin-bottom: 1.25rem;">Step 4: Your Contact Information</h3>
          <div style="margin-bottom: 1rem;">
            <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Full Name</label>
            <input type="text" id="cust-name" required placeholder="John Doe" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
            <div>
              <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Phone Number</label>
              <input type="tel" id="cust-phone" required placeholder="(832) 000-0000" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
            </div>
            <div>
              <label style="display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.3rem;">Email Address</label>
              <input type="email" id="cust-email" required placeholder="john@example.com" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
            </div>
          </div>
          <div style="margin-bottom: 1.25rem;">
            <label style="display: flex; align-items: flex-start; gap: 0.5rem; font-size: 0.85rem; color: var(--text-muted); cursor: pointer;">
              <input type="checkbox" id="consent-check" required style="margin-top: 0.2rem;">
              <span>I consent to receive appointment notifications and updates regarding my roofing request.</span>
            </label>
          </div>

          <div id="booking-error" style="color: #E53E3E; margin-bottom: 1rem; font-size: 0.85rem; display: none;"></div>

          <div style="display: flex; gap: 1rem;">
            <button type="button" class="btn btn-outline" onclick="goToStep(3)">&larr; Back</button>
            <button type="submit" class="btn btn-clay" id="submit-booking-btn">Confirm &amp; Complete Booking</button>
          </div>
        </div>
      </form>

      <!-- Step 5: Success Confirmation -->
      <div id="step-5" style="display: none; text-align: center; padding: 2rem 1rem;">
        <div style="width: 64px; height: 64px; background: #D1FAE5; color: #059669; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 1.5rem; font-size: 2rem; font-weight: 800;">✓</div>
        <h2 style="color: var(--navy); margin-bottom: 0.5rem;">Appointment Scheduled!</h2>
        <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Your inspection request has been created in our database.</p>
        
        <div style="background: var(--bg-light); padding: 1.5rem; border-radius: 12px; margin-bottom: 2rem; text-align: left;">
          <p><strong>Booking Reference:</strong> <span id="conf-ref" style="color: var(--accent-orange); font-weight: 800;"></span></p>
          <p><strong>Service:</strong> <span id="conf-service"></span></p>
          <p><strong>Date &amp; Time:</strong> <span id="conf-time"></span></p>
          <p><strong>Property Address:</strong> <span id="conf-address"></span></p>
        </div>

        <a href="/dashboard" class="btn btn-navy">View Customer Dashboard</a>
      </div>

    </div>
  </div>

  <script>
    let selectedSlotTime = null;

    function goToStep(num) {
      document.querySelectorAll('.wizard-step').forEach(s => s.style.display = 'none');
      document.getElementById('step-' + num).style.display = 'block';
    }

    function fetchSlotsAndNext() {
      const today = new Date().toISOString().split('T')[0];
      const dateEl = document.getElementById('booking-date');
      dateEl.min = today;
      if (!dateEl.value) dateEl.value = today;
      goToStep(3);
      loadSlotsForSelectedDate();
    }

    async function loadSlotsForSelectedDate() {
      const dateVal = document.getElementById('booking-date').value;
      const serviceVal = document.querySelector('input[name="serviceType"]:checked').value;
      const container = document.getElementById('slots-container');
      container.innerHTML = '<p style="grid-column: 1/-1;">Checking live slot availability...</p>';
      selectedSlotTime = null;
      document.getElementById('step3-next-btn').disabled = true;

      try {
        const res = await fetch('/api/availability?date=' + dateVal + '&service=' + encodeURIComponent(serviceVal));
        const data = await res.json();
        
        if (data.availableSlots && data.availableSlots.length > 0) {
          container.innerHTML = data.availableSlots.map(slot => \`
            <button type="button" class="btn btn-outline slot-btn" style="padding:0.5rem; font-size:0.85rem;" onclick="selectSlot('\${slot}', this)">\${slot}</button>
          \`).join('');
        } else {
          container.innerHTML = '<p style="grid-column: 1/-1; color:#E53E3E;">No slots available on this date or blackout date. Please pick another date.</p>';
        }
      } catch (err) {
        container.innerHTML = '<p style="grid-column: 1/-1; color:#E53E3E;">Failed to fetch slots.</p>';
      }
    }

    function selectSlot(timeStr, btn) {
      document.querySelectorAll('.slot-btn').forEach(b => {
        b.style.background = 'transparent';
        b.style.color = 'var(--navy)';
      });
      btn.style.background = 'var(--accent-orange)';
      btn.style.color = '#FFFFFF';
      selectedSlotTime = timeStr;
      document.getElementById('step3-next-btn').disabled = false;
    }

    async function handleBookingSubmit(e) {
      e.preventDefault();
      const errEl = document.getElementById('booking-error');
      errEl.style.display = 'none';

      const payload = {
        serviceType: document.querySelector('input[name="serviceType"]:checked').value,
        propertyType: document.getElementById('prop-type').value,
        streetAddress: document.getElementById('prop-street').value,
        city: document.getElementById('prop-city').value,
        zipCode: document.getElementById('prop-zip').value,
        selectedDate: document.getElementById('booking-date').value,
        selectedTime: selectedSlotTime,
        fullName: document.getElementById('cust-name').value,
        phone: document.getElementById('cust-phone').value,
        email: document.getElementById('cust-email').value,
        consent: document.getElementById('consent-check').checked
      };

      try {
        const res = await fetch('/api/bookings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.success) {
          document.querySelectorAll('.wizard-step').forEach(s => s.style.display = 'none');
          document.getElementById('conf-ref').innerText = data.bookingRef;
          document.getElementById('conf-service').innerText = payload.serviceType;
          document.getElementById('conf-time').innerText = payload.selectedDate + ' @ ' + payload.selectedTime;
          document.getElementById('conf-address').innerText = payload.streetAddress + ', ' + payload.city;
          document.getElementById('step-5').style.display = 'block';
        } else {
          errEl.innerText = data.error || 'Failed to submit booking';
          errEl.style.display = 'block';
        }
      } catch (err) {
        errEl.innerText = 'Network error while creating booking';
        errEl.style.display = 'block';
      }
    }
  </script>
  `;
  res.send(renderPage('Book Online', content, '/book'));
});

// Customer Dashboard - "/dashboard"
app.get('/dashboard', async (req, res) => {
  const content = `
  <div class="container">
    <h1 class="section-title">Customer Project Portal</h1>
    <p class="section-subtitle">Track your appointment and real-time roof replacement progress.</p>

    <div id="dash-auth-box" style="background: #FFFFFF; padding: 2rem; border-radius: 14px; border: 1px solid #E2E8F0; max-width: 500px; margin: 0 auto 3rem;">
      <h3 style="color: var(--navy); margin-bottom: 1rem; text-align: center;">Lookup Appointment or Sign In</h3>
      <div style="margin-bottom: 1rem;">
        <label style="display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.3rem;">Email Address or Booking Reference</label>
        <input type="text" id="dash-lookup-input" placeholder="e.g. HOU-12345 or john@example.com" style="width: 100%; padding: 0.7rem; border: 1px solid #E2E8F0; border-radius: 6px;">
      </div>
      <button class="btn btn-navy" style="width: 100%; margin-bottom: 1.5rem;" onclick="loadCustomerRecords()">Lookup Records</button>

      <hr style="border: none; border-top: 1px solid #E2E8F0; margin-bottom: 1.5rem;">

      <h4 style="color: var(--navy); margin-bottom: 0.75rem; text-align: center;">Customer Account Registration / Sign In</h4>
      <div style="margin-bottom: 0.75rem;">
        <input type="email" id="acc-email" placeholder="Email" style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;">
      </div>
      <div style="margin-bottom: 1rem;">
        <input type="password" id="acc-pass" placeholder="Password" style="width: 100%; padding: 0.65rem; border: 1px solid #E2E8F0; border-radius: 6px;">
      </div>
      <div style="display: flex; gap: 0.5rem;">
        <button class="btn btn-outline" style="flex: 1;" onclick="handleAccountRegister()">Register</button>
        <button class="btn btn-clay" style="flex: 1;" onclick="handleAccountLogin()">Log In</button>
      </div>
    </div>

    <div id="dash-records-view" style="display: none;">
      <div style="background: #FFFFFF; padding: 2rem; border-radius: 16px; border: 1px solid #E2E8F0; margin-bottom: 2rem;">
        <h3 style="color: var(--navy); margin-bottom: 1rem;">Your Appointments</h3>
        <div id="dash-appointments-list"></div>
      </div>

      <div style="background: #FFFFFF; padding: 2rem; border-radius: 16px; border: 1px solid #E2E8F0;">
        <h3 style="color: var(--navy); margin-bottom: 1rem;">Project Progress Tracker</h3>
        <div id="dash-projects-list"></div>
      </div>
    </div>
  </div>

  <script>
    async function handleAccountRegister() {
      const email = document.getElementById('acc-email').value.trim();
      const password = document.getElementById('acc-pass').value;
      if (!email || !password) return alert('Enter email and password.');

      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, fullName: email.split('@')[0] })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          alert('Account created! Fetching records...');
          document.getElementById('dash-lookup-input').value = email;
          loadCustomerRecords();
        } else {
          alert(data.error || 'Registration failed.');
        }
      } catch (err) {
        alert('Network error.');
      }
    }

    async function handleAccountLogin() {
      const email = document.getElementById('acc-email').value.trim();
      const password = document.getElementById('acc-pass').value;
      if (!email || !password) return alert('Enter email and password.');

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          document.getElementById('dash-lookup-input').value = email;
          loadCustomerRecords();
        } else {
          alert(data.error || 'Login failed.');
        }
      } catch (err) {
        alert('Network error.');
      }
    }

    async function cancelBooking(id) {
      if (!confirm('Cancel this appointment slot?')) return;
      try {
        const res = await fetch('/api/bookings/' + id + '/cancel', { method: 'PATCH' });
        if (res.ok) {
          alert('Appointment cancelled.');
          loadCustomerRecords();
        } else {
          alert('Failed to cancel.');
        }
      } catch (e) {
        alert('Error cancelling booking.');
      }
    }

    async function loadCustomerRecords() {
      const val = document.getElementById('dash-lookup-input').value.trim();
      if (!val) return alert('Please enter an email or booking reference.');

      try {
        const res = await fetch('/api/bookings/mine?query=' + encodeURIComponent(val));
        const data = await res.json();
        
        if (res.ok && data.bookings) {
          document.getElementById('dash-auth-box').style.display = 'none';
          document.getElementById('dash-records-view').style.display = 'block';

          const apptContainer = document.getElementById('dash-appointments-list');
          if (data.bookings.length === 0) {
            apptContainer.innerHTML = '<p style="color:var(--text-muted)">No active appointments found.</p>';
          } else {
            apptContainer.innerHTML = data.bookings.map(b => \`
              <div style="padding: 1rem; border: 1px solid #E2E8F0; border-radius: 8px; margin-bottom: 0.75rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                  <strong>Ref: \${b.bookingRef}</strong> - \${b.serviceType}<br>
                  <small style="color:var(--text-muted)">Scheduled: \${b.selectedDate} @ \${b.selectedTime}</small>
                </div>
                <div style="display:flex; gap:0.5rem; align-items:center;">
                  <span style="font-size: 0.8rem; font-weight: 700; padding: 0.3rem 0.6rem; border-radius: 12px; background: #E0F2FE; color: #075985;">\${b.status}</span>
                  \${b.status !== 'cancelled' ? \`<button class="btn btn-outline" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="cancelBooking('\${b._id}')">Cancel</button>\` : ''}
                </div>
              </div>
            \`).join('');
          }

          const projContainer = document.getElementById('dash-projects-list');
          if (!data.projects || data.projects.length === 0) {
            projContainer.innerHTML = '<p style="color:var(--text-muted)">No active roof project in progress for this account.</p>';
          } else {
            projContainer.innerHTML = data.projects.map(p => \`
              <div style="padding: 1.5rem; border: 1px solid #E2E8F0; border-radius: 12px; margin-bottom: 1rem;">
                <h4 style="color: var(--navy);">Stage: \${p.currentStage}</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">Assigned PM: \${p.assignedManager || 'Operations Team'}</p>
                
                <div style="background: var(--bg-light); padding: 1rem; border-radius: 8px;">
                  <strong>Recent Updates:</strong>
                  \${p.stageHistory ? p.stageHistory.map(h => \`<div style="font-size:0.85rem; margin-top:0.4rem;">• \${h.stage}: \${h.note} (\${new Date(h.updatedAt).toLocaleDateString()})</div>\`).join('') : 'No updates recorded yet.'}
                </div>
              </div>
            \`).join('');
          }
        } else {
          alert('No records found for that input.');
        }
      } catch (err) {
        alert('Error retrieving records.');
      }
    }
  </script>
  `;
  res.send(renderPage('Customer Dashboard', content, '/dashboard'));
});

// ------------------- PUBLIC REST API ENDPOINTS -------------------

// Health check endpoint (safe diagnostics - no secrets exposed)
app.get('/api/health', async (req, res) => {
  const db = await connectToDatabase();
  res.json({
    status: db ? 'healthy' : 'degraded',
    timestamp: new Date().toISOString(),
    databaseConnected: !!db,
    databaseError: db ? null : lastDbError,
    env: {
      MONGODB_URI: !!process.env.MONGODB_URI,
      ADMIN_USERNAME: !!process.env.ADMIN_USERNAME,
      ADMIN_PASSWORD: !!process.env.ADMIN_PASSWORD
    },
    version: '1.0.0'
  });
});

// Customer Auth API
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const db = await connectToDatabase();
    if (!db) return res.status(503).json({ error: 'Service temporarily unavailable. Please try again shortly or call (832) 237-3737.' });

    const existing = await db.collection('users').findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ error: 'Account already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const userDoc = {
      email: email.toLowerCase(),
      passwordHash,
      fullName: fullName || email.split('@')[0],
      createdAt: new Date()
    };
    const result = await db.collection('users').insertOne(userDoc);

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');
    await db.collection('sessions').insertOne({
      tokenHash,
      userId: result.insertedId,
      email: email.toLowerCase(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie('user_session', sessionToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
    res.json({ success: true, userId: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: 'Failed to register account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  try {
    const db = await connectToDatabase();
    if (!db) return res.status(503).json({ error: 'Service temporarily unavailable. Please try again shortly or call (832) 237-3737.' });

    const user = await db.collection('users').findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid email or password' });

    const sessionToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');
    await db.collection('sessions').insertOne({
      tokenHash,
      userId: user._id,
      email: user.email,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    });

    res.cookie('user_session', sessionToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
    res.json({ success: true, userId: user._id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies.user_session;
  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const db = await connectToDatabase();
    if (db) await db.collection('sessions').deleteOne({ tokenHash });
  }
  res.clearCookie('user_session');
  res.json({ success: true });
});

app.get('/api/auth/me', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({ authenticated: true, email: req.session.email, userId: req.session.userId });
  }
  res.json({ authenticated: false });
});

// Customer Booking Reschedule / Cancel APIs
app.patch('/api/bookings/:id/cancel', async (req, res) => {
  try {
    const db = await connectToDatabase();
    if (!db) return res.status(503).json({ error: 'Service temporarily unavailable. Please try again shortly or call (832) 237-3737.' });

    await db.collection('bookings').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status: 'cancelled', updatedAt: new Date() } }
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to cancel booking' });
  }
});

app.patch('/api/bookings/:id/reschedule', async (req, res) => {
  const { selectedDate, selectedTime } = req.body || {};
  if (!selectedDate || !selectedTime) return res.status(400).json({ error: 'New date and time required' });

  try {
    const db = await connectToDatabase();
    if (!db) return res.status(503).json({ error: 'Service temporarily unavailable. Please try again shortly or call (832) 237-3737.' });

    await db.collection('bookings').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { selectedDate, selectedTime, updatedAt: new Date() } }
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to reschedule booking' });
  }
});

// Announcements API
app.get('/api/announcements/active', async (req, res) => {
  try {
    const db = await connectToDatabase();
    if (!db) return res.json([]);
    const items = await db.collection('announcements').find({ active: true }).toArray();
    res.json(items);
  } catch (e) {
    res.json([]);
  }
});

// Slot Availability Calculation API
app.get('/api/availability', async (req, res) => {
  const { date, service } = req.query;
  if (!date) return res.status(400).json({ error: 'Date required.' });

  try {
    const db = await connectToDatabase();
    let blackoutDates = ['2026-11-26', '2026-12-25', '2027-01-01'];
    let capacityPerSlot = 2;

    if (db) {
      const settings = await db.collection('settings').findOne({ type: 'global' });
      if (settings) {
        if (settings.blackoutDates) blackoutDates = settings.blackoutDates;
        if (settings.appointmentTypes && settings.appointmentTypes[service]) {
          capacityPerSlot = settings.appointmentTypes[service].capacity || 2;
        }
      }
    }

    if (blackoutDates.includes(date)) {
      return res.json({ date, availableSlots: [], reason: 'Blackout date' });
    }

    // Default daily time slots
    const possibleSlots = [
      '08:00 AM', '09:00 AM', '10:00 AM', '11:00 AM',
      '01:00 PM', '02:00 PM', '03:00 PM', '04:00 PM', '05:00 PM'
    ];

    if (!db) {
      return res.json({ date, availableSlots: possibleSlots });
    }

    // Check capacity against slotOccupancy collection
    const occupiedSlots = await db.collection('slotOccupancy').aggregate([
      { $match: { dateKey: date } },
      { $group: { _id: '$timeSlot', count: { $sum: 1 } } }
    ]).toArray();

    const fullSlotsMap = {};
    occupiedSlots.forEach(slot => {
      if (slot.count >= capacityPerSlot) {
        fullSlotsMap[slot._id] = true;
      }
    });

    const availableSlots = possibleSlots.filter(s => !fullSlotsMap[s]);
    res.json({ date, availableSlots, timezone: 'America/Chicago' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to calculate slot availability' });
  }
});

// Submit Booking Endpoint with Concurrent Capacity Guard
app.post('/api/bookings', async (req, res) => {
  const { serviceType, propertyType, streetAddress, city, zipCode, selectedDate, selectedTime, fullName, phone, email, consent } = req.body || {};

  if (!serviceType || !streetAddress || !zipCode || !selectedDate || !selectedTime || !fullName || !phone || !email || !consent) {
    return res.status(400).json({ error: 'All required booking fields must be completed.' });
  }

  try {
    const db = await connectToDatabase();
    if (!db) return res.status(503).json({ error: 'Booking is temporarily unavailable. Please call (832) 237-3737 to schedule.' });

    const slotKey = `${selectedDate}_${selectedTime}_${fullName.replace(/\s+/g, '_')}`;

    // Atomic insert into slotOccupancy to enforce concurrency capacity limits
    try {
      await db.collection('slotOccupancy').insertOne({
        slotKey,
        dateKey: selectedDate,
        timeSlot: selectedTime,
        createdAt: new Date()
      });
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).json({ error: 'Selected appointment slot is already fully occupied. Please select another time.' });
      }
      throw err;
    }

    const bookingRef = 'HOU-' + crypto.randomBytes(3).toString('hex').toUpperCase();

    const bookingDoc = {
      bookingRef,
      serviceType,
      propertyType,
      streetAddress,
      city: city || 'Houston',
      zipCode,
      selectedDate,
      selectedTime,
      fullName,
      phone,
      email: email.toLowerCase(),
      consentTimestamp: new Date(),
      status: 'pending',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    await db.collection('bookings').insertOne(bookingDoc);

    res.json({
      success: true,
      bookingRef,
      message: 'Booking created successfully'
    });
  } catch (err) {
    console.error('Booking submission error:', err);
    res.status(500).json({ error: 'Server error creating booking' });
  }
});

// Customer Lookup Endpoint
app.get('/api/bookings/mine', async (req, res) => {
  const query = (req.query.query || '').trim().toLowerCase();
  if (!query) return res.status(400).json({ error: 'Query param required' });

  try {
    const db = await connectToDatabase();
    if (!db) return res.json({ bookings: [], projects: [] });

    const bookings = await db.collection('bookings').find({
      $or: [
        { email: query },
        { bookingRef: query.toUpperCase() }
      ]
    }).toArray();

    const projects = await db.collection('projects').find({
      $or: [
        { customerEmail: query },
        { bookingRef: query.toUpperCase() }
      ]
    }).toArray();

    res.json({ bookings, projects });
  } catch (err) {
    res.status(500).json({ error: 'Failed to search customer records' });
  }
});

// Public Contact Form API
app.post('/api/contact', async (req, res) => {
  const { fullName, phone, email, message } = req.body || {};
  if (!fullName || !phone || !email || !message) {
    return res.status(400).json({ error: 'All contact fields are required.' });
  }

  try {
    const db = await connectToDatabase();
    if (!db) {
      return res.status(503).json({ error: 'Our messaging system is temporarily unavailable. Please call (832) 237-3737.' });
    }
    await db.collection('contactMessages').insertOne({
      fullName,
      phone,
      email: String(email).toLowerCase(),
      message,
      createdAt: new Date()
    });
    res.json({ success: true, message: 'Message stored successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit contact request' });
  }
});

// Mount Admin Router Module from admin.js
const adminRouter = createAdminRouter({ getDb, requireAdminAuth });
app.use('/admin', adminRouter);
app.use('/api/admin', adminRouter);

// 404 + global error handler (prevents crashes -> FUNCTION_INVOCATION_FAILED)
app.use((req, res) => res.status(404).send('Not found'));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid request body' });
  res.status(500).json({ error: 'Internal server error' });
});

process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));

// Start server locally
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Houston Roofing Server active on http://localhost:${PORT}`);
  });
}

// Export for Vercel
module.exports = app;
