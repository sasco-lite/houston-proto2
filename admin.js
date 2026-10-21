/**
 * Houston Roofing & Construction - Admin Dashboard Module
 * File: admin.js
 */

const express = require('express');
const { ObjectId } = require('mongodb');
const crypto = require('crypto');

function createAdminRouter({ getDb, requireAdminAuth }) {
  const router = express.Router();

  // Helper for safe audit logging
  async function logAudit(db, req, action, targetType, targetId, details) {
    try {
      await db.collection('auditLogs').insertOne({
        action,
        targetType,
        targetId: targetId ? String(targetId) : null,
        details,
        adminUser: req.session ? req.session.username : 'system',
        ip: req.ip,
        timestamp: new Date()
      });
    } catch (err) {
      console.error('Failed to log audit:', err);
    }
  }

  // Admin Dashboard HTML Page
  router.get('/', async (req, res) => {
    // If not authenticated, render login form inside admin template
    const isAuthenticated = !!(req.session && req.session.isAdmin);

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal - Houston Roofing &amp; Construction</title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-navy: #102238;
      --bg-light: #F7F9FC;
      --surface-white: #FFFFFF;
      --text-main: #102238;
      --text-muted: #65748B;
      --border-color: #E2E8F0;
      --accent-orange: #F47738;
      --accent-blue: #32A7E8;
      --accent-teal: #42C6B1;
      --accent-gold: #F5C36B;
      --status-pending: #F5C36B;
      --status-confirmed: #32A7E8;
      --status-completed: #42C6B1;
      --status-cancelled: #E53E3E;
      --radius-sm: 6px;
      --radius-md: 12px;
      --radius-lg: 18px;
      --shadow-soft: 0 10px 25px -5px rgba(16, 34, 56, 0.05), 0 8px 10px -6px rgba(16, 34, 56, 0.03);
      --glass-bg: rgba(255, 255, 255, 0.85);
      --glass-border: rgba(255, 255, 255, 0.4);
      --glass-shadow: 0 8px 32px 0 rgba(16, 34, 56, 0.08);
      --clay-card: linear-gradient(145deg, #ffffff, #f0f4f9);
      --clay-shadow: 6px 6px 14px #d1d9e6, -6px -6px 14px #ffffff;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, sans-serif; }
    body { background-color: var(--bg-light); color: var(--text-main); line-height: 1.5; min-height: 100vh; }

    /* Admin Layout */
    .admin-container { display: flex; min-height: 100vh; }
    .sidebar {
      width: 260px;
      background: var(--bg-navy);
      color: #FFFFFF;
      padding: 1.5rem 1rem;
      display: flex;
      flex-direction: column;
      position: fixed;
      top: 0; bottom: 0; left: 0;
      z-index: 100;
      transition: transform 0.3s ease;
    }
    .sidebar-brand {
      font-weight: 800;
      font-size: 1.2rem;
      color: #FFFFFF;
      margin-bottom: 2rem;
      padding: 0 0.75rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .sidebar-brand span { color: var(--accent-orange); }
    .nav-list { list-style: none; display: flex; flex-direction: column; gap: 0.5rem; flex: 1; }
    .nav-btn {
      width: 100%;
      background: transparent;
      border: none;
      color: #94A3B8;
      padding: 0.75rem 1rem;
      border-radius: var(--radius-sm);
      text-align: left;
      font-size: 0.95rem;
      font-weight: 500;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      transition: all 0.2s ease;
    }
    .nav-btn:hover, .nav-btn.active {
      background: rgba(255, 255, 255, 0.1);
      color: #FFFFFF;
    }
    .nav-btn.active { background: var(--accent-orange); color: #FFFFFF; }

    .main-content {
      flex: 1;
      margin-left: 260px;
      padding: 2rem;
      max-width: 1400px;
    }

    /* Auth Page */
    .auth-wrapper {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: linear-gradient(135deg, var(--bg-navy) 0%, #1A365D 100%);
      padding: 1.5rem;
    }
    .auth-card {
      background: var(--glass-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--glass-border);
      border-radius: var(--radius-lg);
      padding: 2.5rem;
      width: 100%;
      max-width: 420px;
      box-shadow: var(--glass-shadow);
      color: var(--text-main);
    }
    .auth-title { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem; text-align: center; }
    .auth-subtitle { color: var(--text-muted); font-size: 0.9rem; text-align: center; margin-bottom: 1.5rem; }

    /* UI Components */
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 1px solid var(--border-color);
    }
    .page-title { font-size: 1.75rem; font-weight: 800; color: var(--bg-navy); }
    .btn {
      padding: 0.6rem 1.2rem;
      border-radius: var(--radius-sm);
      font-weight: 600;
      font-size: 0.9rem;
      border: none;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.2s ease;
      text-decoration: none;
    }
    .btn-primary { background: var(--accent-orange); color: #FFFFFF; }
    .btn-primary:hover { background: #E06326; transform: translateY(-1px); }
    .btn-secondary { background: #E2E8F0; color: var(--text-main); }
    .btn-secondary:hover { background: #CBD5E1; }
    .btn-outline { border: 1px solid var(--border-color); background: #FFFFFF; color: var(--text-main); }
    .btn-outline:hover { background: var(--bg-light); }
    .btn-danger { background: #E53E3E; color: #FFFFFF; }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }
    .kpi-card {
      background: var(--surface-white);
      border-radius: var(--radius-md);
      padding: 1.25rem;
      box-shadow: var(--shadow-soft);
      border: 1px solid var(--border-color);
      position: relative;
      overflow: hidden;
    }
    .kpi-title { font-size: 0.85rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .kpi-value { font-size: 2rem; font-weight: 800; color: var(--bg-navy); margin: 0.5rem 0; }
    .kpi-badge { font-size: 0.8rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 20px; display: inline-block; }

    /* Content Cards */
    .card {
      background: var(--surface-white);
      border-radius: var(--radius-md);
      padding: 1.5rem;
      box-shadow: var(--shadow-soft);
      border: 1px solid var(--border-color);
      margin-bottom: 2rem;
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.25rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border-color);
    }
    .card-title { font-size: 1.2rem; font-weight: 700; color: var(--bg-navy); }

    /* Tables */
    .table-responsive { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    th { background: #F8FAFC; color: var(--text-muted); font-weight: 600; padding: 0.75rem 1rem; border-bottom: 1px solid var(--border-color); white-space: nowrap; }
    td { padding: 1rem; border-bottom: 1px solid var(--border-color); color: var(--text-main); }
    tr:hover { background-color: #F8FAFC; }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: capitalize;
    }
    .badge-pending { background: #FEF3C7; color: #92400E; }
    .badge-confirmed { background: #E0F2FE; color: #075985; }
    .badge-completed { background: #D1FAE5; color: #065F46; }
    .badge-cancelled { background: #FEE2E2; color: #991B1B; }

    /* Forms */
    .form-group { margin-bottom: 1.25rem; }
    .form-label { display: block; font-weight: 600; font-size: 0.85rem; margin-bottom: 0.4rem; color: var(--bg-navy); }
    .form-control {
      width: 100%;
      padding: 0.65rem 0.9rem;
      border: 1px solid var(--border-color);
      border-radius: var(--radius-sm);
      font-size: 0.95rem;
      transition: border-color 0.2s ease;
    }
    .form-control:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(50, 167, 232, 0.15); }

    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(16, 34, 56, 0.6);
      backdrop-filter: blur(4px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s ease;
    }
    .modal-overlay.active { opacity: 1; pointer-events: auto; }
    .modal-card {
      background: var(--surface-white);
      border-radius: var(--radius-md);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      padding: 2rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.2);
    }

    /* Toast */
    #toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 2000; display: flex; flex-direction: column; gap: 10px; }
    .toast {
      background: var(--bg-navy);
      color: #FFFFFF;
      padding: 1rem 1.5rem;
      border-radius: var(--radius-sm);
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
      font-size: 0.9rem;
      font-weight: 500;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      animation: slideIn 0.3s ease;
    }
    @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

    /* Tabs & Filters */
    .tab-bar { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.5rem; }
    .tab-btn { padding: 0.5rem 1rem; border: none; background: transparent; font-weight: 600; color: var(--text-muted); cursor: pointer; border-radius: var(--radius-sm); }
    .tab-btn.active { background: #E2E8F0; color: var(--bg-navy); }

    /* Responsive */
    @media (max-width: 768px) {
      .sidebar { transform: translateX(-100%); }
      .sidebar.open { transform: translateX(0); }
      .main-content { margin-left: 0; padding: 1rem; }
    }
  </style>
</head>
<body>

  ${!isAuthenticated ? `
  <!-- Admin Login View -->
  <div class="auth-wrapper">
    <div class="auth-card">
      <div style="text-align: center; margin-bottom: 1.5rem;">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#F47738" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
      </div>
      <h1 class="auth-title">Admin Sign In</h1>
      <p class="auth-subtitle">Houston Roofing &amp; Construction Portal</p>
      <form id="admin-login-form" onsubmit="handleAdminLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">Username</label>
          <input type="text" id="username" class="form-control" required placeholder="Enter admin username">
        </div>
        <div class="form-group">
          <label class="form-label" for="password">Password</label>
          <input type="password" id="password" class="form-control" required placeholder="Enter password">
        </div>
        <div id="login-error" style="color: #E53E3E; font-size: 0.85rem; margin-bottom: 1rem; display: none;"></div>
        <button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center; padding: 0.8rem;">Sign In</button>
      </form>
    </div>
  </div>
  ` : `
  <!-- Authenticated Admin Portal -->
  <div class="admin-container">
    <aside class="sidebar">
      <div class="sidebar-brand">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
        Houston<span>Roofing</span>
      </div>
      <ul class="nav-list">
        <li><button class="nav-btn active" onclick="switchTab('overview')">📊 Overview</button></li>
        <li><button class="nav-btn" onclick="switchTab('bookings')">📅 Bookings &amp; Calendar</button></li>
        <li><button class="nav-btn" onclick="switchTab('projects')">🏗️ Project Management</button></li>
        <li><button class="nav-btn" onclick="switchTab('announcements')">📢 Announcements</button></li>
        <li><button class="nav-btn" onclick="switchTab('settings')">⚙️ Booking Settings</button></li>
        <li><button class="nav-btn" onclick="switchTab('verification')">📋 Claim Verification</button></li>
      </ul>
      <div style="margin-top: auto; padding-top: 1rem; border-top: 1px solid rgba(255,255,255,0.1);">
        <button class="nav-btn" onclick="handleAdminLogout()" style="color: #F87171;">🚪 Logout</button>
      </div>
    </aside>

    <main class="main-content">
      <header class="header-bar">
        <div>
          <h1 class="page-title" id="tab-title">Overview Dashboard</h1>
          <p style="color: var(--text-muted); font-size: 0.9rem;">Live database records &amp; operational metrics</p>
        </div>
        <div style="display: flex; gap: 0.75rem;">
          <a href="/" target="_blank" class="btn btn-outline">🌐 View Website</a>
          <button class="btn btn-primary" onclick="refreshCurrentTab()">🔄 Refresh Data</button>
        </div>
      </header>

      <!-- Section: Overview -->
      <section id="sec-overview" class="tab-section">
        <div class="kpi-grid" id="kpi-container">
          <div class="kpi-card"><div class="kpi-title">Bookings This Week</div><div class="kpi-value" id="kpi-week-bookings">-</div></div>
          <div class="kpi-card"><div class="kpi-title">Upcoming Appointments</div><div class="kpi-value" id="kpi-upcoming">-</div></div>
          <div class="kpi-card"><div class="kpi-title">Pending Requests</div><div class="kpi-value" id="kpi-pending">-</div></div>
          <div class="kpi-card"><div class="kpi-title">Active Projects</div><div class="kpi-value" id="kpi-active-projects">-</div></div>
          <div class="kpi-card"><div class="kpi-title">Completed Projects</div><div class="kpi-value" id="kpi-completed-projects">-</div></div>
          <div class="kpi-card"><div class="kpi-title">Conversion Rate</div><div class="kpi-value" id="kpi-conversion">-</div></div>
        </div>

        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Recent Appointment Activity</h2>
            <button class="btn btn-outline" onclick="switchTab('bookings')">View All</button>
          </div>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Ref</th>
                  <th>Customer</th>
                  <th>Service</th>
                  <th>Date &amp; Time</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="overview-recent-table">
                <tr><td colspan="6" style="text-align:center;">Loading records...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Section: Bookings & Calendar -->
      <section id="sec-bookings" class="tab-section" style="display:none;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Appointment Management</h2>
            <div style="display: flex; gap: 0.5rem;">
              <input type="text" id="booking-search" class="form-control" placeholder="Search customer, ref, or service..." oninput="filterBookings()" style="width: 250px;">
              <select id="booking-status-filter" class="form-control" onchange="filterBookings()" style="width: 150px;">
                <option value="">All Statuses</option>
                <option value="pending">Pending</option>
                <option value="confirmed">Confirmed</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>
          </div>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Ref</th>
                  <th>Customer Info</th>
                  <th>Property Details</th>
                  <th>Service Requested</th>
                  <th>Scheduled Date/Time</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="bookings-table">
                <tr><td colspan="7" style="text-align:center;">Loading bookings...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Section: Projects -->
      <section id="sec-projects" class="tab-section" style="display:none;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Roofing Project Tracker</h2>
            <button class="btn btn-primary" onclick="openNewProjectModal()">+ Create New Project</button>
          </div>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Project ID</th>
                  <th>Customer &amp; Address</th>
                  <th>Service / Scope</th>
                  <th>Manager</th>
                  <th>Current Stage</th>
                  <th>Last Update</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="projects-table">
                <tr><td colspan="7" style="text-align:center;">Loading projects...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Section: Announcements -->
      <section id="sec-announcements" class="tab-section" style="display:none;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Website Announcements</h2>
            <button class="btn btn-primary" onclick="openNewAnnouncementModal()">+ New Announcement</button>
          </div>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Category</th>
                  <th>Message</th>
                  <th>Active Period</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="announcements-table">
                <tr><td colspan="6" style="text-align:center;">Loading announcements...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Section: Settings -->
      <section id="sec-settings" class="tab-section" style="display:none;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Booking Schedule &amp; System Settings</h2>
          </div>
          <form id="settings-form" onsubmit="handleSaveSettings(event)">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem;">
              <div class="form-group">
                <label class="form-label">Configured Timezone</label>
                <input type="text" id="setting-timezone" class="form-control" value="America/Chicago">
              </div>
              <div class="form-group">
                <label class="form-label">Slot Interval (minutes)</label>
                <input type="number" id="setting-slotInterval" class="form-control" value="30">
              </div>
              <div class="form-group">
                <label class="form-label">Minimum Lead Time (hours)</label>
                <input type="number" id="setting-minLeadTimeHours" class="form-control" value="12">
              </div>
              <div class="form-group">
                <label class="form-label">Maximum Horizon (days)</label>
                <input type="number" id="setting-maxHorizonDays" class="form-control" value="60">
              </div>
              <div class="form-group">
                <label class="form-label">Cancellation Cutoff (hours)</label>
                <input type="number" id="setting-cancelCutoffHours" class="form-control" value="24">
              </div>
            </div>

            <h3 style="font-size: 1.1rem; margin: 1.5rem 0 1rem; color: var(--bg-navy);">Operating Hours</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem;">
              <div>
                <label class="form-label">Mon–Fri Hours</label>
                <input type="text" id="setting-hours-weekday" class="form-control" placeholder="08:00-18:00">
              </div>
              <div>
                <label class="form-label">Saturday Hours</label>
                <input type="text" id="setting-hours-saturday" class="form-control" placeholder="08:00-16:00">
              </div>
              <div>
                <label class="form-label">Sunday Hours</label>
                <input type="text" id="setting-hours-sunday" class="form-control" placeholder="10:00-16:00">
              </div>
            </div>

            <h3 style="font-size: 1.1rem; margin: 1.5rem 0 1rem; color: var(--bg-navy);">Blackout Dates</h3>
            <div class="form-group">
              <label class="form-label">Configured Blackout Dates (Comma separated YYYY-MM-DD)</label>
              <textarea id="setting-blackoutDates" class="form-control" rows="3" placeholder="2026-11-26, 2026-12-25, 2027-01-01"></textarea>
            </div>

            <button type="submit" class="btn btn-primary" style="margin-top: 1rem;">Save Booking Settings</button>
          </form>
        </div>
      </section>

      <!-- Section: Verification Checklist -->
      <section id="sec-verification" class="tab-section" style="display:none;">
        <div class="card">
          <div class="card-header">
            <h2 class="card-title">Client Facts &amp; Claim Verification Checklist</h2>
            <span style="font-size: 0.85rem; color: var(--text-muted);">Ensure unconfirmed business claims are held pending client approval</span>
          </div>
          <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1.5rem;">
            Items listed below require client confirmation before public indexation or display. Pending claims remain hidden or flagged on the live site.
          </p>
          <div class="table-responsive">
            <table>
              <thead>
                <tr>
                  <th>Fact / Claim Key</th>
                  <th>Description / Details</th>
                  <th>Verification Status</th>
                  <th>Notes / Approval Record</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="verification-table">
                <tr><td colspan="5" style="text-align:center;">Loading verification checklist...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

    </main>
  </div>

  <!-- Edit Project Stage Modal -->
  <div id="project-modal" class="modal-overlay">
    <div class="modal-card">
      <h3 style="margin-bottom: 1rem; color: var(--bg-navy);" id="modal-project-title">Update Project</h3>
      <form id="project-update-form" onsubmit="handleSaveProjectUpdate(event)">
        <input type="hidden" id="modal-project-id">
        <div class="form-group">
          <label class="form-label">Assigned Project Manager</label>
          <input type="text" id="modal-project-pm" class="form-control" placeholder="Manager Name">
        </div>
        <div class="form-group">
          <label class="form-label">Project Stage</label>
          <select id="modal-project-stage" class="form-control">
            <option value="Request Received">1. Request Received</option>
            <option value="Inspection Scheduled">2. Inspection Scheduled</option>
            <option value="Inspection Complete">3. Inspection Complete</option>
            <option value="Estimate Delivered">4. Estimate Delivered</option>
            <option value="Agreement Signed">5. Agreement Signed</option>
            <option value="Materials &amp; Permits">6. Materials &amp; Permits</option>
            <option value="Installation Scheduled">7. Installation Scheduled</option>
            <option value="Work in Progress">8. Work in Progress</option>
            <option value="Final Inspection">9. Final Inspection</option>
            <option value="Warranty Registered">10. Warranty Registered</option>
            <option value="Complete">11. Complete</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Customer-Visible Update Note</label>
          <textarea id="modal-project-note" class="form-control" rows="3" placeholder="Provide clear updates for the customer dashboard..."></textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Project Photo URL (Validated Link)</label>
          <input type="url" id="modal-project-photourl" class="form-control" placeholder="https://images.unsplash.com/...">
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.5rem;">
          <button type="button" class="btn btn-outline" onclick="closeModal('project-modal')">Cancel</button>
          <button type="submit" class="btn btn-primary">Save Progress Update</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Toast Notifications -->
  <div id="toast-container"></div>
  `}

  <script>
    let allBookingsCache = [];

    function showToast(msg, type) {
      const container = document.getElementById('toast-container');
      if (!container) return;
      const el = document.createElement('div');
      el.className = 'toast';
      el.innerText = msg;
      container.appendChild(el);
      setTimeout(() => el.remove(), 4000);
    }

    async function handleAdminLogin(e) {
      e.preventDefault();
      const errEl = document.getElementById('login-error');
      errEl.style.display = 'none';

      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;

      try {
        const res = await fetch('/api/admin/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          window.location.reload();
        } else {
          errEl.innerText = data.error || 'Login failed';
          errEl.style.display = 'block';
        }
      } catch (err) {
        errEl.innerText = 'Network error. Please try again.';
        errEl.style.display = 'block';
      }
    }

    async function handleAdminLogout() {
      try {
        await fetch('/api/admin/logout', { method: 'POST' });
        window.location.reload();
      } catch (e) {
        window.location.reload();
      }
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-section').forEach(el => el.style.display = 'none');
      document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
      
      const targetSec = document.getElementById('sec-' + tabId);
      if (targetSec) targetSec.style.display = 'block';

      const titles = {
        overview: 'Overview Dashboard',
        bookings: 'Appointments & Calendar',
        projects: 'Project Management',
        announcements: 'Website Announcements',
        settings: 'Booking System Configuration',
        verification: 'Fact & Claim Verification Checklist'
      };
      document.getElementById('tab-title').innerText = titles[tabId] || 'Admin Portal';

      if (window.event && window.event.currentTarget) {
        window.event.currentTarget.classList.add('active');
      }

      loadTabContent(tabId);
    }

    function refreshCurrentTab() {
      const activeBtn = document.querySelector('.nav-btn.active');
      if (activeBtn) {
        activeBtn.click();
      } else {
        switchTab('overview');
      }
      showToast('Dashboard refreshed', 'info');
    }

    async function loadTabContent(tabId) {
      if (tabId === 'overview') {
        loadOverview();
      } else if (tabId === 'bookings') {
        loadBookings();
      } else if (tabId === 'projects') {
        loadProjects();
      } else if (tabId === 'announcements') {
        loadAnnouncements();
      } else if (tabId === 'settings') {
        loadSettings();
      } else if (tabId === 'verification') {
        loadVerification();
      }
    }

    async function loadOverview() {
      try {
        const res = await fetch('/api/admin/overview');
        if (!res.ok) return;
        const data = await res.json();
        
        document.getElementById('kpi-week-bookings').innerText = data.kpis.bookingsThisWeek || 0;
        document.getElementById('kpi-upcoming').innerText = data.kpis.upcomingAppointments || 0;
        document.getElementById('kpi-pending').innerText = data.kpis.pendingRequests || 0;
        document.getElementById('kpi-active-projects').innerText = data.kpis.activeProjects || 0;
        document.getElementById('kpi-completed-projects').innerText = data.kpis.completedProjects || 0;
        document.getElementById('kpi-conversion').innerText = (data.kpis.conversionRate || 0) + '%';

        const tbody = document.getElementById('overview-recent-table');
        if (data.recentBookings && data.recentBookings.length > 0) {
          tbody.innerHTML = data.recentBookings.map(b => \`
            <tr>
              <td><strong>\${b.bookingRef}</strong></td>
              <td>\${escapeHtml(b.fullName)}<br><small style="color:var(--text-muted)">\${escapeHtml(b.phone)}</small></td>
              <td>\${escapeHtml(b.serviceType)}</td>
              <td>\${b.selectedDate} \${b.selectedTime}</td>
              <td><span class="badge badge-\${b.status}">\${b.status}</span></td>
              <td>
                <button class="btn btn-outline" style="padding:0.3rem 0.6rem; font-size:0.8rem;" onclick="switchTab('bookings')">Manage</button>
              </td>
            </tr>
          \`).join('');
        } else {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No recent bookings found.</td></tr>';
        }
      } catch (err) {
        console.error(err);
      }
    }

    async function loadBookings() {
      try {
        const res = await fetch('/api/admin/bookings');
        if (!res.ok) return;
        allBookingsCache = await res.json();
        renderBookingsTable(allBookingsCache);
      } catch (err) {
        console.error(err);
      }
    }

    function filterBookings() {
      const q = document.getElementById('booking-search').value.toLowerCase();
      const st = document.getElementById('booking-status-filter').value;
      const filtered = allBookingsCache.filter(b => {
        const matchQ = !q || b.fullName.toLowerCase().includes(q) || b.bookingRef.toLowerCase().includes(q) || b.serviceType.toLowerCase().includes(q);
        const matchSt = !st || b.status === st;
        return matchQ && matchSt;
      });
      renderBookingsTable(filtered);
    }

    function renderBookingsTable(list) {
      const tbody = document.getElementById('bookings-table');
      if (!list || list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No appointments match your criteria.</td></tr>';
        return;
      }
      tbody.innerHTML = list.map(b => \`
        <tr>
          <td><strong>\${b.bookingRef}</strong></td>
          <td>
            <strong>\${escapeHtml(b.fullName)}</strong><br>
            <small style="color:var(--text-muted)">\${escapeHtml(b.email)} | \${escapeHtml(b.phone)}</small>
          </td>
          <td>\${escapeHtml(b.streetAddress)}, \${escapeHtml(b.city || 'Houston')}</td>
          <td>\${escapeHtml(b.serviceType)}</td>
          <td>\${b.selectedDate} @ \${b.selectedTime}</td>
          <td><span class="badge badge-\${b.status}">\${b.status}</span></td>
          <td>
            <div style="display:flex; gap:0.4rem; flex-wrap:wrap;">
              \${b.status === 'pending' ? \`<button class="btn btn-primary" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="updateBookingStatus('\${b._id}', 'confirmed')">Confirm</button>\` : ''}
              \${b.status !== 'cancelled' ? \`<button class="btn btn-danger" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="updateBookingStatus('\${b._id}', 'cancelled')">Cancel</button>\` : ''}
              <button class="btn btn-secondary" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="convertBookingToProject('\${b._id}')">Convert to Project</button>
            </div>
          </td>
        </tr>
      \`).join('');
    }

    async function updateBookingStatus(id, status) {
      if (!confirm('Are you sure you want to change booking status to ' + status + '?')) return;
      try {
        const res = await fetch('/api/admin/bookings/' + id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status })
        });
        if (res.ok) {
          showToast('Booking status updated to ' + status, 'info');
          loadBookings();
        } else {
          showToast('Failed to update booking', 'error');
        }
      } catch (err) {
        showToast('Error updating booking', 'error');
      }
    }

    async function convertBookingToProject(bookingId) {
      if (!confirm('Convert this booking into an active customer project?')) return;
      try {
        const res = await fetch('/api/admin/projects', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ bookingId })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          showToast('Project created successfully', 'info');
          switchTab('projects');
        } else {
          showToast(data.error || 'Failed to create project', 'error');
        }
      } catch (err) {
        showToast('Error converting booking to project', 'error');
      }
    }

    async function loadProjects() {
      try {
        const res = await fetch('/api/admin/projects');
        if (!res.ok) return;
        const projects = await res.json();
        const tbody = document.getElementById('projects-table');
        if (!projects || projects.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No active projects.</td></tr>';
          return;
        }
        tbody.innerHTML = projects.map(p => \`
          <tr>
            <td><strong>\${p.projectId || p._id.slice(-6)}</strong></td>
            <td>
              <strong>\${escapeHtml(p.customerName)}</strong><br>
              <small style="color:var(--text-muted)">\${escapeHtml(p.propertyAddress || '')}</small>
            </td>
            <td>\${escapeHtml(p.serviceType)}</td>
            <td>\${escapeHtml(p.assignedManager || 'Unassigned')}</td>
            <td><span class="badge badge-confirmed">\${escapeHtml(p.currentStage)}</span></td>
            <td>\${p.updatedAt ? new Date(p.updatedAt).toLocaleDateString() : '-'}</td>
            <td>
              <button class="btn btn-outline" style="padding:0.3rem 0.6rem; font-size:0.8rem;" onclick="openEditProjectModal('\${p._id}', '\${escapeJs(p.currentStage)}', '\${escapeJs(p.assignedManager || '')}')">Update Stage</button>
            </td>
          </tr>
        \`).join('');
      } catch (err) {
        console.error(err);
      }
    }

    function openEditProjectModal(id, stage, manager) {
      document.getElementById('modal-project-id').value = id;
      document.getElementById('modal-project-pm').value = manager;
      document.getElementById('modal-project-stage').value = stage;
      document.getElementById('modal-project-note').value = '';
      document.getElementById('modal-project-photourl').value = '';
      document.getElementById('project-modal').classList.add('active');
    }

    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }

    async function handleSaveProjectUpdate(e) {
      e.preventDefault();
      const id = document.getElementById('modal-project-id').value;
      const assignedManager = document.getElementById('modal-project-pm').value.trim();
      const currentStage = document.getElementById('modal-project-stage').value;
      const updateNote = document.getElementById('modal-project-note').value.trim();
      const photoUrl = document.getElementById('modal-project-photourl').value.trim();

      try {
        const res = await fetch('/api/admin/projects/' + id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ assignedManager, currentStage, updateNote, photoUrl })
        });
        if (res.ok) {
          showToast('Project updated successfully', 'info');
          closeModal('project-modal');
          loadProjects();
        } else {
          showToast('Failed to update project', 'error');
        }
      } catch (err) {
        showToast('Error saving update', 'error');
      }
    }

    async function loadAnnouncements() {
      try {
        const res = await fetch('/api/admin/announcements');
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.getElementById('announcements-table');
        if (!list || list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No announcements configured.</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(a => \`
          <tr>
            <td><strong>\${escapeHtml(a.title)}</strong></td>
            <td>\${escapeHtml(a.category)}</td>
            <td>\${escapeHtml(a.message)}</td>
            <td>\${a.startDate || 'Immediate'} to \${a.endDate || 'Indefinite'}</td>
            <td><span class="badge \${a.active ? 'badge-completed' : 'badge-cancelled'}">\${a.active ? 'Active' : 'Disabled'}</span></td>
            <td>
              <button class="btn btn-outline" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="toggleAnnouncement('\${a._id}', \${!a.active})">\${a.active ? 'Disable' : 'Activate'}</button>
            </td>
          </tr>
        \`).join('');
      } catch (err) {
        console.error(err);
      }
    }

    async function toggleAnnouncement(id, active) {
      try {
        const res = await fetch('/api/admin/announcements/' + id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ active })
        });
        if (res.ok) {
          showToast('Announcement status updated', 'info');
          loadAnnouncements();
        }
      } catch (err) {
        showToast('Error updating announcement', 'error');
      }
    }

    async function loadSettings() {
      try {
        const res = await fetch('/api/admin/settings');
        if (!res.ok) return;
        const settings = await res.json();
        if (settings) {
          document.getElementById('setting-timezone').value = settings.timezone || 'America/Chicago';
          document.getElementById('setting-slotInterval').value = settings.slotIntervalMinutes || 30;
          document.getElementById('setting-minLeadTimeHours').value = settings.minLeadTimeHours || 12;
          document.getElementById('setting-maxHorizonDays').value = settings.maxHorizonDays || 60;
          document.getElementById('setting-cancelCutoffHours').value = settings.cancelCutoffHours || 24;
          if (settings.businessHours) {
            document.getElementById('setting-hours-weekday').value = settings.businessHours.mon_fri || '08:00-18:00';
            document.getElementById('setting-hours-saturday').value = settings.businessHours.saturday || '08:00-16:00';
            document.getElementById('setting-hours-sunday').value = settings.businessHours.sunday || '10:00-16:00';
          }
          if (settings.blackoutDates) {
            document.getElementById('setting-blackoutDates').value = settings.blackoutDates.join(', ');
          }
        }
      } catch (err) {
        console.error(err);
      }
    }

    async function handleSaveSettings(e) {
      e.preventDefault();
      const payload = {
        timezone: document.getElementById('setting-timezone').value,
        slotIntervalMinutes: parseInt(document.getElementById('setting-slotInterval').value, 10),
        minLeadTimeHours: parseInt(document.getElementById('setting-minLeadTimeHours').value, 10),
        maxHorizonDays: parseInt(document.getElementById('setting-maxHorizonDays').value, 10),
        cancelCutoffHours: parseInt(document.getElementById('setting-cancelCutoffHours').value, 10),
        businessHours: {
          mon_fri: document.getElementById('setting-hours-weekday').value,
          saturday: document.getElementById('setting-hours-saturday').value,
          sunday: document.getElementById('setting-hours-sunday').value
        },
        blackoutDates: document.getElementById('setting-blackoutDates').value.split(',').map(s => s.trim()).filter(Boolean)
      };

      try {
        const res = await fetch('/api/admin/settings', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        if (res.ok) {
          showToast('Booking settings saved successfully', 'info');
        } else {
          showToast('Failed to save settings', 'error');
        }
      } catch (err) {
        showToast('Error saving settings', 'error');
      }
    }

    async function loadVerification() {
      try {
        const res = await fetch('/api/admin/verification');
        if (!res.ok) return;
        const list = await res.json();
        const tbody = document.getElementById('verification-table');
        if (!list || list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No pending verification items.</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(item => \`
          <tr>
            <td><strong>\${escapeHtml(item.key)}</strong></td>
            <td>\${escapeHtml(item.description)}</td>
            <td><span class="badge \${item.verified ? 'badge-completed' : 'badge-pending'}">\${item.verified ? 'Verified & Approved' : 'Pending Client Approval'}</span></td>
            <td><small style="color:var(--text-muted)">\${escapeHtml(item.notes || 'Awaiting confirmation')}</small></td>
            <td>
              <button class="btn btn-outline" style="padding:0.25rem 0.5rem; font-size:0.75rem;" onclick="toggleVerification('\${item._id}', \${!item.verified})">
                \${item.verified ? 'Revoke Approval' : 'Approve Fact'}
              </button>
            </td>
          </tr>
        \`).join('');
      } catch (err) {
        console.error(err);
      }
    }

    async function toggleVerification(id, verified) {
      try {
        const res = await fetch('/api/admin/verification/' + id, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verified })
        });
        if (res.ok) {
          showToast('Verification state updated', 'info');
          loadVerification();
        }
      } catch (err) {
        showToast('Error updating verification state', 'error');
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function escapeJs(str) {
      if (!str) return '';
      return String(str).replace(/'/g, "\\'").replace(/"/g, '\\"');
    }

    // Initialize default tab
    if (${isAuthenticated}) {
      loadOverview();
    }
  </script>
</body>
</html>`;

    res.type('html').send(html);
  });

  // REST API: Admin Auth
  router.post('/login', async (req, res, next) => { try {
    const { username, password } = req.body || {};
    const adminUser = process.env.ADMIN_USERNAME;
    const adminPass = process.env.ADMIN_PASSWORD;

    if (!adminUser || !adminPass) {
      return res.status(503).json({ error: 'Admin login is not configured on the server (set ADMIN_USERNAME and ADMIN_PASSWORD).' });
    }

    if (username === adminUser && password === adminPass) {
      // Create session in db and set cookie
      const sessionToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

      const db = getDb();
      if (!db) return res.status(503).json({ error: 'Database unavailable. Check MONGODB_URI and Atlas network access.' });
      await db.collection('sessions').insertOne({
        tokenHash,
        isAdmin: true,
        username: adminUser,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
      });

      res.cookie('admin_session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
      });

      req.session = { isAdmin: true, username: adminUser };
      await logAudit(db, req, 'LOGIN', 'ADMIN', adminUser, 'Admin login successful');

      return res.json({ success: true, message: 'Authenticated successfully' });
    } else {
      return res.status(401).json({ error: 'Invalid admin credentials.' });
    }
  } catch (err) { next(err); } });

  router.post('/logout', async (req, res) => {
    const token = req.cookies.admin_session;
    if (token) {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const db = getDb();
      if (db) await db.collection('sessions').deleteOne({ tokenHash });
    }
    res.clearCookie('admin_session');
    res.json({ success: true, message: 'Logged out' });
  });

  // Require admin auth middleware for remaining API endpoints
  router.use(requireAdminAuth);
  router.use((req, res, next) => {
    if (!getDb()) return res.status(503).json({ error: 'Database temporarily unavailable.' });
    next();
  });

  // REST API: Admin Overview
  router.get('/overview', async (req, res) => {
    try {
      const db = getDb();
      const now = new Date();
      const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

      const totalBookings = await db.collection('bookings').countDocuments();
      const bookingsThisWeek = await db.collection('bookings').countDocuments({ createdAt: { $gte: weekAgo } });
      const upcomingAppointments = await db.collection('bookings').countDocuments({ status: { $in: ['pending', 'confirmed'] } });
      const pendingRequests = await db.collection('bookings').countDocuments({ status: 'pending' });
      const activeProjects = await db.collection('projects').countDocuments({ currentStage: { $ne: 'Complete' } });
      const completedProjects = await db.collection('projects').countDocuments({ currentStage: 'Complete' });

      const conversionRate = totalBookings > 0 ? Math.round((activeProjects + completedProjects) / totalBookings * 100) : 0;

      const recentBookings = await db.collection('bookings')
        .find({})
        .sort({ createdAt: -1 })
        .limit(5)
        .toArray();

      res.json({
        kpis: {
          bookingsThisWeek,
          upcomingAppointments,
          pendingRequests,
          activeProjects,
          completedProjects,
          conversionRate
        },
        recentBookings
      });
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch overview data' });
    }
  });

  // REST API: Admin Bookings
  router.get('/bookings', async (req, res) => {
    try {
      const db = getDb();
      const bookings = await db.collection('bookings').find({}).sort({ createdAt: -1 }).toArray();
      res.json(bookings);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch bookings' });
    }
  });

  router.patch('/bookings/:id', async (req, res) => {
    try {
      const db = getDb();
      const { status, adminNotes } = req.body;
      const updateDoc = {};
      if (status) updateDoc.status = status;
      if (adminNotes !== undefined) updateDoc.adminNotes = adminNotes;
      updateDoc.updatedAt = new Date();

      await db.collection('bookings').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: updateDoc }
      );

      await logAudit(db, req, 'UPDATE_BOOKING', 'BOOKING', req.params.id, updateDoc);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update booking' });
    }
  });

  // REST API: Admin Projects
  router.get('/projects', async (req, res) => {
    try {
      const db = getDb();
      const projects = await db.collection('projects').find({}).sort({ updatedAt: -1 }).toArray();
      res.json(projects);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch projects' });
    }
  });

  router.post('/projects', async (req, res) => {
    try {
      const db = getDb();
      const { bookingId } = req.body;
      let booking = null;

      if (bookingId) {
        booking = await db.collection('bookings').findOne({ _id: new ObjectId(bookingId) });
      }

      const projectDoc = {
        bookingId: booking ? booking._id : null,
        bookingRef: booking ? booking.bookingRef : null,
        customerName: booking ? booking.fullName : (req.body.customerName || 'Direct Project'),
        customerEmail: booking ? booking.email : (req.body.customerEmail || ''),
        customerPhone: booking ? booking.phone : (req.body.customerPhone || ''),
        propertyAddress: booking ? `${booking.streetAddress}, ${booking.city || 'Houston'}` : (req.body.address || ''),
        serviceType: booking ? booking.serviceType : (req.body.serviceType || 'Roof Replacement'),
        assignedManager: 'Operations Team',
        currentStage: 'Request Received',
        stageHistory: [{
          stage: 'Request Received',
          updatedAt: new Date(),
          note: 'Project initialized'
        }],
        updates: [],
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const result = await db.collection('projects').insertOne(projectDoc);

      if (booking) {
        await db.collection('bookings').updateOne(
          { _id: booking._id },
          { $set: { status: 'confirmed', hasProject: true, projectId: result.insertedId } }
        );
      }

      await logAudit(db, req, 'CREATE_PROJECT', 'PROJECT', result.insertedId, { bookingId });
      res.json({ success: true, projectId: result.insertedId });
    } catch (err) {
      res.status(500).json({ error: 'Failed to create project' });
    }
  });

  router.patch('/projects/:id', async (req, res) => {
    try {
      const db = getDb();
      const { assignedManager, currentStage, updateNote, photoUrl } = req.body;
      const project = await db.collection('projects').findOne({ _id: new ObjectId(req.params.id) });

      if (!project) return res.status(404).json({ error: 'Project not found' });

      const setDoc = { updatedAt: new Date() };
      if (assignedManager) setDoc.assignedManager = assignedManager;

      const pushOps = {};

      if (currentStage && currentStage !== project.currentStage) {
        setDoc.currentStage = currentStage;
        pushOps.stageHistory = {
          stage: currentStage,
          updatedAt: new Date(),
          note: updateNote || `Advanced to ${currentStage}`
        };
      }

      if (updateNote || photoUrl) {
        pushOps.updates = {
          note: updateNote || '',
          photoUrl: photoUrl || null,
          createdAt: new Date(),
          author: req.session.username
        };
      }

      const updateQuery = { $set: setDoc };
      if (Object.keys(pushOps).length > 0) {
        updateQuery.$push = pushOps;
      }

      await db.collection('projects').updateOne({ _id: new ObjectId(req.params.id) }, updateQuery);
      await logAudit(db, req, 'UPDATE_PROJECT', 'PROJECT', req.params.id, { currentStage, assignedManager });

      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update project' });
    }
  });

  // REST API: Admin Settings
  router.get('/settings', async (req, res) => {
    try {
      const db = getDb();
      const settings = await db.collection('settings').findOne({ type: 'global' });
      res.json(settings || {});
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  router.patch('/settings', async (req, res) => {
    try {
      const db = getDb();
      const payload = req.body;
      payload.updatedAt = new Date();

      await db.collection('settings').updateOne(
        { type: 'global' },
        { $set: payload },
        { upsert: true }
      );

      await logAudit(db, req, 'UPDATE_SETTINGS', 'SETTINGS', 'global', payload);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to save settings' });
    }
  });

  // REST API: Admin Announcements
  router.get('/announcements', async (req, res) => {
    try {
      const db = getDb();
      const announcements = await db.collection('announcements').find({}).sort({ createdAt: -1 }).toArray();
      res.json(announcements);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch announcements' });
    }
  });

  router.post('/announcements', async (req, res) => {
    try {
      const db = getDb();
      const { title, category, message, startDate, endDate, active } = req.body;
      const doc = {
        title,
        category: category || 'General',
        message,
        startDate: startDate || null,
        endDate: endDate || null,
        active: active !== undefined ? active : true,
        createdAt: new Date()
      };
      const result = await db.collection('announcements').insertOne(doc);
      await logAudit(db, req, 'CREATE_ANNOUNCEMENT', 'ANNOUNCEMENT', result.insertedId, doc);
      res.json({ success: true, id: result.insertedId });
    } catch (err) {
      res.status(500).json({ error: 'Failed to create announcement' });
    }
  });

  router.patch('/announcements/:id', async (req, res) => {
    try {
      const db = getDb();
      const { active, title, message } = req.body;
      const setDoc = { updatedAt: new Date() };
      if (active !== undefined) setDoc.active = active;
      if (title) setDoc.title = title;
      if (message) setDoc.message = message;

      await db.collection('announcements').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: setDoc }
      );

      await logAudit(db, req, 'UPDATE_ANNOUNCEMENT', 'ANNOUNCEMENT', req.params.id, setDoc);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update announcement' });
    }
  });

  // REST API: Verification Items
  router.get('/verification', async (req, res) => {
    try {
      const db = getDb();
      const items = await db.collection('siteContent').find({ type: 'fact_verification' }).toArray();
      res.json(items);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch verification list' });
    }
  });

  router.patch('/verification/:id', async (req, res) => {
    try {
      const db = getDb();
      const { verified, notes } = req.body;
      const setDoc = { updatedAt: new Date() };
      if (verified !== undefined) setDoc.verified = verified;
      if (notes) setDoc.notes = notes;

      await db.collection('siteContent').updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: setDoc }
      );

      await logAudit(db, req, 'UPDATE_VERIFICATION', 'SITE_CONTENT', req.params.id, setDoc);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update verification item' });
    }
  });

  return router;
}

module.exports = { createAdminRouter };
