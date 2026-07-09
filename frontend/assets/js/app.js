// frontend/assets/js/app.js

const API = '';

const Auth = {
  getToken:   ()     => localStorage.getItem('gpms_token'),
  getUser:    ()     => JSON.parse(localStorage.getItem('gpms_user') || 'null'),
  save:       (t, u) => { localStorage.setItem('gpms_token', t); localStorage.setItem('gpms_user', JSON.stringify(u)); },
  clear:      ()     => { localStorage.removeItem('gpms_token'); localStorage.removeItem('gpms_user'); },
  isLoggedIn: ()     => !!localStorage.getItem('gpms_token'),
};

async function api(method, path, body = null) {
  const headers = { 'Content-Type': 'application/json' };
  const token   = Auth.getToken();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API + path, {
    method, headers,
    body: body ? JSON.stringify(body) : null,
  });
  if (res.status === 401) { Auth.clear(); window.location = '../pages/login.html'; return; }
  return res.json();
}

let _toastTimer;
function toast(msg, type = 'default') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.className   = `show ${type}`;
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.className = ''; }, 3500);
}

function guardPage(allowedRoles) {
  if (!Auth.isLoggedIn()) { window.location = '../pages/login.html'; return null; }
  const user = Auth.getUser();
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    window.location = '../pages/login.html'; return null;
  }
  return user;
}

function hydrateSidebar(activeItem) {
  const user = Auth.getUser();
  if (!user) return;
  const nameEl = document.getElementById('sidebar-name');
  const roleEl = document.getElementById('sidebar-role');
  if (nameEl) nameEl.textContent = user.name;
  if (roleEl) roleEl.textContent = user.role.charAt(0).toUpperCase() + user.role.slice(1);
  document.querySelectorAll('.nav-item').forEach(el => {
    if (el.dataset.nav === activeItem) el.classList.add('active');
  });
}

function logout() { Auth.clear(); window.location = '../pages/login.html'; }

function timeAgo(dateStr) {
  const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000);
  if (diff < 60)    return 'Just now';
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

async function loadNotifications() {
  const data = await api('GET', '/api/notifications');
  if (!data?.success) return;
  const badge = document.getElementById('notif-badge');
  const list  = document.getElementById('notif-list');
  if (badge) {
    badge.textContent    = data.data.unread_count;
    badge.style.display  = data.data.unread_count > 0 ? 'flex' : 'none';
  }
  if (list) {
    list.innerHTML = data.data.notifications.length === 0
      ? `<div class="empty-state" style="padding:24px"><p>No notifications yet.</p></div>`
      : data.data.notifications.map(n => `
          <div class="notif-row ${n.is_read ? '' : 'unread'}" onclick="markRead(${n.id}, this)">
            <div class="notif-row-title">${n.title}</div>
            <div class="notif-row-msg">${n.message}</div>
            <div class="notif-row-time">${timeAgo(n.created_at)}</div>
          </div>`).join('');
  }
}

async function markRead(id, el) {
  await api('PUT', `/api/notifications/${id}/read`);
  el.classList.remove('unread');
  loadNotifications();
}

async function markAllRead() {
  await api('PUT', '/api/notifications/read-all');
  loadNotifications();
  toast('All notifications marked as read');
}

function toggleNotifPanel() {
  document.getElementById('notif-panel')?.classList.toggle('open');
}

document.addEventListener('click', e => {
  const panel = document.getElementById('notif-panel');
  if (panel?.classList.contains('open') && !e.target.closest('#notif-area')) {
    panel.classList.remove('open');
  }
});
