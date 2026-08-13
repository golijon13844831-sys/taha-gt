const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const app = express();
const server = http.createServer(app);
const clients = new Map();

// ─── WebSocket ───
server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://localhost');
  const token = url.searchParams.get('token');
  const user = verifyToken(token);
  if (!user) { socket.destroy(); return; }

  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );

  socket.user = user;
  clients.set(user.id, socket);

  let buf = Buffer.alloc(0);
  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let offset = 2;
      if (len === 126) {
        if (buf.length < 4) break;
        len = buf.readUInt16BE(2); offset = 4;
      } else if (len === 127) {
        if (buf.length < 10) break;
        len = Number(buf.readBigUInt64BE(2)); offset = 10;
      }
      const total = offset + (masked ? 4 : 0) + len;
      if (buf.length < total) break;
      const mask = masked ? buf.slice(offset, offset + 4) : null;
      if (masked) offset += 4;
      const payload = buf.slice(offset, offset + len);
      if (masked) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
      buf = buf.slice(total);
      try {
        const data = JSON.parse(payload.toString('utf8'));
        handleWsMessage(socket, data);
      } catch {}
    }
  });

  socket.on('close', () => {
    clients.delete(user.id);
    notifyLeave(socket);
    updateLastSeen(user.id);
  });
  socket.on('error', () => {
    clients.delete(user.id);
    notifyLeave(socket);
    updateLastSeen(user.id);
  });
});

function updateLastSeen(userId) {
  const db = loadDB();
  if (!db.userPresence) db.userPresence = [];
  let rec = db.userPresence.find(p => p.userId === userId);
  if (!rec) { rec = { userId, lastSeen: null }; db.userPresence.push(rec); }
  rec.lastSeen = new Date().toISOString();
  saveDB(db);
}

function notifyLeave(socket) {
  if (!socket.currentClassId) return;
  const db = loadDB();
  const session = (db.classSessions || []).find(s => s.id === socket.currentClassId);
  if (!session) return;
  const members = new Set([session.teacherId, ...session.students]);
  broadcast({ type: 'presence_leave', userId: socket.user.id, userName: socket.user.name, classId: socket.currentClassId }, id => members.has(id));
}

function encodeWsFrame(msg) {
  const payload = Buffer.from(msg, 'utf8');
  const len = payload.length;
  let frame;
  if (len < 126) {
    frame = Buffer.alloc(2 + len);
    frame[0] = 0x81; frame[1] = len;
    payload.copy(frame, 2);
  } else if (len < 65536) {
    frame = Buffer.alloc(4 + len);
    frame[0] = 0x81; frame[1] = 126;
    frame.writeUInt16BE(len, 2);
    payload.copy(frame, 4);
  } else {
    frame = Buffer.alloc(10 + len);
    frame[0] = 0x81; frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
    payload.copy(frame, 10);
  }
  return frame;
}

function wsSend(socket, data) {
  try { if (socket && !socket.destroyed) socket.write(encodeWsFrame(JSON.stringify(data))); } catch {}
}

function broadcast(data, filter) {
  clients.forEach((sock, uid) => {
    if (!filter || filter(uid)) wsSend(sock, data);
  });
}

function handleWsMessage(socket, data) {
  const { type } = data;

  // چت: فقط broadcast کن، ذخیره از طریق API انجام میشه
  if (type === 'chat_message') {
    const db = loadDB();
    const room = (db.chatRooms || []).find(r => r.id === data.roomId);
    if (!room) return;
    const members = new Set(room.members);
    if (!members.has(socket.user.id)) return; // فقط اعضای واقعی اتاق
    // فقط به بقیه اعضا بفرست (نه فرستنده)
    clients.forEach((sock, uid) => {
      if (members.has(uid) && uid !== socket.user.id) wsSend(sock, data);
    });
  }

  // ─── نشانگر «در حال تایپ» (ارتقا ۱) ───
  if (type === 'typing') {
    const db = loadDB();
    const room = (db.chatRooms || []).find(r => r.id === data.roomId);
    if (!room) return;
    const members = new Set(room.members);
    if (!members.has(socket.user.id)) return;
    clients.forEach((sock, uid2) => {
      if (members.has(uid2) && uid2 !== socket.user.id) {
        wsSend(sock, { type: 'typing', roomId: data.roomId, userId: socket.user.id, userName: socket.user.name, isTyping: !!data.isTyping });
      }
    });
  }

  if (type === 'class_message') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return; // فقط اعضای واقعی کلاس اجازه ارسال دارند
    const msg = {
      id: uid(), senderId: socket.user.id, senderName: socket.user.name,
      senderRole: socket.user.role, classId: data.classId,
      text: data.text, createdAt: new Date().toISOString()
    };
    if (!db.classMessages) db.classMessages = [];
    db.classMessages.push(msg);
    saveDB(db);
    // به بقیه اعضا بفرست، نه به خود فرستنده (کلاینت echo لوکال نشون میده)
    clients.forEach((sock, uid2) => {
      if (members.has(uid2) && uid2 !== socket.user.id) wsSend(sock, { type: 'class_message', message: msg });
    });
  }

  if (type === 'class_raise_hand') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return;
    broadcast({ type: 'class_raise_hand', userId: socket.user.id, userName: socket.user.name, classId: data.classId, action: data.action || 'up' }, id => members.has(id));
  }

  if (type === 'whiteboard') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return;
    broadcast({ ...data }, id => members.has(id) && id !== socket.user.id);
  }

  // ─── WebRTC Signaling (peer-to-peer، سرور فقط پیام رد و بدل می‌کند) ───
  if (type === 'webrtc_signal') {
    // data: { classId, targetId, signal: {sdp|candidate...} }
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id) || !members.has(data.targetId)) return;
    const targetSock = clients.get(data.targetId);
    if (targetSock) wsSend(targetSock, { type: 'webrtc_signal', fromId: socket.user.id, fromName: socket.user.name, signal: data.signal, classId: data.classId });
  }

  // اعلام حضور/عدم حضور رسانه (میکروفون/دوربین/اشتراک صفحه روشن یا خاموش شد)
  if (type === 'media_state') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return;
    broadcast({ type: 'media_state', userId: socket.user.id, userName: socket.user.name, classId: data.classId, mic: data.mic, cam: data.cam, screen: data.screen }, id => members.has(id) && id !== socket.user.id);
  }

  // معلم کاربری را mute می‌کند
  if (type === 'force_mute') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || session.teacherId !== socket.user.id) return; // فقط معلم اجازه دارد
    const targetSock = clients.get(data.targetId);
    if (targetSock) wsSend(targetSock, { type: 'force_mute', classId: data.classId, kind: data.kind || 'mic' });
  }

  // ─── Breakout Rooms ───
  if (type === 'breakout_assign') {
    // فقط معلم: data:{classId, groups:[{name, studentIds:[]}]}
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || session.teacherId !== socket.user.id) return;
    session.breakoutGroups = data.groups || [];
    session.breakoutActive = true;
    saveDB(db);
    const members = new Set([session.teacherId, ...session.students]);
    broadcast({ type: 'breakout_started', classId: data.classId, groups: session.breakoutGroups }, id => members.has(id));
  }
  if (type === 'breakout_end') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || session.teacherId !== socket.user.id) return;
    session.breakoutActive = false;
    saveDB(db);
    const members = new Set([session.teacherId, ...session.students]);
    broadcast({ type: 'breakout_ended', classId: data.classId }, id => members.has(id));
  }

  // ─── Live Poll در حین کلاس ───
  if (type === 'live_poll_start') {
    // فقط معلم: data:{classId, question, options:[]}
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || session.teacherId !== socket.user.id) return;
    session.livePoll = { id: uid(), question: data.question, options: data.options, votes: {}, active: true };
    saveDB(db);
    const members = new Set([session.teacherId, ...session.students]);
    broadcast({ type: 'live_poll_start', classId: data.classId, poll: session.livePoll }, id => members.has(id));
  }
  if (type === 'live_poll_vote') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || !session.livePoll || !session.livePoll.active) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return;
    session.livePoll.votes[socket.user.id] = data.option;
    saveDB(db);
    const counts = session.livePoll.options.map((_, i) => Object.values(session.livePoll.votes).filter(v => v === i).length);
    broadcast({ type: 'live_poll_update', classId: data.classId, counts }, id => members.has(id));
  }
  if (type === 'live_poll_end') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session || session.teacherId !== socket.user.id || !session.livePoll) return;
    session.livePoll.active = false;
    saveDB(db);
    const members = new Set([session.teacherId, ...session.students]);
    broadcast({ type: 'live_poll_end', classId: data.classId }, id => members.has(id));
  }

  // ─── Presence: کاربر وارد/خارج جلسه شد ───
  if (type === 'join_session') {
    const db = loadDB();
    const session = (db.classSessions || []).find(s => s.id === data.classId);
    if (!session) return;
    const members = new Set([session.teacherId, ...session.students]);
    if (!members.has(socket.user.id)) return;
    socket.currentClassId = data.classId;
    broadcast({ type: 'presence_join', userId: socket.user.id, userName: socket.user.name, userRole: socket.user.role, classId: data.classId }, id => members.has(id) && id !== socket.user.id);
    // به تازه‌وارد لیست افرادی که الان آنلاین‌اند رو بفرست
    const online = [...members].filter(id => clients.has(id) && id !== socket.user.id).map(id => {
      const c = clients.get(id);
      return { userId: id, userName: c.user.name, userRole: c.user.role };
    });
    wsSend(socket, { type: 'presence_list', classId: data.classId, online });
  }

  if (type === 'ping') wsSend(socket, { type: 'pong' });
}

// ─── DB ───
app.use(express.json({ limit: '25mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const DB_FILE = path.join(__dirname, 'data.json');
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = {
      users: [], classes: [], lessons: [], assignments: [],
      submissions: [], quizzes: [], quizSubmissions: [],
      attendance: [], polls: [], pollVotes: [],
      chatRooms: [], messages: [], notifications: [],
      classSessions: [], classMessages: [], uploads: [],
      questionBank: [], studentNotes: [], badges: [], studentBadges: [],
      assignmentTemplates: [], quizTemplates: [],
      studentXP: [], studentStreaks: [], flashcardReviews: [],
      messageReactions: [], pinnedMessages: [], userPresence: [], roomUserPrefs: [],
      announcements: [], faqs: [], contactMessages: [], activityLog: [], settings: {}
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  try { return JSON.parse(fs.readFileSync(DB_FILE)); }
  catch { return {}; }
}
function saveDB(db) { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }

const SECRET = 'edu_secret_2024_change_me';
function signToken(p) {
  const h = Buffer.from('{}').toString('base64');
  const b = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + 86400000 * 7 })).toString('base64');
  const s = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64');
  return `${h}.${b}.${s}`;
}
function verifyToken(token) {
  if (!token) return null;
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;
    const exp = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64');
    if (s !== exp) return null;
    const p = JSON.parse(Buffer.from(b, 'base64').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
function hashPw(pw) { return crypto.createHash('sha256').update(pw + SECRET).digest('hex'); }

function auth(req, res, next) {
  const t = (req.headers.authorization || '').replace('Bearer ', '').trim();
  const u = verifyToken(t);
  if (!u) return res.status(401).json({ error: 'لطفاً وارد شوید' });
  req.user = u; next();
}
function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'دسترسی ندارید' });
    next();
  };
}

function addNotif(db, userId, text, type = 'info') {
  if (!db.notifications) db.notifications = [];
  db.notifications.push({ id: uid(), userId, text, type, read: false, createdAt: new Date().toISOString() });
  const sock = clients.get(userId);
  if (sock) wsSend(sock, { type: 'notification', text, notifType: type });
}

// چک می‌کند که معلم واقعاً صاحب این کلاس است (ادمین همیشه مجاز است)
function ownsClass(req, db, classId) {
  if (req.user.role === 'admin') return true;
  const cls = (db.classes || []).find(c => c.id === classId);
  return cls && cls.teacherId === req.user.id;
}

// ثبت رویداد در لاگ فعالیت سیستم (ارتقا ۳ ادمین)
function logActivity(db, userId, userName, userRole, action, details) {
  if (!db.activityLog) db.activityLog = [];
  db.activityLog.push({
    id: uid(), userId, userName, userRole, action, details: details || '',
    createdAt: new Date().toISOString()
  });
  // فقط ۱۰۰۰ رکورد آخر نگه‌داشته می‌شود تا فایل دیتابیس بی‌نهایت بزرگ نشود
  if (db.activityLog.length > 1000) db.activityLog = db.activityLog.slice(-1000);
}

// ══════════════════════════
//  AUTH
// ══════════════════════════
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'ایمیل و رمز عبور الزامی است' });
  const db = loadDB();
  const u = db.users.find(u => u.email === email && u.password === hashPw(password) && u.active !== false);
  if (!u) return res.status(401).json({ error: 'ایمیل یا رمز عبور اشتباه است' });
  const token = signToken({ id: u.id, name: u.name, email: u.email, role: u.role });
  logActivity(db, u.id, u.name, u.role, 'login', 'ورود به سامانه');
  saveDB(db);
  res.json({ token, user: { id: u.id, name: u.name, email: u.email, role: u.role } });
});

app.get('/api/me', auth, (req, res) => {
  const db = loadDB();
  const u = db.users.find(u => u.id === req.user.id);
  if (!u) return res.status(404).json({ error: 'یافت نشد' });
  const { password, ...safe } = u;
  res.json(safe);
});

// ══════════════════════════
//  ADMIN
// ══════════════════════════
app.get('/api/admin/users', auth, role('admin'), (req, res) => {
  const db = loadDB();
  res.json(db.users.map(u => { const { password, ...s } = u; return s; }));
});

app.post('/api/admin/users', auth, role('admin'), (req, res) => {
  const { name, email, password, role: r, classIds } = req.body;
  if (!name || !email || !password || !r) return res.status(400).json({ error: 'همه فیلدها الزامی است' });
  const db = loadDB();
  if (db.users.find(u => u.email === email)) return res.status(400).json({ error: 'ایمیل تکراری است' });
  const u = { id: uid(), name, email, password: hashPw(password), role: r, classIds: classIds || [], active: true, createdAt: new Date().toISOString() };
  db.users.push(u);
  logActivity(db, req.user.id, req.user.name, req.user.role, 'create_user', `کاربر جدید: ${name} (${r})`);
  saveDB(db);
  const { password: _, ...safe } = u;
  res.json(safe);
});

app.patch('/api/admin/users/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const u = db.users.find(u => u.id === req.params.id);
  if (!u) return res.status(404).json({ error: 'یافت نشد' });
  const { name, email, password, active, classIds } = req.body;
  if (name) u.name = name;
  if (email) u.email = email;
  if (password) u.password = hashPw(password);
  if (active !== undefined) u.active = active;

  // اگر کاربر دانش‌آموز است و classIds تغییر کرده، عضویت او در کلاس‌ها را sync کن
  if (classIds && u.role === 'student') {
    const oldIds = u.classIds || [];
    u.classIds = classIds;
    (db.classes || []).forEach(cls => {
      const wasIn = oldIds.includes(cls.id);
      const nowIn = classIds.includes(cls.id);
      if (nowIn && !cls.studentIds.includes(u.id)) cls.studentIds.push(u.id);
      if (!nowIn && cls.studentIds.includes(u.id)) cls.studentIds = cls.studentIds.filter(id => id !== u.id);
      // sync اتاق چت گروهی
      const room = (db.chatRooms || []).find(r => r.classId === cls.id);
      if (room) room.members = [cls.teacherId, ...(cls.studentIds || [])];
    });
  } else if (classIds) {
    u.classIds = classIds;
  }

  saveDB(db);
  const { password: _, ...safe } = u;
  res.json(safe);
});

app.delete('/api/admin/users/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const idx = db.users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  const u = db.users[idx];
  if (u.role === 'admin') return res.status(400).json({ error: 'نمیتوان ادمین را حذف کرد' });
  // جلوگیری از حذف معلمی که کلاس فعال دارد
  if (u.role === 'teacher') {
    const hasClasses = (db.classes || []).some(c => c.teacherId === u.id);
    if (hasClasses) return res.status(400).json({ error: 'ابتدا کلاس‌های این معلم را به معلم دیگری منتقل یا حذف کنید' });
  }
  // حذف دانش‌آموز از تمام کلاس‌ها و اتاق‌های چت
  if (u.role === 'student') {
    (db.classes || []).forEach(cls => {
      cls.studentIds = (cls.studentIds || []).filter(id => id !== u.id);
    });
    (db.chatRooms || []).forEach(room => {
      room.members = (room.members || []).filter(id => id !== u.id);
    });
  }
  db.users.splice(idx, 1);
  logActivity(db, req.user.id, req.user.name, req.user.role, 'delete_user', `کاربر حذف شد: ${u.name} (${u.role})`);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/admin/stats', auth, role('admin'), (req, res) => {
  const db = loadDB();
  res.json({
    users: db.users.length,
    teachers: db.users.filter(u => u.role === 'teacher').length,
    students: db.users.filter(u => u.role === 'student').length,
    classes: (db.classes || []).length,
    lessons: (db.lessons || []).length,
    quizzes: (db.quizzes || []).length
  });
});

// ══════════════════════════
//  ADMIN UPGRADE 6: آمار کلی پیشرفته‌تر (روند ثبت‌نام، فعالیت هفتگی)
// ══════════════════════════
app.get('/api/admin/advanced-stats', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const now = new Date();
  const last7Days = [...Array(7)].map((_, i) => {
    const d = new Date(now); d.setDate(d.getDate() - (6 - i));
    return d.toISOString().slice(0, 10);
  });
  const signupsByDay = last7Days.map(date => ({
    date, count: db.users.filter(u => u.createdAt && u.createdAt.slice(0, 10) === date).length
  }));
  const loginsByDay = last7Days.map(date => ({
    date, count: (db.activityLog || []).filter(a => a.action === 'login' && a.createdAt.slice(0, 10) === date).length
  }));
  const submissionsByDay = last7Days.map(date => ({
    date, count: (db.quizSubmissions || []).filter(s => s.submittedAt && s.submittedAt.slice(0, 10) === date).length
  }));
  res.json({
    signupsByDay, loginsByDay, submissionsByDay,
    totalMessages: (db.messages || []).length + (db.classMessages || []).length,
    totalSubmissions: (db.quizSubmissions || []).length + (db.submissions || []).length,
    activeUsersToday: new Set((db.activityLog || []).filter(a => a.createdAt.slice(0, 10) === now.toISOString().slice(0, 10)).map(a => a.userId)).size
  });
});

// ══════════════════════════
//  ADMIN UPGRADE 1: مدیریت اطلاعیه‌ها (برای صفحه Home)
// ══════════════════════════
app.get('/api/announcements', (req, res) => {
  const db = loadDB();
  const active = (db.announcements || []).filter(a => a.active !== false).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(active);
});
app.get('/api/admin/announcements', auth, role('admin'), (req, res) => {
  const db = loadDB();
  res.json((db.announcements || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});
app.post('/api/admin/announcements', auth, role('admin'), (req, res) => {
  const { title, body } = req.body;
  if (!title) return res.status(400).json({ error: 'عنوان الزامی است' });
  const db = loadDB();
  const a = { id: uid(), title, body: body || '', active: true, createdAt: new Date().toISOString() };
  if (!db.announcements) db.announcements = [];
  db.announcements.push(a);
  logActivity(db, req.user.id, req.user.name, req.user.role, 'create_announcement', title);
  saveDB(db);
  res.json(a);
});
app.patch('/api/admin/announcements/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const a = (db.announcements || []).find(x => x.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'یافت نشد' });
  Object.assign(a, req.body);
  saveDB(db);
  res.json(a);
});
app.delete('/api/admin/announcements/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.announcements || []).findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.announcements.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  ADMIN UPGRADE 2: مدیریت FAQ صفحه Home
// ══════════════════════════
app.get('/api/faqs', (req, res) => {
  const db = loadDB();
  res.json((db.faqs || []).filter(f => f.active !== false));
});
app.get('/api/admin/faqs', auth, role('admin'), (req, res) => {
  const db = loadDB();
  res.json(db.faqs || []);
});
app.post('/api/admin/faqs', auth, role('admin'), (req, res) => {
  const { question, answer } = req.body;
  if (!question || !answer) return res.status(400).json({ error: 'سوال و پاسخ الزامی است' });
  const db = loadDB();
  const f = { id: uid(), question, answer, active: true, order: (db.faqs || []).length, createdAt: new Date().toISOString() };
  if (!db.faqs) db.faqs = [];
  db.faqs.push(f);
  saveDB(db);
  res.json(f);
});
app.patch('/api/admin/faqs/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const f = (db.faqs || []).find(x => x.id === req.params.id);
  if (!f) return res.status(404).json({ error: 'یافت نشد' });
  Object.assign(f, req.body);
  saveDB(db);
  res.json(f);
});
app.delete('/api/admin/faqs/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.faqs || []).findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.faqs.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  ADMIN UPGRADE 3: لاگ فعالیت سیستم
// ══════════════════════════
app.get('/api/admin/activity-log', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const { action, limit } = req.query;
  let log = (db.activityLog || []).slice().reverse();
  if (action) log = log.filter(l => l.action === action);
  res.json(log.slice(0, parseInt(limit) || 100));
});

// ══════════════════════════
//  ADMIN UPGRADE 4: پشتیبان‌گیری / Export دیتابیس
// ══════════════════════════
app.get('/api/admin/backup', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const { password, ...safeDb } = db; // احتیاط: رمزها اصلاً نباید خارج شوند حتی داخل users
  safeDb.users = db.users.map(u => { const { password, ...s } = u; return s; });
  logActivity(db, req.user.id, req.user.name, req.user.role, 'backup_export', 'دانلود پشتیبان دیتابیس');
  saveDB(db);
  res.setHeader('Content-Disposition', `attachment; filename="backup-${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(safeDb);
});

// ══════════════════════════
//  ADMIN UPGRADE 5: مدیریت پیام‌های تماس (از فرم Home)
// ══════════════════════════
app.post('/api/contact', (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'همه فیلدها الزامی است' });
  const db = loadDB();
  const m = { id: uid(), name, email, message, read: false, createdAt: new Date().toISOString() };
  if (!db.contactMessages) db.contactMessages = [];
  db.contactMessages.push(m);
  saveDB(db);
  res.json({ ok: true });
});
app.get('/api/admin/contact-messages', auth, role('admin'), (req, res) => {
  const db = loadDB();
  res.json((db.contactMessages || []).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});
app.patch('/api/admin/contact-messages/:id/read', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const m = (db.contactMessages || []).find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: 'یافت نشد' });
  m.read = true;
  saveDB(db);
  res.json(m);
});
app.delete('/api/admin/contact-messages/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.contactMessages || []).findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.contactMessages.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  ADMIN UPGRADE 7: مدیریت گروهی کاربران (bulk actions)
// ══════════════════════════
app.post('/api/admin/users/bulk', auth, role('admin'), (req, res) => {
  const { userIds, action } = req.body; // action: 'activate' | 'deactivate' | 'delete'
  if (!userIds?.length || !action) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  let affected = 0;
  userIds.forEach(id => {
    const u = db.users.find(x => x.id === id);
    if (!u || u.role === 'admin') return;
    if (action === 'activate') { u.active = true; affected++; }
    if (action === 'deactivate') { u.active = false; affected++; }
    if (action === 'delete') {
      const idx = db.users.findIndex(x => x.id === id);
      if (idx !== -1) {
        if (u.role === 'teacher' && (db.classes || []).some(c => c.teacherId === u.id)) return; // معلم دارای کلاس رد می‌شود
        if (u.role === 'student') {
          (db.classes || []).forEach(cls => { cls.studentIds = (cls.studentIds || []).filter(sid => sid !== u.id); });
          (db.chatRooms || []).forEach(room => { room.members = (room.members || []).filter(mid => mid !== u.id); });
        }
        db.users.splice(idx, 1);
        affected++;
      }
    }
  });
  logActivity(db, req.user.id, req.user.name, req.user.role, 'bulk_user_action', `${action} روی ${affected} کاربر`);
  saveDB(db);
  res.json({ ok: true, affected });
});

// ══════════════════════════
//  ADMIN UPGRADE 8: تنظیمات سراسری سامانه
// ══════════════════════════
app.get('/api/settings', (req, res) => {
  const db = loadDB();
  res.json(db.settings || {});
});
app.patch('/api/admin/settings', auth, role('admin'), (req, res) => {
  const db = loadDB();
  db.settings = { ...(db.settings || {}), ...req.body };
  logActivity(db, req.user.id, req.user.name, req.user.role, 'update_settings', 'تنظیمات سامانه ویرایش شد');
  saveDB(db);
  res.json(db.settings);
});

// ══════════════════════════
//  ADMIN UPGRADE 9: مانیتور فضای ذخیره‌سازی
// ══════════════════════════
app.get('/api/admin/storage', auth, role('admin'), (req, res) => {
  const uploadsDir = path.join(__dirname, 'public', 'uploads');
  let totalSize = 0, fileCount = 0;
  try {
    const files = fs.readdirSync(uploadsDir);
    files.forEach(f => {
      if (f === '.gitkeep') return;
      const stat = fs.statSync(path.join(uploadsDir, f));
      if (stat.isFile()) { totalSize += stat.size; fileCount++; }
    });
  } catch {}
  const dbSize = fs.existsSync(DB_FILE) ? fs.statSync(DB_FILE).size : 0;
  res.json({
    uploadsSizeBytes: totalSize, uploadsFileCount: fileCount,
    dbSizeBytes: dbSize,
    totalSizeBytes: totalSize + dbSize
  });
});

// بازیابی دیتابیس از فایل پشتیبان (احتیاط: عملیات خطرناک، همه‌چیز رو جایگزین می‌کند)
app.post('/api/admin/restore', auth, role('admin'), (req, res) => {
  const backup = req.body;
  if (!backup || typeof backup !== 'object' || !Array.isArray(backup.users)) {
    return res.status(400).json({ error: 'فایل پشتیبان نامعتبر است' });
  }
  const db = loadDB();
  // رمزهای عبور موجود را حفظ کن (فایل بک‌آپ رمزها را ندارد)، وگرنه هیچ‌کس نمی‌تواند وارد شود
  const restoredUsers = backup.users.map(bu => {
    const existing = db.users.find(u => u.id === bu.id);
    return { ...bu, password: existing ? existing.password : hashPw('changeme123') };
  });
  const merged = { ...db, ...backup, users: restoredUsers };
  saveDB(merged);
  logActivity(merged, req.user.id, req.user.name, req.user.role, 'backup_restore', 'دیتابیس از فایل پشتیبان بازیابی شد');
  saveDB(merged);
  res.json({ ok: true, usersRestored: restoredUsers.length });
});

// ══════════════════════════
//  ADMIN UPGRADE 10: مدیریت نقش‌ها و مجوزها (فعال/غیرفعال کردن قابلیت‌ها)
// ══════════════════════════
app.get('/api/feature-flags', (req, res) => {
  const db = loadDB();
  res.json(db.settings?.featureFlags || {
    chat: true, virtualClass: true, quizzes: true, polls: true, questionBank: true, leaderboard: true
  });
});
app.patch('/api/admin/feature-flags', auth, role('admin'), (req, res) => {
  const db = loadDB();
  if (!db.settings) db.settings = {};
  db.settings.featureFlags = { ...(db.settings.featureFlags || {}), ...req.body };
  logActivity(db, req.user.id, req.user.name, req.user.role, 'update_feature_flags', JSON.stringify(req.body));
  saveDB(db);
  res.json(db.settings.featureFlags);
});

// معلم فقط می‌تواند نام دانش‌آموزان کلاس‌های خودش را ببیند (نه لیست کامل کاربران)
app.get('/api/teacher/students', auth, role('teacher'), (req, res) => {
  const db = loadDB();
  const myClasses = (db.classes || []).filter(c => c.teacherId === req.user.id);
  const ids = new Set();
  myClasses.forEach(c => (c.studentIds || []).forEach(id => ids.add(id)));
  const students = db.users.filter(u => ids.has(u.id)).map(u => ({ id: u.id, name: u.name }));
  res.json(students);
});

// ══════════════════════════
//  CLASSES
// ══════════════════════════
app.get('/api/classes', auth, (req, res) => {
  const db = loadDB();
  let classes = db.classes || [];
  if (req.user.role === 'teacher') classes = classes.filter(c => c.teacherId === req.user.id);
  if (req.user.role === 'student') classes = classes.filter(c => (c.studentIds || []).includes(req.user.id));
  res.json(classes);
});

app.post('/api/classes', auth, role('admin'), (req, res) => {
  const { name, teacherId, studentIds, subject } = req.body;
  if (!name || !teacherId) return res.status(400).json({ error: 'نام و معلم الزامی است' });
  const db = loadDB();
  const teacher = db.users.find(u => u.id === teacherId && u.role === 'teacher');
  if (!teacher) return res.status(400).json({ error: 'معلم یافت نشد' });
  const cls = {
    id: uid(), name, subject: subject || '', teacherId,
    teacherName: teacher.name, studentIds: studentIds || [],
    createdAt: new Date().toISOString()
  };
  if (!db.classes) db.classes = [];
  db.classes.push(cls);
  // اتاق چت گروهی برای کلاس
  if (!db.chatRooms) db.chatRooms = [];
  db.chatRooms.push({
    id: 'room_' + cls.id, classId: cls.id,
    name: `گروه ${cls.name}`, type: 'class',
    members: [teacherId, ...(studentIds || [])],
    createdAt: new Date().toISOString()
  });
  logActivity(db, req.user.id, req.user.name, req.user.role, 'create_class', `کلاس جدید: ${name} (معلم: ${teacher.name})`);
  saveDB(db);
  res.json(cls);
});

app.patch('/api/classes/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'یافت نشد' });
  // اگر معلم تغییر کرده، معتبر بودنش رو چک کن و نام رو sync کن
  if (req.body.teacherId && req.body.teacherId !== cls.teacherId) {
    const newTeacher = db.users.find(u => u.id === req.body.teacherId && u.role === 'teacher');
    if (!newTeacher) return res.status(400).json({ error: 'معلم یافت نشد' });
    req.body.teacherName = newTeacher.name;
  }
  Object.assign(cls, req.body);
  // بروزرسانی اعضای اتاق چت
  const room = (db.chatRooms || []).find(r => r.classId === cls.id);
  if (room) room.members = [cls.teacherId, ...(cls.studentIds || [])];
  saveDB(db);
  res.json(cls);
});

app.delete('/api/classes/:id', auth, role('admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.classes || []).findIndex(c => c.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  const classId = req.params.id;
  db.classes.splice(idx, 1);
  // پاک‌سازی داده‌های وابسته به این کلاس
  db.lessons = (db.lessons || []).filter(l => l.classId !== classId);
  db.assignments = (db.assignments || []).filter(a => a.classId !== classId);
  db.quizzes = (db.quizzes || []).filter(q => q.classId !== classId);
  db.polls = (db.polls || []).filter(p => p.classId !== classId);
  db.attendance = (db.attendance || []).filter(a => a.classId !== classId);
  db.classSessions = (db.classSessions || []).filter(s => s.classId !== classId);
  db.chatRooms = (db.chatRooms || []).filter(r => r.classId !== classId);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  LESSONS
// ══════════════════════════
app.get('/api/lessons', auth, (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  let lessons = db.lessons || [];
  if (classId) lessons = lessons.filter(l => l.classId === classId);
  res.json(lessons);
});

app.post('/api/lessons', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, title, content, files } = req.body;
  if (!classId || !title) return res.status(400).json({ error: 'کلاس و عنوان الزامی است' });
  const db = loadDB();
  if (!ownsClass(req, db, classId)) return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  const lesson = {
    id: uid(), classId, title, content: content || '',
    files: files || [], teacherId: req.user.id,
    createdAt: new Date().toISOString()
  };
  if (!db.lessons) db.lessons = [];
  db.lessons.push(lesson);
  const cls = (db.classes || []).find(c => c.id === classId);
  if (cls) cls.studentIds.forEach(sid => addNotif(db, sid, `درس جدید: "${title}" در کلاس ${cls.name}`, 'lesson'));
  saveDB(db);
  res.json(lesson);
});

app.patch('/api/lessons/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const lesson = (db.lessons || []).find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, lesson.classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  Object.assign(lesson, req.body);
  saveDB(db);
  res.json(lesson);
});

app.delete('/api/lessons/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.lessons || []).findIndex(l => l.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, db.lessons[idx].classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  db.lessons.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  ASSIGNMENTS
// ══════════════════════════
app.get('/api/assignments', auth, (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  let list = db.assignments || [];
  if (classId) list = list.filter(a => a.classId === classId);
  res.json(list);
});

app.post('/api/assignments', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, title, description, dueDate } = req.body;
  if (!classId || !title) return res.status(400).json({ error: 'کلاس و عنوان الزامی است' });
  const db = loadDB();
  if (!ownsClass(req, db, classId)) return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  const a = { id: uid(), classId, title, description: description || '', dueDate: dueDate || '', teacherId: req.user.id, createdAt: new Date().toISOString() };
  if (!db.assignments) db.assignments = [];
  db.assignments.push(a);
  const cls = (db.classes || []).find(c => c.id === classId);
  if (cls) cls.studentIds.forEach(sid => addNotif(db, sid, `تکلیف جدید: "${title}"`, 'assignment'));
  saveDB(db);
  res.json(a);
});

app.delete('/api/assignments/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.assignments || []).findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, db.assignments[idx].classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  const assignmentId = db.assignments[idx].id;
  db.assignments.splice(idx, 1);
  // پاک‌سازی پاسخ‌های وابسته
  db.submissions = (db.submissions || []).filter(s => s.assignmentId !== assignmentId);
  saveDB(db);
  res.json({ ok: true });
});

app.post('/api/assignments/:id/submit', auth, role('student'), (req, res) => {
  const { text, files } = req.body;
  const db = loadDB();
  if (!db.submissions) db.submissions = [];
  const existing = db.submissions.find(s => s.assignmentId === req.params.id && s.studentId === req.user.id);
  if (existing) return res.status(400).json({ error: 'قبلاً ارسال کرده‌اید' });
  const sub = {
    id: uid(), assignmentId: req.params.id,
    studentId: req.user.id, studentName: req.user.name,
    text: text || '', files: files || [],
    grade: null, feedback: '', submittedAt: new Date().toISOString()
  };
  db.submissions.push(sub);
  saveDB(db);
  res.json(sub);
});

app.get('/api/assignments/:id/submissions', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const assignment = (db.assignments || []).find(a => a.id === req.params.id);
  if (!assignment) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, assignment.classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  res.json((db.submissions || []).filter(s => s.assignmentId === req.params.id));
});

app.patch('/api/submissions/:id/grade', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const sub = (db.submissions || []).find(s => s.id === req.params.id);
  if (!sub) return res.status(404).json({ error: 'یافت نشد' });
  const assignment = (db.assignments || []).find(a => a.id === sub.assignmentId);
  if (!assignment || !ownsClass(req, db, assignment.classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  sub.grade = req.body.grade;
  sub.feedback = req.body.feedback || '';
  addNotif(db, sub.studentId, `نمره تکلیف شما ثبت شد: ${sub.grade}`, 'grade');
  saveDB(db);
  res.json(sub);
});

// دریافت تکالیف ارسال شده توسط دانش‌آموز
app.get('/api/student/submissions', auth, role('student'), (req, res) => {
  const db = loadDB();
  res.json((db.submissions || []).filter(s => s.studentId === req.user.id));
});

// ══════════════════════════
//  QUIZZES
// ══════════════════════════
app.get('/api/quizzes', auth, (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  let list = db.quizzes || [];
  if (classId) list = list.filter(q => q.classId === classId);
  // برای دانش‌آموز: آزمون‌هایی که قبلاً داده‌اند مشخص بشه
  if (req.user.role === 'student') {
    const done = (db.quizSubmissions || []).filter(s => s.studentId === req.user.id).map(s => s.quizId);
    list = list.map(q => ({ ...q, done: done.includes(q.id) }));
  }
  res.json(list);
});

app.post('/api/quizzes', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, title, questions } = req.body;
  if (!classId || !title || !questions?.length) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  if (!ownsClass(req, db, classId)) return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  const quiz = { id: uid(), classId, title, questions, teacherId: req.user.id, active: true, createdAt: new Date().toISOString() };
  if (!db.quizzes) db.quizzes = [];
  db.quizzes.push(quiz);
  const cls = (db.classes || []).find(c => c.id === classId);
  if (cls) cls.studentIds.forEach(sid => addNotif(db, sid, `آزمون جدید: "${title}"`, 'quiz'));
  saveDB(db);
  res.json(quiz);
});

app.delete('/api/quizzes/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.quizzes || []).findIndex(q => q.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, db.quizzes[idx].classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  const quizId = db.quizzes[idx].id;
  db.quizzes.splice(idx, 1);
  db.quizSubmissions = (db.quizSubmissions || []).filter(s => s.quizId !== quizId);
  saveDB(db);
  res.json({ ok: true });
});

// دریافت آزمون برای دانش‌آموز (بدون پاسخ)
app.get('/api/student/quizzes/:id', auth, role('student'), (req, res) => {
  const db = loadDB();
  const quiz = (db.quizzes || []).find(q => q.id === req.params.id && q.active);
  if (!quiz) return res.status(404).json({ error: 'آزمون یافت نشد' });
  const already = (db.quizSubmissions || []).find(s => s.quizId === req.params.id && s.studentId === req.user.id);
  if (already) return res.status(400).json({ error: 'قبلاً این آزمون را داده‌اید', submission: already });
  // پاسخ‌ها رو پنهان کن
  const questions = quiz.questions.map(q => {
    const { answer, explanation, ...safe } = q;
    return safe;
  });
  res.json({ id: quiz.id, title: quiz.title, questions });
});

// ارسال پاسخ آزمون توسط دانش‌آموز
app.post('/api/student/quizzes/:id/submit', auth, role('student'), (req, res) => {
  const { answers } = req.body;
  const db = loadDB();
  const quiz = (db.quizzes || []).find(q => q.id === req.params.id);
  if (!quiz) return res.status(404).json({ error: 'آزمون یافت نشد' });
  if ((db.quizSubmissions || []).find(s => s.quizId === req.params.id && s.studentId === req.user.id))
    return res.status(400).json({ error: 'قبلاً این آزمون را داده‌اید' });

  let correct = 0;
  const results = quiz.questions.map((q, i) => {
    const userAns = (answers[i] || '').trim().toLowerCase();
    const correctAns = (q.answer || '').trim().toLowerCase();
    let isCorrect = false;
    if (q.type === 'mc' || q.type === 'tf') isCorrect = userAns === correctAns;
    else if (q.type === 'fill') isCorrect = userAns !== '' && (userAns === correctAns || correctAns.includes(userAns));
    else isCorrect = userAns.length > 5; // تشریحی
    if (isCorrect) correct++;
    return {
      question: q.question, userAnswer: answers[i] || '',
      correctAnswer: q.answer, isCorrect, explanation: q.explanation || ''
    };
  });

  const score = Math.round((correct / quiz.questions.length) * 100);
  const sub = {
    id: uid(), quizId: quiz.id, quizTitle: quiz.title,
    studentId: req.user.id, studentName: req.user.name,
    score, correct, total: quiz.questions.length,
    results, submittedAt: new Date().toISOString()
  };
  if (!db.quizSubmissions) db.quizSubmissions = [];
  db.quizSubmissions.push(sub);
  // بررسی و اعطای خودکار نشان‌ها بعد از هر آزمون
  evaluateBadges(db, req.user.id, quiz.classId);
  // افزودن XP و بروزرسانی استریک روزانه
  addXP(db, req.user.id, 15 + Math.round(score / 10), 'quiz_submit');
  bumpStreak(db, req.user.id);
  saveDB(db);
  res.json(sub);
});

// ══════════════════════════
//  XP / LEVEL SYSTEM (ارتقا ۱)
// ══════════════════════════
function xpForLevel(level) { return 100 * level * (level + 1) / 2; } // مجموع تصاعدی ساده
function levelFromXP(xp) {
  let level = 1;
  while (xpForLevel(level + 1) <= xp) level++;
  return level;
}
function addXP(db, studentId, amount, reason) {
  if (!db.studentXP) db.studentXP = [];
  let rec = db.studentXP.find(x => x.studentId === studentId);
  if (!rec) { rec = { studentId, totalXP: 0, history: [] }; db.studentXP.push(rec); }
  const prevLevel = levelFromXP(rec.totalXP);
  rec.totalXP += amount;
  rec.history.push({ amount, reason, at: new Date().toISOString() });
  if (rec.history.length > 100) rec.history = rec.history.slice(-100);
  const newLevel = levelFromXP(rec.totalXP);
  if (newLevel > prevLevel) addNotif(db, studentId, `🎉 تبریک! به سطح ${newLevel} رسیدید!`, 'level_up');
  return rec;
}

app.get('/api/students/me/xp', auth, role('student'), (req, res) => {
  const db = loadDB();
  const rec = (db.studentXP || []).find(x => x.studentId === req.user.id) || { totalXP: 0, history: [] };
  const level = levelFromXP(rec.totalXP);
  const currentLevelXP = xpForLevel(level);
  const nextLevelXP = xpForLevel(level + 1);
  res.json({
    totalXP: rec.totalXP, level,
    progressInLevel: rec.totalXP - currentLevelXP,
    neededForNext: nextLevelXP - currentLevelXP,
    recentHistory: rec.history.slice(-10).reverse()
  });
});

// ══════════════════════════
//  DAILY STREAK (ارتقا ۲)
// ══════════════════════════
function bumpStreak(db, studentId) {
  if (!db.studentStreaks) db.studentStreaks = [];
  let rec = db.studentStreaks.find(s => s.studentId === studentId);
  const today = new Date().toISOString().slice(0, 10);
  if (!rec) { rec = { studentId, currentStreak: 1, longestStreak: 1, lastActiveDate: today }; db.studentStreaks.push(rec); return rec; }
  if (rec.lastActiveDate === today) return rec; // امروز قبلاً ثبت شده
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  if (rec.lastActiveDate === yesterday) rec.currentStreak++;
  else rec.currentStreak = 1; // زنجیره شکسته شد
  rec.longestStreak = Math.max(rec.longestStreak, rec.currentStreak);
  rec.lastActiveDate = today;
  if ([3, 7, 14, 30].includes(rec.currentStreak)) addNotif(db, studentId, `🔥 ${rec.currentStreak} روز متوالی فعالیت! عالیه!`, 'streak');
  return rec;
}
app.get('/api/students/me/streak', auth, role('student'), (req, res) => {
  const db = loadDB();
  const rec = (db.studentStreaks || []).find(s => s.studentId === req.user.id) || { currentStreak: 0, longestStreak: 0, lastActiveDate: null };
  // اگر آخرین فعالیت دیروز یا امروز نبوده، استریک عملاً صفر شده (نمایش صادقانه بدون تغییر دیتابیس)
  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const isActive = rec.lastActiveDate === today || rec.lastActiveDate === yesterday;
  res.json({ currentStreak: isActive ? rec.currentStreak : 0, longestStreak: rec.longestStreak, lastActiveDate: rec.lastActiveDate });
});
// ثبت فعالیت ساده (بازدید از درس و...) برای حفظ استریک بدون آزمون
app.post('/api/students/me/activity-ping', auth, role('student'), (req, res) => {
  const db = loadDB();
  bumpStreak(db, req.user.id);
  addXP(db, req.user.id, 2, 'daily_activity');
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  FLASHCARDS (ارتقا ۳) - از سوالات آزمون‌های گذشته
// ══════════════════════════
app.get('/api/students/me/flashcards', auth, role('student'), (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  // سوالات از آزمون‌هایی که دانش‌آموز شرکت کرده و به آن‌ها اشتباه پاسخ داده (اولویت مرور)، به‌علاوه بقیه سوالات
  const mySubs = (db.quizSubmissions || []).filter(s => s.studentId === req.user.id);
  const cards = [];
  mySubs.forEach(sub => {
    const quiz = (db.quizzes || []).find(q => q.id === sub.quizId);
    if (!quiz) return;
    if (classId && quiz.classId !== classId) return;
    sub.results.forEach((r, i) => {
      if (quiz.questions[i]?.type === 'essay') return; // تشریحی برای فلش‌کارت مناسب نیست
      cards.push({
        id: `${sub.id}_${i}`, question: r.question, answer: r.correctAnswer,
        wasCorrect: r.isCorrect, quizTitle: quiz.title, classId: quiz.classId
      });
    });
  });
  // اولویت: سوالاتی که قبلاً اشتباه بوده اول بیایند
  cards.sort((a, b) => (a.wasCorrect === b.wasCorrect) ? 0 : (a.wasCorrect ? 1 : -1));
  res.json(cards);
});

// ثبت نتیجه مرور یک فلش‌کارت (برای spaced repetition ساده)
app.post('/api/students/me/flashcards/review', auth, role('student'), (req, res) => {
  const { cardId, knewIt } = req.body;
  const db = loadDB();
  if (!db.flashcardReviews) db.flashcardReviews = [];
  db.flashcardReviews.push({ id: uid(), studentId: req.user.id, cardId, knewIt: !!knewIt, reviewedAt: new Date().toISOString() });
  if (knewIt) addXP(db, req.user.id, 1, 'flashcard_review');
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  STUDENT PERFORMANCE ANALYTICS (ارتقا ۴ و ۵)
// ══════════════════════════
app.get('/api/students/me/performance', auth, role('student'), (req, res) => {
  const db = loadDB();
  const mySubs = (db.quizSubmissions || []).filter(s => s.studentId === req.user.id).sort((a, b) => new Date(a.submittedAt) - new Date(b.submittedAt));

  // روند نمرات من در طول زمان
  const trend = mySubs.map(s => ({ quizTitle: s.quizTitle, date: s.submittedAt.slice(0, 10), score: s.score }));

  // تحلیل نقاط ضعف: بر اساس نوع سوال، کدام نوع بیشترین خطا را دارد
  const typeStats = {};
  mySubs.forEach(sub => {
    const quiz = (db.quizzes || []).find(q => q.id === sub.quizId);
    if (!quiz) return;
    sub.results.forEach((r, i) => {
      const type = quiz.questions[i]?.type || 'other';
      if (!typeStats[type]) typeStats[type] = { correct: 0, total: 0 };
      typeStats[type].total++;
      if (r.isCorrect) typeStats[type].correct++;
    });
  });
  const weaknesses = Object.entries(typeStats).map(([type, s]) => ({
    type, correctPct: Math.round((s.correct / s.total) * 100), total: s.total
  })).sort((a, b) => a.correctPct - b.correctPct);

  const avgScore = mySubs.length ? Math.round(mySubs.reduce((a, s) => a + s.score, 0) / mySubs.length) : 0;
  res.json({ trend, weaknesses, avgScore, totalQuizzes: mySubs.length });
});

// رتبه شخصی دانش‌آموز در کلاس (بدون افشای نام بقیه - ملایم)
app.get('/api/classes/:id/my-rank', auth, role('student'), (req, res) => {
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === req.params.id);
  if (!cls || !(cls.studentIds || []).includes(req.user.id)) return res.status(403).json({ error: 'دسترسی ندارید' });

  const quizIds = (db.quizzes || []).filter(q => q.classId === cls.id).map(q => q.id);
  const scores = (cls.studentIds || []).map(sid => {
    const subs = (db.quizSubmissions || []).filter(s => quizIds.includes(s.quizId) && s.studentId === sid);
    const avg = subs.length ? subs.reduce((a, s) => a + s.score, 0) / subs.length : 0;
    return { studentId: sid, avg };
  }).sort((a, b) => b.avg - a.avg);

  const myIndex = scores.findIndex(s => s.studentId === req.user.id);
  res.json({
    rank: myIndex + 1, totalStudents: scores.length,
    myAvg: Math.round(scores[myIndex]?.avg || 0),
    percentile: scores.length > 1 ? Math.round(((scores.length - myIndex - 1) / (scores.length - 1)) * 100) : 100
  });
});

// چک‌لیست روزانه دانش‌آموز (ارتقا ۷)
app.get('/api/students/me/today', auth, role('student'), (req, res) => {
  const db = loadDB();
  const myClasses = (db.classes || []).filter(c => (c.studentIds || []).includes(req.user.id));
  const classIds = myClasses.map(c => c.id);
  const today = new Date().toISOString().slice(0, 10);

  const doneQuizIds = (db.quizSubmissions || []).filter(s => s.studentId === req.user.id).map(s => s.quizId);
  const pendingQuizzes = (db.quizzes || []).filter(q => classIds.includes(q.classId) && q.active && !doneQuizIds.includes(q.id));

  const doneAsgIds = (db.submissions || []).filter(s => s.studentId === req.user.id).map(s => s.assignmentId);
  const dueSoonAsg = (db.assignments || []).filter(a => classIds.includes(a.classId) && !doneAsgIds.includes(a.id) && a.dueDate && a.dueDate >= today);

  const activeSessions = (db.classSessions || []).filter(s => classIds.includes(s.classId) && s.active && (s.students || []).includes(req.user.id));

  res.json({
    pendingQuizzes: pendingQuizzes.map(q => ({ id: q.id, title: q.title, classId: q.classId })),
    dueSoonAssignments: dueSoonAsg.map(a => ({ id: a.id, title: a.title, dueDate: a.dueDate, classId: a.classId })),
    activeSessions: activeSessions.map(s => ({ id: s.id, title: s.title, classId: s.classId }))
  });
});

// تقویم شخصی دانش‌آموز (ارتقا ۸)
app.get('/api/students/me/calendar', auth, role('student'), (req, res) => {
  const db = loadDB();
  const myClasses = (db.classes || []).filter(c => (c.studentIds || []).includes(req.user.id));
  const classIds = myClasses.map(c => c.id);
  const events = [];
  (db.assignments || []).filter(a => classIds.includes(a.classId) && a.dueDate).forEach(a => {
    const cls = myClasses.find(c => c.id === a.classId);
    events.push({ type: 'assignment', id: a.id, title: a.title, date: a.dueDate, className: cls?.name || '' });
  });
  (db.classSessions || []).filter(s => classIds.includes(s.classId)).forEach(s => {
    const cls = myClasses.find(c => c.id === s.classId);
    events.push({ type: 'session', id: s.id, title: s.title, date: s.startedAt.slice(0, 10), className: cls?.name || '', active: s.active });
  });
  res.json(events);
});

// پیام تشویقی خودکار بر اساس عملکرد اخیر (ارتقا ۱۰ - منطق قانونی، بدون AI)
app.get('/api/students/me/motivation', auth, role('student'), (req, res) => {
  const db = loadDB();
  const mySubs = (db.quizSubmissions || []).filter(s => s.studentId === req.user.id).sort((a, b) => new Date(b.submittedAt) - new Date(a.submittedAt));
  const streak = (db.studentStreaks || []).find(s => s.studentId === req.user.id);

  let message, emoji;
  if (!mySubs.length) {
    message = 'به سامانه خوش آمدید! اولین آزمون خود را شروع کنید.'; emoji = '👋';
  } else {
    const last = mySubs[0].score;
    const prevAvg = mySubs.length > 1 ? Math.round(mySubs.slice(1, 4).reduce((a, s) => a + s.score, 0) / Math.min(3, mySubs.length - 1)) : last;
    if (last >= 90) { message = 'عملکرد فوق‌العاده‌ای داشتید! همینطور ادامه دهید.'; emoji = '🏆'; }
    else if (last > prevAvg + 10) { message = 'پیشرفت چشمگیری داشتید! به همین روند ادامه دهید.'; emoji = '📈'; }
    else if (last < prevAvg - 15) { message = 'نمره اخیر کمی افت داشته. شاید وقت مرور دوباره مطالب باشد.'; emoji = '💪'; }
    else if (streak?.currentStreak >= 5) { message = `${streak.currentStreak} روز متوالی فعالیت داشتید. عالیه!`; emoji = '🔥'; }
    else { message = 'به تلاش خود ادامه دهید، هر آزمون یک قدم به جلوست.'; emoji = '✨'; }
  }
  res.json({ message, emoji });
});

// ══════════════════════════
//  QUESTION BANK (بانک سوال مرکزی - ارتقا ۲)
// ══════════════════════════
app.get('/api/question-bank', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const { tag, type } = req.query;
  let list = (db.questionBank || []).filter(q => q.teacherId === req.user.id);
  if (tag) list = list.filter(q => (q.tags || []).includes(tag));
  if (type) list = list.filter(q => q.type === type);
  res.json(list);
});

app.post('/api/question-bank', auth, role('teacher', 'admin'), (req, res) => {
  const { type, question, options, answer, explanation, tags } = req.body;
  if (!type || !question || !answer) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  const q = {
    id: uid(), teacherId: req.user.id, type, question,
    options: options || [], answer, explanation: explanation || '',
    tags: tags || [], usageCount: 0, createdAt: new Date().toISOString()
  };
  if (!db.questionBank) db.questionBank = [];
  db.questionBank.push(q);
  saveDB(db);
  res.json(q);
});

app.delete('/api/question-bank/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.questionBank || []).findIndex(q => q.id === req.params.id && q.teacherId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.questionBank.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// افزایش شمارنده استفاده وقتی سوال از بانک به آزمون اضافه می‌شود
app.post('/api/question-bank/:id/use', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const q = (db.questionBank || []).find(q => q.id === req.params.id && q.teacherId === req.user.id);
  if (!q) return res.status(404).json({ error: 'یافت نشد' });
  q.usageCount = (q.usageCount || 0) + 1;
  saveDB(db);
  res.json({ ok: true });
});

// همه برچسب‌های منحصربه‌فرد معلم (برای فیلتر UI)
app.get('/api/question-bank/tags', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const tags = new Set();
  (db.questionBank || []).filter(q => q.teacherId === req.user.id).forEach(q => (q.tags || []).forEach(t => tags.add(t)));
  res.json([...tags]);
});

// ══════════════════════════
//  LESSON LIBRARY - کپی درس بین کلاس‌ها (ارتقا ۳)
// ══════════════════════════
app.post('/api/lessons/:id/copy', auth, role('teacher', 'admin'), (req, res) => {
  const { targetClassId } = req.body;
  if (!targetClassId) return res.status(400).json({ error: 'کلاس مقصد الزامی است' });
  const db = loadDB();
  const lesson = (db.lessons || []).find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'درس یافت نشد' });
  if (!ownsClass(req, db, lesson.classId) || !ownsClass(req, db, targetClassId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  const copy = { ...lesson, id: uid(), classId: targetClassId, createdAt: new Date().toISOString() };
  db.lessons.push(copy);
  const cls = (db.classes || []).find(c => c.id === targetClassId);
  if (cls) cls.studentIds.forEach(sid => addNotif(db, sid, `درس جدید: "${copy.title}" در کلاس ${cls.name}`, 'lesson'));
  saveDB(db);
  res.json(copy);
});

// ══════════════════════════
//  CLASS CALENDAR - تقویم کلاسی (ارتقا ۴)
// ══════════════════════════
// تجمیع تمام رویدادهای معلم (تکلیف، آزمون، جلسه) در یک تقویم
app.get('/api/teacher/calendar', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const myClassIds = (db.classes || []).filter(c => req.user.role === 'admin' || c.teacherId === req.user.id).map(c => c.id);
  const events = [];
  (db.assignments || []).filter(a => myClassIds.includes(a.classId) && a.dueDate).forEach(a => {
    const cls = (db.classes || []).find(c => c.id === a.classId);
    events.push({ type: 'assignment', id: a.id, title: a.title, date: a.dueDate, className: cls?.name || '' });
  });
  (db.classSessions || []).filter(s => myClassIds.includes(s.classId)).forEach(s => {
    const cls = (db.classes || []).find(c => c.id === s.classId);
    events.push({ type: 'session', id: s.id, title: s.title, date: s.startedAt.slice(0, 10), className: cls?.name || '', active: s.active });
  });
  (db.quizzes || []).filter(q => myClassIds.includes(q.classId)).forEach(q => {
    const cls = (db.classes || []).find(c => c.id === q.classId);
    events.push({ type: 'quiz', id: q.id, title: q.title, date: q.createdAt.slice(0, 10), className: cls?.name || '' });
  });
  res.json(events);
});

// ══════════════════════════
//  LEADERBOARD - رتبه‌بندی کلاس (ارتقا ۵)
// ══════════════════════════
app.get('/api/classes/:id/leaderboard', auth, (req, res) => {
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'یافت نشد' });
  const isMember = cls.teacherId === req.user.id || (cls.studentIds || []).includes(req.user.id) || req.user.role === 'admin';
  if (!isMember) return res.status(403).json({ error: 'دسترسی ندارید' });

  const scores = {};
  (cls.studentIds || []).forEach(sid => { scores[sid] = { studentId: sid, quizAvg: 0, quizCount: 0, asgAvg: 0, asgCount: 0, points: 0 }; });

  const quizIds = (db.quizzes || []).filter(q => q.classId === cls.id).map(q => q.id);
  (db.quizSubmissions || []).filter(s => quizIds.includes(s.quizId) && scores[s.studentId]).forEach(s => {
    scores[s.studentId].quizCount++;
    scores[s.studentId].quizAvg += s.score;
  });

  const asgIds = (db.assignments || []).filter(a => a.classId === cls.id).map(a => a.id);
  (db.submissions || []).filter(s => asgIds.includes(s.assignmentId) && scores[s.studentId] && s.grade !== null).forEach(s => {
    scores[s.studentId].asgCount++;
    scores[s.studentId].asgAvg += (s.grade / 20) * 100; // نرمال‌سازی به درصد
  });

  const allU = db.users;
  const result = Object.values(scores).map(s => {
    const u = allU.find(x => x.id === s.studentId);
    const quizAvg = s.quizCount ? Math.round(s.quizAvg / s.quizCount) : 0;
    const asgAvg = s.asgCount ? Math.round(s.asgAvg / s.asgCount) : 0;
    const points = (s.quizCount * 10) + (s.asgCount * 8) + Math.round((quizAvg + asgAvg) / 2 * 0.5);
    return { studentId: s.studentId, studentName: u?.name || 'ناشناس', quizAvg, quizCount: s.quizCount, asgAvg, asgCount: s.asgCount, points };
  }).sort((a, b) => b.points - a.points);

  res.json(result);
});

// ══════════════════════════
//  BADGES - نشان‌ها و جوایز (ارتقا ۶)
// ══════════════════════════
const BADGE_DEFS = [
  { key: 'quiz_ace_5', name: 'قهرمان آزمون', icon: '🏆', desc: '۵ آزمون بالای ۹۰٪', check: (stats) => stats.highQuizCount >= 5 },
  { key: 'perfect_attendance', name: 'حضور کامل', icon: '📅', desc: 'یک ماه بدون غیبت', check: (stats) => stats.attendanceStreak >= 20 },
  { key: 'homework_hero', name: 'قهرمان تکلیف', icon: '📝', desc: '۱۰ تکلیف به‌موقع', check: (stats) => stats.onTimeAsg >= 10 },
  { key: 'first_quiz', name: 'اولین قدم', icon: '🎯', desc: 'شرکت در اولین آزمون', check: (stats) => stats.quizCount >= 1 },
  { key: 'top_scorer', name: 'نمره برتر', icon: '⭐', desc: 'میانگین بالای ۹۵٪', check: (stats) => stats.avgScore >= 95 }
];

// محاسبه و اعطای خودکار نشان‌ها برای یک دانش‌آموز در یک کلاس
function evaluateBadges(db, studentId, classId) {
  const quizIds = (db.quizzes || []).filter(q => q.classId === classId).map(q => q.id);
  const subs = (db.quizSubmissions || []).filter(s => quizIds.includes(s.quizId) && s.studentId === studentId);
  const stats = {
    quizCount: subs.length,
    highQuizCount: subs.filter(s => s.score >= 90).length,
    avgScore: subs.length ? Math.round(subs.reduce((a, s) => a + s.score, 0) / subs.length) : 0,
    attendanceStreak: (db.attendance || []).filter(a => a.classId === classId && a.records.find(r => r.studentId === studentId && r.status === 'present')).length,
    onTimeAsg: (db.submissions || []).filter(s => s.studentId === studentId).length
  };
  if (!db.studentBadges) db.studentBadges = [];
  const earned = [];
  BADGE_DEFS.forEach(def => {
    const already = db.studentBadges.find(b => b.studentId === studentId && b.classId === classId && b.badgeKey === def.key);
    if (!already && def.check(stats)) {
      const badge = { id: uid(), studentId, classId, badgeKey: def.key, earnedAt: new Date().toISOString() };
      db.studentBadges.push(badge);
      earned.push({ ...badge, ...def });
      addNotif(db, studentId, `🎉 نشان جدید کسب کردید: ${def.icon} ${def.name}`, 'badge');
    }
  });
  return earned;
}

app.get('/api/students/:id/badges', auth, (req, res) => {
  const db = loadDB();
  // خود دانش‌آموز یا معلم کلاس‌های مشترک یا ادمین می‌تواند ببیند
  if (req.user.role === 'student' && req.user.id !== req.params.id) return res.status(403).json({ error: 'دسترسی ندارید' });
  const list = (db.studentBadges || []).filter(b => b.studentId === req.params.id).map(b => {
    const def = BADGE_DEFS.find(d => d.key === b.badgeKey);
    return { ...b, ...def };
  });
  res.json(list);
});

app.get('/api/badges/definitions', auth, (req, res) => res.json(BADGE_DEFS.map(({ check, ...d }) => d)));

// ══════════════════════════
//  STUDENT NOTES - یادداشت خصوصی معلم (ارتقا ۹)
// ══════════════════════════
app.get('/api/students/:id/notes', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const notes = (db.studentNotes || []).filter(n => n.studentId === req.params.id && n.teacherId === req.user.id);
  res.json(notes);
});

app.post('/api/students/:id/notes', auth, role('teacher', 'admin'), (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'متن یادداشت الزامی است' });
  const db = loadDB();
  const note = { id: uid(), studentId: req.params.id, teacherId: req.user.id, text, createdAt: new Date().toISOString() };
  if (!db.studentNotes) db.studentNotes = [];
  db.studentNotes.push(note);
  saveDB(db);
  res.json(note);
});

app.delete('/api/students/notes/:noteId', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.studentNotes || []).findIndex(n => n.id === req.params.noteId && n.teacherId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.studentNotes.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  TEMPLATES - الگوی تکلیف/آزمون (ارتقا ۱۰)
// ══════════════════════════
app.get('/api/templates/assignments', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  res.json((db.assignmentTemplates || []).filter(t => t.teacherId === req.user.id));
});
app.post('/api/templates/assignments', auth, role('teacher', 'admin'), (req, res) => {
  const { title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'عنوان الزامی است' });
  const db = loadDB();
  const t = { id: uid(), teacherId: req.user.id, title, description: description || '', createdAt: new Date().toISOString() };
  if (!db.assignmentTemplates) db.assignmentTemplates = [];
  db.assignmentTemplates.push(t);
  saveDB(db);
  res.json(t);
});
app.delete('/api/templates/assignments/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.assignmentTemplates || []).findIndex(t => t.id === req.params.id && t.teacherId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.assignmentTemplates.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

app.get('/api/templates/quizzes', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  res.json((db.quizTemplates || []).filter(t => t.teacherId === req.user.id));
});
app.post('/api/templates/quizzes', auth, role('teacher', 'admin'), (req, res) => {
  const { title, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  const t = { id: uid(), teacherId: req.user.id, title, questions, createdAt: new Date().toISOString() };
  if (!db.quizTemplates) db.quizTemplates = [];
  db.quizTemplates.push(t);
  saveDB(db);
  res.json(t);
});
app.delete('/api/templates/quizzes/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const idx = (db.quizTemplates || []).findIndex(t => t.id === req.params.id && t.teacherId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'یافت نشد' });
  db.quizTemplates.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  ADVANCED ANALYTICS - آمار پیشرفته (ارتقا ۱)
// ══════════════════════════
app.get('/api/classes/:id/analytics', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, cls.id)) return res.status(403).json({ error: 'دسترسی ندارید' });

  const quizIds = (db.quizzes || []).filter(q => q.classId === cls.id).map(q => q.id);
  const allSubs = (db.quizSubmissions || []).filter(s => quizIds.includes(s.quizId)).sort((a, b) => new Date(a.submittedAt) - new Date(b.submittedAt));

  // روند نمرات کلاس در طول زمان (میانگین هر آزمون)
  const trend = (db.quizzes || []).filter(q => q.classId === cls.id).map(q => {
    const subs = allSubs.filter(s => s.quizId === q.id);
    const avg = subs.length ? Math.round(subs.reduce((a, s) => a + s.score, 0) / subs.length) : null;
    return { quizTitle: q.title, date: q.createdAt.slice(0, 10), avgScore: avg, submissionCount: subs.length };
  });

  // مقایسه دانش‌آموزها
  const studentStats = (cls.studentIds || []).map(sid => {
    const subs = allSubs.filter(s => s.studentId === sid);
    const u = db.users.find(x => x.id === sid);
    const avg = subs.length ? Math.round(subs.reduce((a, s) => a + s.score, 0) / subs.length) : 0;
    return { studentId: sid, studentName: u?.name || 'ناشناس', avgScore: avg, quizCount: subs.length };
  }).sort((a, b) => b.avgScore - a.avgScore);

  // هشدار افت تحصیلی: دانش‌آموزانی که آخرین نمره‌شان به‌طور محسوس کمتر از میانگین قبلی‌شان است
  const atRisk = [];
  (cls.studentIds || []).forEach(sid => {
    const subs = allSubs.filter(s => s.studentId === sid);
    if (subs.length < 2) return;
    const last = subs[subs.length - 1].score;
    const prevAvg = Math.round(subs.slice(0, -1).reduce((a, s) => a + s.score, 0) / (subs.length - 1));
    if (prevAvg - last >= 20) {
      const u = db.users.find(x => x.id === sid);
      atRisk.push({ studentId: sid, studentName: u?.name || 'ناشناس', lastScore: last, previousAvg: prevAvg, drop: prevAvg - last });
    }
  });

  res.json({ trend, studentStats, atRisk, totalStudents: (cls.studentIds || []).length });
});

// تحلیل سوال به سوال یک آزمون (ارتقا ۸)
app.get('/api/quizzes/:id/item-analysis', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const quiz = (db.quizzes || []).find(q => q.id === req.params.id);
  if (!quiz) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, quiz.classId)) return res.status(403).json({ error: 'دسترسی ندارید' });
  const subs = (db.quizSubmissions || []).filter(s => s.quizId === quiz.id);
  if (!subs.length) return res.json({ questions: [], totalSubmissions: 0 });

  const questions = quiz.questions.map((q, i) => {
    const answers = subs.map(s => s.results[i]);
    const correctCount = answers.filter(a => a?.isCorrect).length;
    const wrongAnswers = {};
    answers.filter(a => a && !a.isCorrect).forEach(a => {
      const key = a.userAnswer || '(بدون پاسخ)';
      wrongAnswers[key] = (wrongAnswers[key] || 0) + 1;
    });
    return {
      question: q.question, type: q.type,
      correctCount, totalCount: answers.length,
      correctPct: Math.round((correctCount / answers.length) * 100),
      commonWrongAnswers: Object.entries(wrongAnswers).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([answer, count]) => ({ answer, count }))
    };
  });
  res.json({ questions, totalSubmissions: subs.length });
});

// گزارش کامل کلاس برای Export/PDF (ارتقا ۷) - داده خام؛ ساخت PDF سمت کلاینت با چاپ مرورگر انجام می‌شود
app.get('/api/classes/:id/report', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'یافت نشد' });
  if (!ownsClass(req, db, cls.id)) return res.status(403).json({ error: 'دسترسی ندارید' });

  const quizIds = (db.quizzes || []).filter(q => q.classId === cls.id).map(q => q.id);
  const asgIds = (db.assignments || []).filter(a => a.classId === cls.id).map(a => a.id);

  const students = (cls.studentIds || []).map(sid => {
    const u = db.users.find(x => x.id === sid);
    const quizSubs = (db.quizSubmissions || []).filter(s => quizIds.includes(s.quizId) && s.studentId === sid);
    const asgSubs = (db.submissions || []).filter(s => asgIds.includes(s.assignmentId) && s.studentId === sid);
    const attRecords = (db.attendance || []).filter(a => a.classId === cls.id).flatMap(a => a.records.filter(r => r.studentId === sid).map(r => r.status));
    return {
      name: u?.name || 'ناشناس', email: u?.email || '',
      quizAvg: quizSubs.length ? Math.round(quizSubs.reduce((a, s) => a + s.score, 0) / quizSubs.length) : null,
      quizCount: quizSubs.length,
      asgSubmitted: asgSubs.length, asgTotal: asgIds.length,
      asgAvgGrade: asgSubs.filter(s => s.grade !== null).length ? Math.round(asgSubs.filter(s => s.grade !== null).reduce((a, s) => a + s.grade, 0) / asgSubs.filter(s => s.grade !== null).length * 10) / 10 : null,
      present: attRecords.filter(s => s === 'present').length,
      absent: attRecords.filter(s => s === 'absent').length,
      late: attRecords.filter(s => s === 'late').length
    };
  });

  res.json({ className: cls.name, subject: cls.subject, teacherName: cls.teacherName, generatedAt: new Date().toISOString(), students });
});

// ══════════════════════════
//  ATTENDANCE
// ══════════════════════════
app.get('/api/attendance', auth, (req, res) => {
  const db = loadDB();
  const { classId, date } = req.query;
  let list = db.attendance || [];
  if (classId) list = list.filter(a => a.classId === classId);
  if (date) list = list.filter(a => a.date === date);
  res.json(list);
});

app.post('/api/attendance', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, date, records } = req.body;
  if (!classId || !date || !records) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  if (!ownsClass(req, db, classId)) return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  if (!db.attendance) db.attendance = [];
  const existing = db.attendance.find(a => a.classId === classId && a.date === date);
  if (existing) {
    existing.records = records;
    saveDB(db);
    return res.json(existing);
  }
  const att = { id: uid(), classId, date, records, teacherId: req.user.id, createdAt: new Date().toISOString() };
  db.attendance.push(att);
  records.forEach(r => {
    if (r.status === 'absent') addNotif(db, r.studentId, `غیبت شما در تاریخ ${date} ثبت شد`, 'attendance');
  });
  saveDB(db);
  res.json(att);
});

// ══════════════════════════
//  POLLS
// ══════════════════════════
app.get('/api/polls', auth, (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  let polls = db.polls || [];
  if (classId) polls = polls.filter(p => p.classId === classId);
  const votes = db.pollVotes || [];
  res.json(polls.map(p => ({
    ...p,
    myVote: votes.find(v => v.pollId === p.id && v.userId === req.user.id)?.option ?? null,
    results: p.options.map((opt, i) => ({ option: opt, count: votes.filter(v => v.pollId === p.id && v.option === i).length }))
  })));
});

app.post('/api/polls', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, question, options } = req.body;
  if (!classId || !question || !options?.length) return res.status(400).json({ error: 'اطلاعات ناقص است' });
  const db = loadDB();
  if (!ownsClass(req, db, classId)) return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  const poll = { id: uid(), classId, question, options, teacherId: req.user.id, active: true, createdAt: new Date().toISOString() };
  if (!db.polls) db.polls = [];
  db.polls.push(poll);
  const cls = (db.classes || []).find(c => c.id === classId);
  if (cls) cls.studentIds.forEach(sid => addNotif(db, sid, `نظرسنجی جدید: "${question}"`, 'poll'));
  saveDB(db);
  res.json(poll);
});

app.post('/api/polls/:id/vote', auth, (req, res) => {
  const { option } = req.body;
  if (option === undefined || option === null) return res.status(400).json({ error: 'گزینه الزامی است' });
  const db = loadDB();
  if (!db.pollVotes) db.pollVotes = [];
  const existing = db.pollVotes.find(v => v.pollId === req.params.id && v.userId === req.user.id);
  if (existing) { existing.option = option; }
  else { db.pollVotes.push({ id: uid(), pollId: req.params.id, userId: req.user.id, option, createdAt: new Date().toISOString() }); }
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  CHAT
// ══════════════════════════
app.get('/api/chat/rooms', auth, (req, res) => {
  const db = loadDB();
  const rooms = (db.chatRooms || []).filter(r => (r.members || []).includes(req.user.id));
  const userPrefs = (db.roomUserPrefs || []).filter(p => p.userId === req.user.id);
  res.json(rooms.map(r => {
    const msgs = (db.messages || []).filter(m => m.roomId === r.id && !m.deleted);
    const lastMsg = msgs[msgs.length - 1] || null;
    let displayName = r.name;
    if (r.type === 'private') {
      const otherId = (r.members || []).find(id => id !== req.user.id);
      const other = db.users.find(u => u.id === otherId);
      displayName = other ? other.name : 'کاربر حذف‌شده';
    }
    const unreadCount = msgs.filter(m => m.senderId !== req.user.id && !(m.readBy || []).includes(req.user.id)).length;
    const pref = userPrefs.find(p => p.roomId === r.id);
    return { ...r, name: displayName, lastMsg, unreadCount, pinned: !!pref?.pinned, archived: !!pref?.archived };
  }));
});

// پین/آنپین یک گفتگو در لیست (شخصی برای هر کاربر، نه سراسری)
app.post('/api/chat/rooms/:id/pin', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  if (!db.roomUserPrefs) db.roomUserPrefs = [];
  let pref = db.roomUserPrefs.find(p => p.roomId === req.params.id && p.userId === req.user.id);
  if (!pref) { pref = { roomId: req.params.id, userId: req.user.id, pinned: false, archived: false }; db.roomUserPrefs.push(pref); }
  pref.pinned = !pref.pinned;
  saveDB(db);
  res.json({ pinned: pref.pinned });
});

// بایگانی/خروج از بایگانی یک گفتگو
app.post('/api/chat/rooms/:id/archive', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  if (!db.roomUserPrefs) db.roomUserPrefs = [];
  let pref = db.roomUserPrefs.find(p => p.roomId === req.params.id && p.userId === req.user.id);
  if (!pref) { pref = { roomId: req.params.id, userId: req.user.id, pinned: false, archived: false }; db.roomUserPrefs.push(pref); }
  pref.archived = !pref.archived;
  saveDB(db);
  res.json({ archived: pref.archived });
});

app.post('/api/chat/rooms', auth, (req, res) => {
  const { targetId, name } = req.body;
  if (!targetId) return res.status(400).json({ error: 'targetId الزامی است' });
  const db = loadDB();
  const target = db.users.find(u => u.id === targetId);
  if (!target) return res.status(404).json({ error: 'کاربر مورد نظر یافت نشد' });
  if (!db.chatRooms) db.chatRooms = [];
  const existing = db.chatRooms.find(r => r.type === 'private' && r.members.includes(req.user.id) && r.members.includes(targetId));
  if (existing) return res.json(existing);
  const room = {
    id: uid(), type: 'private',
    name: name || `چت با ${target.name}`,
    members: [req.user.id, targetId], createdAt: new Date().toISOString()
  };
  db.chatRooms.push(room);
  saveDB(db);
  res.json(room);
});

app.get('/api/chat/rooms/:id/messages', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  const before = req.query.before; // برای صفحه‌بندی تاریخچه (بارگذاری پیام‌های قدیمی‌تر)
  let msgs = (db.messages || []).filter(m => m.roomId === req.params.id && !m.deleted);
  if (before) {
    const idx = msgs.findIndex(m => m.id === before);
    if (idx > -1) msgs = msgs.slice(0, idx);
  }
  msgs = msgs.slice(-50);
  // پیوست reactions به هر پیام
  const reactions = db.messageReactions || [];
  msgs = msgs.map(m => ({
    ...m,
    reactions: reactions.filter(r => r.messageId === m.id).reduce((acc, r) => {
      acc[r.emoji] = acc[r.emoji] || [];
      acc[r.emoji].push(r.userId);
      return acc;
    }, {})
  }));
  res.json(msgs);
});

app.post('/api/chat/rooms/:id/messages', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  const { text, fileUrl, fileName, fileType, fileSize, voiceUrl, voiceDuration, replyToId } = req.body;

  let replyTo = null;
  if (replyToId) {
    const original = (db.messages || []).find(m => m.id === replyToId && m.roomId === req.params.id);
    if (original) replyTo = { id: original.id, text: original.text || (original.fileName ? '📎 ' + original.fileName : voiceUrl ? '🎤 پیام صوتی' : ''), senderName: original.senderName };
  }

  const msg = {
    id: uid(), senderId: req.user.id, senderName: req.user.name,
    senderRole: req.user.role, roomId: req.params.id,
    text: text || '', fileUrl: fileUrl || '', fileName: fileName || '',
    fileType: fileType || '', fileSize: fileSize || 0,
    voiceUrl: voiceUrl || '', voiceDuration: voiceDuration || 0,
    replyTo, edited: false, deleted: false,
    readBy: [req.user.id], createdAt: new Date().toISOString()
  };
  if (!db.messages) db.messages = [];
  db.messages.push(msg);
  saveDB(db);
  const members = new Set(room.members);
  clients.forEach((sock, uid2) => {
    if (members.has(uid2) && uid2 !== req.user.id) wsSend(sock, { type: 'chat_message', message: msg });
  });
  res.json(msg);
});

// ─── ادیت پیام (ارتقا ۲) ───
app.patch('/api/chat/messages/:id', auth, (req, res) => {
  const db = loadDB();
  const msg = (db.messages || []).find(m => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: 'پیام یافت نشد' });
  if (msg.senderId !== req.user.id) return res.status(403).json({ error: 'فقط فرستنده می‌تواند ویرایش کند' });
  if (msg.deleted) return res.status(400).json({ error: 'پیام حذف شده است' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: 'متن پیام الزامی است' });
  msg.text = text.trim();
  msg.edited = true;
  msg.editedAt = new Date().toISOString();
  saveDB(db);
  const room = (db.chatRooms || []).find(r => r.id === msg.roomId);
  if (room) {
    const members = new Set(room.members);
    clients.forEach((sock, uid2) => { if (members.has(uid2)) wsSend(sock, { type: 'message_edited', message: msg }); });
  }
  res.json(msg);
});

// ─── حذف پیام (ارتقا ۲) ───
app.delete('/api/chat/messages/:id', auth, (req, res) => {
  const db = loadDB();
  const msg = (db.messages || []).find(m => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: 'پیام یافت نشد' });
  if (msg.senderId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'دسترسی ندارید' });
  msg.deleted = true;
  msg.text = '';
  msg.fileUrl = ''; msg.voiceUrl = '';
  saveDB(db);
  const room = (db.chatRooms || []).find(r => r.id === msg.roomId);
  if (room) {
    const members = new Set(room.members);
    clients.forEach((sock, uid2) => { if (members.has(uid2)) wsSend(sock, { type: 'message_deleted', messageId: msg.id, roomId: msg.roomId }); });
  }
  res.json({ ok: true });
});

// ─── وضعیت خوانده‌شدن (ارتقا ۱) ───
app.post('/api/chat/rooms/:id/read', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  const { messageIds } = req.body; // آرایه اختیاری؛ اگر نیامد همه پیام‌های روم خوانده می‌شود
  const msgs = (db.messages || []).filter(m => m.roomId === req.params.id && (!messageIds || messageIds.includes(m.id)));
  const newlyRead = [];
  msgs.forEach(m => {
    if (!m.readBy) m.readBy = [];
    if (!m.readBy.includes(req.user.id)) { m.readBy.push(req.user.id); newlyRead.push(m.id); }
  });
  saveDB(db);
  if (newlyRead.length) {
    const members = new Set(room.members);
    clients.forEach((sock, uid2) => {
      if (members.has(uid2) && uid2 !== req.user.id) wsSend(sock, { type: 'messages_read', roomId: req.params.id, messageIds: newlyRead, readerId: req.user.id });
    });
  }
  res.json({ ok: true, readCount: newlyRead.length });
});

// ─── ریاکشن ایموجی (ارتقا ۷) ───
app.post('/api/chat/messages/:id/react', auth, (req, res) => {
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'ایموجی الزامی است' });
  const db = loadDB();
  const msg = (db.messages || []).find(m => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: 'پیام یافت نشد' });
  const room = (db.chatRooms || []).find(r => r.id === msg.roomId && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  if (!db.messageReactions) db.messageReactions = [];
  const existing = db.messageReactions.find(r => r.messageId === req.params.id && r.userId === req.user.id && r.emoji === emoji);
  if (existing) {
    // toggle off
    db.messageReactions = db.messageReactions.filter(r => r !== existing);
  } else {
    db.messageReactions.push({ id: uid(), messageId: req.params.id, userId: req.user.id, emoji, createdAt: new Date().toISOString() });
  }
  saveDB(db);
  const reactions = db.messageReactions.filter(r => r.messageId === req.params.id).reduce((acc, r) => {
    acc[r.emoji] = acc[r.emoji] || [];
    acc[r.emoji].push(r.userId);
    return acc;
  }, {});
  const members = new Set(room.members);
  clients.forEach((sock, uid2) => { if (members.has(uid2)) wsSend(sock, { type: 'reaction_update', messageId: req.params.id, roomId: msg.roomId, reactions }); });
  res.json({ reactions });
});

// ─── پین کردن پیام (ارتقا ۵) ───
app.post('/api/chat/messages/:id/pin', auth, (req, res) => {
  const db = loadDB();
  const msg = (db.messages || []).find(m => m.id === req.params.id);
  if (!msg) return res.status(404).json({ error: 'پیام یافت نشد' });
  const room = (db.chatRooms || []).find(r => r.id === msg.roomId && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  if (!db.pinnedMessages) db.pinnedMessages = [];
  const already = db.pinnedMessages.find(p => p.messageId === req.params.id);
  if (already) {
    db.pinnedMessages = db.pinnedMessages.filter(p => p !== already);
  } else {
    db.pinnedMessages.push({ id: uid(), messageId: req.params.id, roomId: msg.roomId, pinnedBy: req.user.id, pinnedAt: new Date().toISOString() });
  }
  saveDB(db);
  const members = new Set(room.members);
  clients.forEach((sock, uid2) => { if (members.has(uid2)) wsSend(sock, { type: 'pin_update', roomId: msg.roomId }); });
  res.json({ pinned: !already });
});

app.get('/api/chat/rooms/:id/pinned', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  const pins = (db.pinnedMessages || []).filter(p => p.roomId === req.params.id);
  const msgs = pins.map(p => (db.messages || []).find(m => m.id === p.messageId)).filter(Boolean);
  res.json(msgs);
});

// ─── جستجو در تاریخچه پیام‌ها (ارتقا ۴ و ۹) ───
app.get('/api/chat/rooms/:id/search', auth, (req, res) => {
  const db = loadDB();
  const room = (db.chatRooms || []).find(r => r.id === req.params.id && (r.members || []).includes(req.user.id));
  if (!room) return res.status(403).json({ error: 'دسترسی ندارید' });
  const { q, senderId, type, from, to } = req.query;
  let msgs = (db.messages || []).filter(m => m.roomId === req.params.id && !m.deleted);
  if (q) msgs = msgs.filter(m => (m.text || '').toLowerCase().includes(q.toLowerCase()));
  if (senderId) msgs = msgs.filter(m => m.senderId === senderId);
  if (type === 'file') msgs = msgs.filter(m => m.fileUrl);
  if (type === 'voice') msgs = msgs.filter(m => m.voiceUrl);
  if (type === 'text') msgs = msgs.filter(m => m.text && !m.fileUrl && !m.voiceUrl);
  if (from) msgs = msgs.filter(m => m.createdAt >= from);
  if (to) msgs = msgs.filter(m => m.createdAt <= to);
  res.json(msgs.slice(-100).reverse());
});

// ─── وضعیت آنلاین/آفلاین (ارتقا ۱۰) ───
app.get('/api/chat/presence', auth, (req, res) => {
  const db = loadDB();
  const { userIds } = req.query; // comma-separated
  const ids = userIds ? userIds.split(',') : [];
  const result = {};
  ids.forEach(id => {
    const rec = (db.userPresence || []).find(p => p.userId === id);
    result[id] = { online: clients.has(id), lastSeen: rec?.lastSeen || null };
  });
  res.json(result);
});

// ══════════════════════════
//  VIRTUAL CLASS
// ══════════════════════════
app.get('/api/sessions', auth, (req, res) => {
  const db = loadDB();
  const { classId } = req.query;
  let sessions = db.classSessions || [];
  if (classId) sessions = sessions.filter(s => s.classId === classId);
  if (req.user.role === 'student') sessions = sessions.filter(s => (s.students || []).includes(req.user.id));
  res.json(sessions);
});

app.post('/api/sessions', auth, role('teacher', 'admin'), (req, res) => {
  const { classId, title, meetLink } = req.body;
  const db = loadDB();
  const cls = (db.classes || []).find(c => c.id === classId);
  if (!cls) return res.status(404).json({ error: 'کلاس یافت نشد' });
  if (req.user.role === 'teacher' && cls.teacherId !== req.user.id) {
    return res.status(403).json({ error: 'شما معلم این کلاس نیستید' });
  }
  const session = {
    id: uid(), classId, title: title || `کلاس ${new Date().toLocaleDateString('fa-IR')}`,
    teacherId: cls.teacherId, teacherName: cls.teacherName,
    students: cls.studentIds || [], meetLink: meetLink || '',
    active: true, startedAt: new Date().toISOString(), whiteboardData: [],
    breakoutGroups: [], breakoutActive: false, livePoll: null
  };
  if (!db.classSessions) db.classSessions = [];
  db.classSessions.push(session);
  (cls.studentIds || []).forEach(sid => addNotif(db, sid, `کلاس آنلاین شروع شد: "${session.title}"`, 'class'));
  saveDB(db);
  res.json(session);
});

app.patch('/api/sessions/:id', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const s = (db.classSessions || []).find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role === 'teacher' && s.teacherId !== req.user.id) return res.status(403).json({ error: 'دسترسی ندارید' });
  Object.assign(s, req.body);
  saveDB(db);
  res.json(s);
});

app.get('/api/sessions/:id', auth, (req, res) => {
  const db = loadDB();
  const s = (db.classSessions || []).find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  // فقط معلم برگزارکننده یا دانش‌آموزان همان کلاس دسترسی دارند
  const isTeacher = s.teacherId === req.user.id;
  const isStudent = (s.students || []).includes(req.user.id);
  const isAdmin = req.user.role === 'admin';
  if (!isTeacher && !isStudent && !isAdmin) return res.status(403).json({ error: 'دسترسی ندارید' });
  const msgs = (db.classMessages || []).filter(m => m.classId === req.params.id).slice(-200);
  res.json({ ...s, messages: msgs });
});

app.post('/api/sessions/:id/whiteboard', auth, (req, res) => {
  const db = loadDB();
  const s = (db.classSessions || []).find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  const isTeacher = s.teacherId === req.user.id;
  const isStudent = (s.students || []).includes(req.user.id);
  if (!isTeacher && !isStudent && req.user.role !== 'admin') return res.status(403).json({ error: 'دسترسی ندارید' });
  s.whiteboardData = req.body.data || [];
  saveDB(db);
  res.json({ ok: true });
});

// پایان جلسه توسط معلم
app.post('/api/sessions/:id/end', auth, role('teacher', 'admin'), (req, res) => {
  const db = loadDB();
  const s = (db.classSessions || []).find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role === 'teacher' && s.teacherId !== req.user.id) return res.status(403).json({ error: 'دسترسی ندارید' });
  s.active = false;
  s.endedAt = new Date().toISOString();
  saveDB(db);
  // به همه اعضا خبر بده که جلسه تمام شد
  const members = new Set([s.teacherId, ...s.students]);
  broadcast({ type: 'session_ended', classId: s.id }, id => members.has(id));
  res.json({ ok: true });
});

// ذخیره ضبط جلسه (فایل ویدیویی ضبط‌شده سمت مرورگر با MediaRecorder)
app.post('/api/sessions/:id/recording', auth, role('teacher', 'admin'), (req, res) => {
  const { name, data } = req.body;
  if (!name || !data) return res.status(400).json({ error: 'فایل ضبط الزامی است' });
  const db = loadDB();
  const s = (db.classSessions || []).find(s => s.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'یافت نشد' });
  if (req.user.role === 'teacher' && s.teacherId !== req.user.id) return res.status(403).json({ error: 'دسترسی ندارید' });
  try {
    const fname = uid() + (path.extname(name) || '.webm');
    const fpath = path.join(__dirname, 'public', 'uploads', fname);
    const buf = Buffer.from(data.replace(/^data:.+;base64,/, ''), 'base64');
    if (buf.length > 200 * 1024 * 1024) return res.status(400).json({ error: 'حجم ضبط بیش از حد مجاز (۲۰۰MB)' });
    fs.writeFileSync(fpath, buf);
    if (!s.recordings) s.recordings = [];
    s.recordings.push({ url: '/uploads/' + fname, name, createdAt: new Date().toISOString() });
    saveDB(db);
    res.json({ url: '/uploads/' + fname });
  } catch (e) {
    res.status(500).json({ error: 'خطا در ذخیره ضبط' });
  }
});

// ══════════════════════════
//  FILE UPLOAD
// ══════════════════════════
app.post('/api/upload', auth, (req, res) => {
  const { name, data } = req.body;
  if (!name || !data) return res.status(400).json({ error: 'فایل الزامی است' });
  try {
    const ext = path.extname(name) || '';
    const fname = uid() + ext;
    const fpath = path.join(__dirname, 'public', 'uploads', fname);
    const buf = Buffer.from(data.replace(/^data:.+;base64,/, ''), 'base64');
    if (buf.length > 25 * 1024 * 1024) return res.status(400).json({ error: 'حجم فایل بیش از ۲۵MB' });
    fs.writeFileSync(fpath, buf);
    res.json({ url: '/uploads/' + fname, name });
  } catch (e) {
    res.status(500).json({ error: 'خطا در ذخیره فایل' });
  }
});

// ─── آپلود پیشرفته چت (ارتقا ۶) - اعتبارسنجی نوع/حجم بر اساس نوع فایل ───
const CHAT_FILE_LIMITS = {
  image: { exts: ['.jpg', '.jpeg', '.png', '.gif', '.webp'], maxMB: 10 },
  video: { exts: ['.mp4', '.webm', '.mov'], maxMB: 50 },
  audio: { exts: ['.mp3', '.wav', '.webm', '.ogg', '.m4a'], maxMB: 15 },
  document: { exts: ['.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.txt', '.zip'], maxMB: 25 }
};
function classifyExt(ext) {
  ext = ext.toLowerCase();
  for (const [category, def] of Object.entries(CHAT_FILE_LIMITS)) {
    if (def.exts.includes(ext)) return { category, maxMB: def.maxMB };
  }
  return null;
}
app.post('/api/chat/upload', auth, (req, res) => {
  const { name, data, kind } = req.body; // kind: 'file' یا 'voice'
  if (!name || !data) return res.status(400).json({ error: 'فایل الزامی است' });
  const ext = path.extname(name) || '';
  const info = classifyExt(ext);
  if (kind !== 'voice' && !info) {
    return res.status(400).json({ error: `نوع فایل "${ext}" مجاز نیست. فرمت‌های مجاز: تصویر، ویدیو، صوت، سند` });
  }
  try {
    const buf = Buffer.from(data.replace(/^data:.+;base64,/, ''), 'base64');
    const maxMB = kind === 'voice' ? 15 : info.maxMB;
    if (buf.length > maxMB * 1024 * 1024) return res.status(400).json({ error: `حجم فایل بیش از ${maxMB}MB مجاز است` });
    const fname = uid() + (ext || '.webm');
    const fpath = path.join(__dirname, 'public', 'uploads', fname);
    fs.writeFileSync(fpath, buf);
    res.json({
      url: '/uploads/' + fname, name,
      fileType: kind === 'voice' ? 'audio' : (info?.category || 'document'),
      fileSize: buf.length
    });
  } catch (e) {
    res.status(500).json({ error: 'خطا در ذخیره فایل' });
  }
});

// ══════════════════════════
//  NOTIFICATIONS
// ══════════════════════════
app.get('/api/notifications', auth, (req, res) => {
  const db = loadDB();
  const notifs = (db.notifications || []).filter(n => n.userId === req.user.id).slice(-50).reverse();
  res.json(notifs);
});

app.patch('/api/notifications/read', auth, (req, res) => {
  const db = loadDB();
  (db.notifications || []).filter(n => n.userId === req.user.id).forEach(n => n.read = true);
  saveDB(db);
  res.json({ ok: true });
});

// ══════════════════════════
//  CONTACTS
// ══════════════════════════
app.get('/api/contacts', auth, (req, res) => {
  const db = loadDB();
  const myClasses = (db.classes || []).filter(c =>
    c.teacherId === req.user.id || (c.studentIds || []).includes(req.user.id)
  );
  const ids = new Set();
  myClasses.forEach(c => { ids.add(c.teacherId); (c.studentIds || []).forEach(id => ids.add(id)); });
  ids.delete(req.user.id);
  const contacts = db.users.filter(u => ids.has(u.id) && u.active !== false).map(u => ({ id: u.id, name: u.name, role: u.role }));
  res.json(contacts);
});

// ══════════════════════════
//  PUBLIC ENDPOINTS برای صفحه Home
// ══════════════════════════

// آمار عمومی سامانه (بدون افشای اطلاعات حساس)
app.get('/api/public/stats', (req, res) => {
  const db = loadDB();
  res.json({
    teachers: db.users.filter(u => u.role === 'teacher').length,
    students: db.users.filter(u => u.role === 'student').length,
    classes: (db.classes || []).length,
    lessons: (db.lessons || []).length
  });
});

// وضعیت آنلاین بودن سرور (health-check ساده)
app.get('/api/public/status', (req, res) => {
  res.json({ status: 'online', time: new Date().toISOString(), uptimeSeconds: Math.floor(process.uptime()) });
});

// آخرین بروزرسانی‌های سامانه (Changelog) — برای صفحه Home
app.get('/api/public/changelog', (req, res) => {
  res.json([
    { version: '2.4', date: '1404-05-14', items: ['اضافه شدن پین و بایگانی گفتگو در پیام‌رسان', 'پیام صوتی و واکنش ایموجی در چت', 'کلاس مجازی با تخته چندلایه و اتاق‌های گروهی'] },
    { version: '2.3', date: '1404-05-01', items: ['اضافه شدن گیمیفیکیشن دانش‌آموز (XP، سطح، استریک)', 'فلش‌کارت هوشمند برای مرور', 'داشبورد تحلیلی پیشرفته برای معلم'] },
    { version: '2.2', date: '1404-04-20', items: ['بانک سوال مرکزی و امکان کپی درس بین کلاس‌ها', 'رتبه‌بندی و نشان‌های کلاسی', 'گزارش‌گیری و خروجی چاپی'] },
    { version: '2.1', date: '1404-04-05', items: ['راه‌اندازی اولیه سامانه با پنل مدیر، معلم و دانش‌آموز', 'آزمون‌ساز، حضور و غیاب و نظرسنجی'] }
  ]);
});

// پروکسی آب‌وهوا (open-meteo، بدون نیاز به کلید API) — جلوگیری از افشای هرگونه کلید در کلاینت
app.get('/api/public/weather', async (req, res) => {
  const { lat, lon } = req.query;
  if (!lat || !lon) return res.status(400).json({ error: 'مختصات جغرافیایی الزامی است' });
  try {
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${encodeURIComponent(lat)}&longitude=${encodeURIComponent(lon)}&current=temperature_2m,weather_code,relative_humidity_2m&timezone=auto`;
    const r = await fetch(url);
    if (!r.ok) throw new Error('weather api error');
    const data = await r.json();
    res.json({
      temp: Math.round(data.current.temperature_2m),
      humidity: data.current.relative_humidity_2m,
      code: data.current.weather_code
    });
  } catch (e) {
    res.status(502).json({ error: 'دریافت آب‌وهوا ناموفق بود' });
  }
});

// ══════════════════════════
//  PAGES
// ══════════════════════════
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
['admin', 'teacher', 'student'].forEach(r =>
  app.get(`/${r}`, (_, res) => res.sendFile(path.join(__dirname, 'public', `${r}.html`)))
);
app.get('/chat', (_, res) => res.sendFile(path.join(__dirname, 'public', 'chat.html')));
app.get('/classroom', (_, res) => res.sendFile(path.join(__dirname, 'public', 'classroom.html')));

// ─── ساخت ادمین پیش‌فرض ───
const db0 = loadDB();
if (!db0.users) db0.users = [];
if (!db0.users.find(u => u.role === 'admin')) {
  db0.users.push({
    id: uid(), name: 'مدیر سیستم', email: 'admin@school.ir',
    password: hashPw('admin123'), role: 'admin', active: true,
    createdAt: new Date().toISOString()
  });
  saveDB(db0);
  console.log('✅ Admin created: admin@school.ir / admin123');
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`✅ EduApp running on http://localhost:${PORT}`));
