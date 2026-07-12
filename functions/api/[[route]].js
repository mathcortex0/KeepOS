// ==================== HELPERS ====================

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode('keepos-jwt-secret-key-2025');
  const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const header = { alg: 'HS256', typ: 'JWT' };
  const parts = [
    btoa(JSON.stringify(header)).replace(/=+$/, ''),
    btoa(JSON.stringify(payload)).replace(/=+$/, '')
  ];
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(parts.join('.')));
  const sig = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=+$/, '');
  return parts.join('.') + '.' + sig;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const encoder = new TextEncoder();
    const keyData = encoder.encode('keepos-jwt-secret-key-2025');
    const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(parts[2]), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(parts[0] + '.' + parts[1]));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return await verifyToken(match[1].trim());
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' };

// ==================== DATABASE SETUP ====================

async function ensureTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      master_key_hash TEXT,
      created_at INTEGER NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS subjects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      color TEXT DEFAULT '#00d4aa',
      icon TEXT DEFAULT 'book',
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS chapters (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_id INTEGER NOT NULL REFERENCES subjects(id),
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_chapters_subject ON chapters(subject_id)`).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS topics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      chapter_id INTEGER NOT NULL REFERENCES chapters(id),
      name TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_topics_chapter ON topics(chapter_id)`).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      topic_id INTEGER NOT NULL REFERENCES topics(id),
      title TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'text',
      content_html TEXT,
      url TEXT,
      image_url TEXT,
      sort_order INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_notes_topic ON notes(topic_id)`).run();

  // Seed admin user
  const pwHash = await sha256('zxcv1234A');
  await db.prepare(
    `INSERT OR IGNORE INTO users (email, password_hash, master_key_hash, created_at) VALUES (?, ?, NULL, ?)`
  ).bind('mdalamin.cnct@gmail.com', pwHash, Date.now()).run();

  // Migrations
  const migrations = [
    `ALTER TABLE notes ADD COLUMN content_html TEXT`,
    `ALTER TABLE notes ADD COLUMN url TEXT`,
    `ALTER TABLE notes ADD COLUMN image_url TEXT`
  ];
  for (const sql of migrations) {
    try { await db.prepare(sql).run(); } catch {}
  }
}

// ==================== AUTH HANDLERS ====================

async function handleAuth(method, path, body, db) {
  // POST /api/auth/login
  if (method === 'POST' && path === '/api/auth/login') {
    const { email, password, masterKey } = body || {};
    if (!email || !password || !masterKey) return err('Email, password, and master key are required.');

    const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user) return err('Invalid credentials.', 401);

    const pwHash = await sha256(password);
    if (pwHash !== user.password_hash) return err('Invalid credentials.', 401);

    const mkHash = await sha256(masterKey);

    // First login: set master key
    if (!user.master_key_hash) {
      await db.prepare('UPDATE users SET master_key_hash = ? WHERE id = ?').bind(mkHash, user.id).run();
    } else if (mkHash !== user.master_key_hash) {
      return err('Invalid master key.', 401);
    }

    const token = await signToken({ id: user.id, email: user.email, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
    return json({ token, user: { id: user.id, email: user.email } });
  }

  // GET /api/auth/me
  if (method === 'GET' && path === '/api/auth/me') return err('Method not allowed', 405);

  // POST /api/auth/change-password
  if (method === 'POST' && path === '/api/auth/change-password') {
    const { currentPassword, newPassword } = body || {};
    if (!currentPassword || !newPassword) return err('Current and new password are required.');

    const userRecord = await db.prepare('SELECT * FROM users WHERE id = ?').bind(body._userId).first();
    const curHash = await sha256(currentPassword);
    if (curHash !== userRecord.password_hash) return err('Current password is incorrect.', 401);

    const newHash = await sha256(newPassword);
    await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').bind(newHash, body._userId).run();
    return json({ ok: true });
  }

  // POST /api/auth/change-masterkey
  if (method === 'POST' && path === '/api/auth/change-masterkey') {
    const { currentPassword, newMasterKey } = body || {};
    if (!currentPassword || !newMasterKey) return err('Current password and new master key are required.');

    const userRecord = await db.prepare('SELECT * FROM users WHERE id = ?').bind(body._userId).first();
    const curHash = await sha256(currentPassword);
    if (curHash !== userRecord.password_hash) return err('Current password is incorrect.', 401);

    const newHash = await sha256(newMasterKey);
    await db.prepare('UPDATE users SET master_key_hash = ? WHERE id = ?').bind(newHash, body._userId).run();
    return json({ ok: true });
  }

  return err('Not found', 404);
}

// ==================== SUBJECT HANDLERS ====================

async function handleSubjects(method, path, body, db, userId) {
  const idMatch = path.match(/^\/api\/subjects\/(\d+)$/);
  const chaptersMatch = path.match(/^\/api\/subjects\/(\d+)\/chapters$/);

  // GET /api/subjects
  if (method === 'GET' && path === '/api/subjects') {
    const subjects = await db.prepare(`
      SELECT s.*,
        (SELECT COUNT(*) FROM chapters c WHERE c.subject_id = s.id) as chapter_count,
        (SELECT COUNT(*) FROM topics t JOIN chapters c ON t.chapter_id = c.id WHERE c.subject_id = s.id) as topic_count,
        (SELECT COUNT(*) FROM notes n JOIN topics t ON n.topic_id = t.id JOIN chapters c ON t.chapter_id = c.id WHERE c.subject_id = s.id) as note_count
      FROM subjects s ORDER BY s.sort_order ASC, s.name ASC
    `).all();
    return json(subjects.results);
  }

  // POST /api/subjects
  if (method === 'POST' && path === '/api/subjects') {
    const { name, color, icon } = body || {};
    if (!name) return err('Name is required.');
    const result = await db.prepare(
      `INSERT INTO subjects (name, color, icon, created_at) VALUES (?, ?, ?, ?)`
    ).bind(name, color || '#00d4aa', icon || 'book', Date.now()).run();
    const subject = await db.prepare('SELECT * FROM subjects WHERE id = ?').bind(result.meta.last_row_id).first();
    return json(subject, 201);
  }

  // GET /api/subjects/:id
  if (method === 'GET' && idMatch) {
    const id = parseInt(idMatch[1]);
    const subject = await db.prepare('SELECT * FROM subjects WHERE id = ?').bind(id).first();
    if (!subject) return err('Subject not found', 404);
    const counts = await db.prepare(`
      SELECT
        (SELECT COUNT(*) FROM chapters WHERE subject_id = ?) as chapter_count,
        (SELECT COUNT(*) FROM topics t JOIN chapters c ON t.chapter_id = c.id WHERE c.subject_id = ?) as topic_count,
        (SELECT COUNT(*) FROM notes n JOIN topics t ON n.topic_id = t.id JOIN chapters c ON t.chapter_id = c.id WHERE c.subject_id = ?) as note_count
    `).bind(id, id, id).first();
    return json({ ...subject, ...counts });
  }

  // PUT /api/subjects/:id
  if (method === 'PUT' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM subjects WHERE id = ?').bind(id).first();
    if (!existing) return err('Subject not found', 404);
    const { name, color, icon, sort_order } = body || {};
    await db.prepare(
      `UPDATE subjects SET name = ?, color = ?, icon = ?, sort_order = ? WHERE id = ?`
    ).bind(
      name ?? existing.name, color ?? existing.color, icon ?? existing.icon,
      sort_order ?? existing.sort_order, id
    ).run();
    const updated = await db.prepare('SELECT * FROM subjects WHERE id = ?').bind(id).first();
    return json(updated);
  }

  // DELETE /api/subjects/:id
  if (method === 'DELETE' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM subjects WHERE id = ?').bind(id).first();
    if (!existing) return err('Subject not found', 404);
    // Count cascaded items
    const chapters = await db.prepare('SELECT id FROM chapters WHERE subject_id = ?').bind(id).all();
    let topicCount = 0, noteCount = 0;
    for (const ch of chapters.results) {
      const topics = await db.prepare('SELECT id FROM topics WHERE chapter_id = ?').bind(ch.id).all();
      topicCount += topics.results.length;
      for (const tp of topics.results) {
        const notes = await db.prepare('SELECT id FROM notes WHERE topic_id = ?').bind(tp.id).all();
        noteCount += notes.results.length;
        await db.prepare('DELETE FROM notes WHERE topic_id = ?').bind(tp.id).run();
      }
      await db.prepare('DELETE FROM topics WHERE chapter_id = ?').bind(ch.id).run();
    }
    await db.prepare('DELETE FROM chapters WHERE subject_id = ?').bind(id).run();
    await db.prepare('DELETE FROM subjects WHERE id = ?').bind(id).run();
    return json({ ok: true, deleted: { chapters: chapters.results.length, topics: topicCount, notes: noteCount } });
  }

  // GET /api/subjects/:id/chapters
  if (method === 'GET' && chaptersMatch) {
    const subjectId = parseInt(chaptersMatch[1]);
    const chaptersList = await db.prepare(`
      SELECT c.*,
        (SELECT COUNT(*) FROM topics t WHERE t.chapter_id = c.id) as topic_count,
        (SELECT COUNT(*) FROM notes n JOIN topics t ON n.topic_id = t.id WHERE t.chapter_id = c.id) as note_count
      FROM chapters c WHERE c.subject_id = ? ORDER BY c.sort_order ASC, c.name ASC
    `).bind(subjectId).all();
    return json(chaptersList.results);
  }

  return err('Not found', 404);
}

// ==================== CHAPTER HANDLERS ====================

async function handleChapters(method, path, body, db, userId) {
  const idMatch = path.match(/^\/api\/chapters\/(\d+)$/);
  const topicsMatch = path.match(/^\/api\/chapters\/(\d+)\/topics$/);

  // POST /api/chapters
  if (method === 'POST' && path === '/api/chapters') {
    const { subject_id, name } = body || {};
    if (!subject_id || !name) return err('subject_id and name are required.');
    const result = await db.prepare(
      `INSERT INTO chapters (subject_id, name, created_at) VALUES (?, ?, ?)`
    ).bind(subject_id, name, Date.now()).run();
    const chapter = await db.prepare('SELECT * FROM chapters WHERE id = ?').bind(result.meta.last_row_id).first();
    return json(chapter, 201);
  }

  // GET /api/chapters/:id
  if (method === 'GET' && idMatch) {
    const id = parseInt(idMatch[1]);
    const chapter = await db.prepare(`
      SELECT c.*, s.id as subject_id, s.name as subject_name, s.color as subject_color
      FROM chapters c JOIN subjects s ON c.subject_id = s.id WHERE c.id = ?
    `).bind(id).first();
    if (!chapter) return err('Chapter not found', 404);
    const result = {
      id: chapter.id, name: chapter.name, subject_id: chapter.subject_id,
      sort_order: chapter.sort_order, created_at: chapter.created_at,
      subject: { id: chapter.subject_id, name: chapter.subject_name }
    };
    return json(result);
  }

  // PUT /api/chapters/:id
  if (method === 'PUT' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM chapters WHERE id = ?').bind(id).first();
    if (!existing) return err('Chapter not found', 404);
    const { name, subject_id, sort_order } = body || {};
    await db.prepare(
      `UPDATE chapters SET name = ?, subject_id = ?, sort_order = ? WHERE id = ?`
    ).bind(
      name ?? existing.name, subject_id ?? existing.subject_id,
      sort_order ?? existing.sort_order, id
    ).run();
    const updated = await db.prepare('SELECT * FROM chapters WHERE id = ?').bind(id).first();
    return json(updated);
  }

  // DELETE /api/chapters/:id
  if (method === 'DELETE' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM chapters WHERE id = ?').bind(id).first();
    if (!existing) return err('Chapter not found', 404);
    const topics = await db.prepare('SELECT id FROM topics WHERE chapter_id = ?').bind(id).all();
    let noteCount = 0;
    for (const tp of topics.results) {
      const notes = await db.prepare('SELECT id FROM notes WHERE topic_id = ?').bind(tp.id).all();
      noteCount += notes.results.length;
      await db.prepare('DELETE FROM notes WHERE topic_id = ?').bind(tp.id).run();
    }
    await db.prepare('DELETE FROM topics WHERE chapter_id = ?').bind(id).run();
    await db.prepare('DELETE FROM chapters WHERE id = ?').bind(id).run();
    return json({ ok: true, deleted: { topics: topics.results.length, notes: noteCount } });
  }

  // GET /api/chapters/:id/topics
  if (method === 'GET' && topicsMatch) {
    const chapterId = parseInt(topicsMatch[1]);
    const topicsList = await db.prepare(`
      SELECT t.*,
        (SELECT COUNT(*) FROM notes n WHERE n.topic_id = t.id) as note_count
      FROM topics t WHERE t.chapter_id = ? ORDER BY t.sort_order ASC, t.name ASC
    `).bind(chapterId).all();
    return json(topicsList.results);
  }

  return err('Not found', 404);
}

// ==================== TOPIC HANDLERS ====================

async function handleTopics(method, path, body, db, userId) {
  const idMatch = path.match(/^\/api\/topics\/(\d+)$/);
  const notesMatch = path.match(/^\/api\/topics\/(\d+)\/notes$/);

  // POST /api/topics
  if (method === 'POST' && path === '/api/topics') {
    const { chapter_id, name } = body || {};
    if (!chapter_id || !name) return err('chapter_id and name are required.');
    const result = await db.prepare(
      `INSERT INTO topics (chapter_id, name, created_at) VALUES (?, ?, ?)`
    ).bind(chapter_id, name, Date.now()).run();
    const topic = await db.prepare('SELECT * FROM topics WHERE id = ?').bind(result.meta.last_row_id).first();
    return json(topic, 201);
  }

  // GET /api/topics/:id
  if (method === 'GET' && idMatch) {
    const id = parseInt(idMatch[1]);
    const topic = await db.prepare(`
      SELECT t.*, c.id as chapter_id, c.name as chapter_name, s.id as subject_id, s.name as subject_name
      FROM topics t JOIN chapters c ON t.chapter_id = c.id JOIN subjects s ON c.subject_id = s.id WHERE t.id = ?
    `).bind(id).first();
    if (!topic) return err('Topic not found', 404);
    return json({
      id: topic.id, name: topic.name, chapter_id: topic.chapter_id,
      sort_order: topic.sort_order, created_at: topic.created_at,
      chapter: { id: topic.chapter_id, name: topic.chapter_name },
      subject: { id: topic.subject_id, name: topic.subject_name }
    });
  }

  // PUT /api/topics/:id
  if (method === 'PUT' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM topics WHERE id = ?').bind(id).first();
    if (!existing) return err('Topic not found', 404);
    const { name, chapter_id, sort_order } = body || {};
    await db.prepare(
      `UPDATE topics SET name = ?, chapter_id = ?, sort_order = ? WHERE id = ?`
    ).bind(
      name ?? existing.name, chapter_id ?? existing.chapter_id,
      sort_order ?? existing.sort_order, id
    ).run();
    const updated = await db.prepare('SELECT * FROM topics WHERE id = ?').bind(id).first();
    return json(updated);
  }

  // DELETE /api/topics/:id
  if (method === 'DELETE' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM topics WHERE id = ?').bind(id).first();
    if (!existing) return err('Topic not found', 404);
    const notes = await db.prepare('SELECT id FROM notes WHERE topic_id = ?').bind(id).all();
    await db.prepare('DELETE FROM notes WHERE topic_id = ?').bind(id).run();
    await db.prepare('DELETE FROM topics WHERE id = ?').bind(id).run();
    return json({ ok: true, deleted: { notes: notes.results.length } });
  }

  // GET /api/topics/:id/notes
  if (method === 'GET' && notesMatch) {
    const topicId = parseInt(notesMatch[1]);
    const notesList = await db.prepare(
      `SELECT * FROM notes WHERE topic_id = ? ORDER BY sort_order ASC, created_at DESC`
    ).bind(topicId).all();
    return json(notesList.results);
  }

  return err('Not found', 404);
}

// ==================== NOTE HANDLERS ====================

async function handleNotes(method, path, body, db, userId) {
  const idMatch = path.match(/^\/api\/notes\/(\d+)$/);
  const moveMatch = path.match(/^\/api\/notes\/(\d+)\/move$/);

  // POST /api/notes
  if (method === 'POST' && path === '/api/notes') {
    const { topic_id, title, type, content_html, url, image_url } = body || {};
    if (!topic_id || !title) return err('topic_id and title are required.');
    const now = Date.now();
    const result = await db.prepare(
      `INSERT INTO notes (topic_id, title, type, content_html, url, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(topic_id, title, type || 'text', content_html || '', url || '', image_url || '', now, now).run();
    const note = await db.prepare('SELECT * FROM notes WHERE id = ?').bind(result.meta.last_row_id).first();
    return json(note, 201);
  }

  // GET /api/notes/:id
  if (method === 'GET' && idMatch) {
    const id = parseInt(idMatch[1]);
    const note = await db.prepare(`
      SELECT n.*, t.id as topic_id, t.name as topic_name, c.id as chapter_id, c.name as chapter_name, s.id as subject_id, s.name as subject_name
      FROM notes n JOIN topics t ON n.topic_id = t.id JOIN chapters c ON t.chapter_id = c.id JOIN subjects s ON c.subject_id = s.id WHERE n.id = ?
    `).bind(id).first();
    if (!note) return err('Note not found', 404);
    return json({
      id: note.id, topic_id: note.topic_id, title: note.title, type: note.type,
      content_html: note.content_html, url: note.url, image_url: note.image_url,
      sort_order: note.sort_order, created_at: note.created_at, updated_at: note.updated_at,
      topic: { id: note.topic_id, name: note.topic_name },
      chapter: { id: note.chapter_id, name: note.chapter_name },
      subject: { id: note.subject_id, name: note.subject_name }
    });
  }

  // PUT /api/notes/:id
  if (method === 'PUT' && idMatch) {
    const id = parseInt(idMatch[1]);
    const existing = await db.prepare('SELECT * FROM notes WHERE id = ?').bind(id).first();
    if (!existing) return err('Note not found', 404);
    const { title, type, content_html, url, image_url, sort_order } = body || {};
    await db.prepare(
      `UPDATE notes SET title = ?, type = ?, content_html = ?, url = ?, image_url = ?, sort_order = ?, updated_at = ? WHERE id = ?`
    ).bind(
      title ?? existing.title, type ?? existing.type, content_html ?? existing.content_html,
      url ?? existing.url, image_url ?? existing.image_url,
      sort_order ?? existing.sort_order, Date.now(), id
    ).run();
    const updated = await db.prepare('SELECT * FROM notes WHERE id = ?').bind(id).first();
    return json(updated);
  }

  // DELETE /api/notes/:id
  if (method === 'DELETE' && idMatch) {
    const id = parseInt(idMatch[1]);
    await db.prepare('DELETE FROM notes WHERE id = ?').bind(id).run();
    return json({ ok: true });
  }

  // POST /api/notes/:id/move
  if (method === 'POST' && moveMatch) {
    const id = parseInt(moveMatch[1]);
    const { direction } = body || {};
    if (!direction || (direction !== 'up' && direction !== 'down')) return err('direction must be "up" or "down".');

    const note = await db.prepare('SELECT * FROM notes WHERE id = ?').bind(id).first();
    if (!note) return err('Note not found', 404);

    const neighborSort = direction === 'up' ? note.sort_order - 1 : note.sort_order + 1;
    const neighbor = await db.prepare(
      'SELECT * FROM notes WHERE topic_id = ? AND sort_order = ? LIMIT 1'
    ).bind(note.topic_id, neighborSort).first();

    if (!neighbor) return err('Cannot move further in that direction.', 400);

    await db.prepare('UPDATE notes SET sort_order = ? WHERE id = ?').bind(neighbor.sort_order, note.id).run();
    await db.prepare('UPDATE notes SET sort_order = ? WHERE id = ?').bind(note.sort_order, neighbor.id).run();
    return json({ ok: true });
  }

  return err('Not found', 404);
}

// ==================== SEARCH ====================

async function handleSearch(method, path, queryParams, db) {
  if (method !== 'GET' || path !== '/api/search') return err('Not found', 404);

  const q = queryParams.get('q');
  if (!q || q.trim().length < 2) return err('Query must be at least 2 characters.');

  const term = `%${q.trim()}%`;

  const subjects = await db.prepare(
    `SELECT id, name FROM subjects WHERE LOWER(name) LIKE LOWER(?) LIMIT 10`
  ).bind(term).all();

  const chapters = await db.prepare(
    `SELECT c.id, c.name, s.id as subject_id, s.name as subject_name FROM chapters c JOIN subjects s ON c.subject_id = s.id WHERE LOWER(c.name) LIKE LOWER(?) LIMIT 10`
  ).bind(term).all();

  const topics = await db.prepare(
    `SELECT t.id, t.name, c.id as chapter_id, c.name as chapter_name, s.id as subject_id, s.name as subject_name FROM topics t JOIN chapters c ON t.chapter_id = c.id JOIN subjects s ON c.subject_id = s.id WHERE LOWER(t.name) LIKE LOWER(?) LIMIT 10`
  ).bind(term).all();

  const notesRaw = await db.prepare(
    `SELECT n.id, n.title, n.content_html, t.id as topic_id, t.name as topic_name, c.id as chapter_id, c.name as chapter_name, s.id as subject_id, s.name as subject_name FROM notes n JOIN topics t ON n.topic_id = t.id JOIN chapters c ON t.chapter_id = c.id JOIN subjects s ON c.subject_id = s.id WHERE LOWER(n.title) LIKE LOWER(?) OR LOWER(n.content_html) LIKE LOWER(?) LIMIT 20`
  ).bind(term, term).all();

  const notes = notesRaw.results.map(n => {
    let snippet = '';
    const stripped = (n.content_html || '').replace(/<[^>]+>/g, '');
    const idx = stripped.toLowerCase().indexOf(q.trim().toLowerCase());
    if (idx >= 0) {
      const start = Math.max(0, idx - 60);
      snippet = (start > 0 ? '...' : '') + stripped.substring(start, idx + q.trim().length + 60) + (idx + q.trim().length + 60 < stripped.length ? '...' : '');
    } else {
      snippet = stripped.substring(0, 120) + (stripped.length > 120 ? '...' : '');
    }
    return {
      id: n.id, title: n.title, snippet,
      topic: { id: n.topic_id, name: n.topic_name },
      chapter: { id: n.chapter_id, name: n.chapter_name },
      subject: { id: n.subject_id, name: n.subject_name }
    };
  });

  return json({
    subjects: subjects.results.map(s => ({ id: s.id, name: s.name })),
    chapters: chapters.results.map(c => ({ id: c.id, name: c.name, subject: { id: c.subject_id, name: c.subject_name } })),
    topics: topics.results.map(t => ({ id: t.id, name: t.name, chapter: { id: t.chapter_id, name: t.chapter_name }, subject: { id: t.subject_id, name: t.subject_name } })),
    notes
  });
}

// ==================== SETTINGS / UPLOADS ====================

async function handleSettings(method, path, body, db, userId) {
  // GET /api/settings/imgbb
  if (method === 'GET' && path === '/api/settings/imgbb') {
    const row = await db.prepare("SELECT value FROM settings WHERE key = 'imgbb_api_key'").first();
    return json({ set: !!row });
  }

  // POST /api/settings/imgbb
  if (method === 'POST' && path === '/api/settings/imgbb') {
    const { apiKey } = body || {};
    if (!apiKey) return err('apiKey is required.');
    await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('imgbb_api_key', ?)").bind(apiKey).run();
    return json({ ok: true });
  }

  // POST /api/upload/image
  if (method === 'POST' && path === '/api/upload/image') {
    const { imageBase64 } = body || {};
    if (!imageBase64) return err('imageBase64 is required.');

    const apiKeyRow = await db.prepare("SELECT value FROM settings WHERE key = 'imgbb_api_key'").first();
    if (!apiKeyRow) return err('ImgBB API key not configured. Set it in Settings.', 400);

    try {
      const formData = new URLSearchParams();
      formData.append('key', apiKeyRow.value);
      formData.append('image', imageBase64.replace(/^data:image\/\w+;base64,/, ''));

      const imgbbRes = await fetch('https://api.imgbb.com/1/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
      });
      const imgbbData = await imgbbRes.json();
      if (!imgbbData.success) return err('Image upload failed: ' + (imgbbData.error?.message || 'Unknown error'), 500);
      return json({ url: imgbbData.data.display_url });
    } catch (e) {
      return err('Image upload failed. Check your ImgBB API key.', 500);
    }
  }

  return err('Not found', 404);
}

// ==================== MAIN ROUTER ====================

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.KEEP_DB;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  // Handle CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // Ensure tables on first request
  if (!globalThis.__tablesReady) {
    await ensureTables(db);
    globalThis.__tablesReady = true;
  }

  // Parse body for POST/PUT
  let body = null;
  if (method === 'POST' || method === 'PUT') {
    try { body = await request.json(); } catch { body = {}; }
  }

  // Route: /api/auth/*
  if (path.startsWith('/api/auth/')) {
    const authPath = path.replace('/api/auth', '') || '/';
    if (method === 'POST' && (authPath === '/login' || authPath === '/change-password' || authPath === '/change-masterkey')) {
      if (authPath === '/change-password' || authPath === '/change-masterkey') {
        const user = await getUser(request);
        if (!user) return err('Unauthorized', 401);
        if (body) body._userId = user.id;
      }
    }
    const result = await handleAuth(method, '/api/auth' + authPath, body, db);
    return result;
  }

  // All other routes require auth
  const user = await getUser(request);
  if (!user) return err('Unauthorized', 401);

  // Route: /api/subjects/*
  if (path.startsWith('/api/subjects')) {
    return await handleSubjects(method, path, body, db, user.id);
  }

  // Route: /api/chapters/*
  if (path.startsWith('/api/chapters')) {
    return await handleChapters(method, path, body, db, user.id);
  }

  // Route: /api/topics/*
  if (path.startsWith('/api/topics')) {
    return await handleTopics(method, path, body, db, user.id);
  }

  // Route: /api/notes/*
  if (path.startsWith('/api/notes')) {
    return await handleNotes(method, path, body, db, user.id);
  }

  // Route: /api/search
  if (path === '/api/search') {
    return await handleSearch(method, path, url.searchParams, db);
  }

  // Route: /api/settings/* and /api/upload/*
  if (path.startsWith('/api/settings') || path.startsWith('/api/upload')) {
    return await handleSettings(method, path, body, db, user.id);
  }

  return err('Not found', 404);
}
