'use strict';

const { db }          = require('../db');
const { requireAuth } = require('../middleware/auth');
const { parseBody }   = require('../middleware/security');
const { ok, notFound, badRequest } = require('../middleware/response');

// GET /api/labs/:slug/notes
function getNotes(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT id FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');
  const row = db.prepare(
    `SELECT content, updated_at FROM lab_notes WHERE user_id=? AND lab_id=?`
  ).get(user.id, lab.id);
  return ok(res, { content: row?.content || '', updated_at: row?.updated_at || null });
}

// PUT /api/labs/:slug/notes
async function saveNotes(req, res, slug) {
  const user = requireAuth(req, res); if (!user) return;
  const lab  = db.prepare(`SELECT id FROM labs WHERE slug=?`).get(slug);
  if (!lab) return notFound(res, 'Lab not found');
  const { content } = await parseBody(req);
  if (typeof content !== 'string') return badRequest(res, 'content must be a string');
  // Max 10,000 chars per note
  if (content.length > 10_000) return badRequest(res, 'Notes must be under 10,000 characters');
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO lab_notes (user_id, lab_id, content, updated_at)
     VALUES (?,?,?,?)
     ON CONFLICT(user_id, lab_id) DO UPDATE SET
       content=excluded.content, updated_at=excluded.updated_at`
  ).run(user.id, lab.id, content.trim(), now);
  return ok(res, { saved: true, updated_at: now });
}

module.exports = { getNotes, saveNotes };
