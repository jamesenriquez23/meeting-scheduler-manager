require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { sendNewUserNotification } = require('./utils/mailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key-change-in-production';

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup (SQLite)
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) console.error('Error connecting to SQLite:', err.message);
  else console.log('Connected to SQLite database.');
});

// Initialize Database Tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    reset_token TEXT,
    reset_expires INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS brothers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    can_wt_reader INTEGER DEFAULT 0,
    can_chairman INTEGER DEFAULT 0,
    can_attendants INTEGER DEFAULT 0,
    can_microvers INTEGER DEFAULT 0,
    can_av INTEGER DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS away_dates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    brother_id INTEGER NOT NULL,
    away_date TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(brother_id) REFERENCES brothers(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS special_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_date TEXT NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    schedule_date TEXT NOT NULL,
    wt_reader TEXT,
    chairman TEXT,
    attendants TEXT,
    microvers TEXT,
    av TEXT,
    month INTEGER NOT NULL,
    year INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token missing or invalid' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Token expired or invalid' });
    req.user = user;
    next();
  });
};

// ==========================================
// AUTHENTICATION & USER ENDPOINTS
// ==========================================

// REGISTER
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`,
      [username, email, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username or email already exists.' });
          }
          return res.status(500).json({ error: 'Failed to create user account.' });
        }

        const newUser = { id: this.lastID, username, email };
        const token = jwt.sign(newUser, JWT_SECRET, { expiresIn: '7d' });

        sendNewUserNotification(newUser).catch((mailErr) => {
          console.error('Failed to send registration alert email:', mailErr.message);
        });

        return res.status(201).json({
          message: 'Account registered successfully!',
          token,
          user: newUser
        });
      }
    );
  } catch (err) {
    return res.status(500).json({ error: 'Server error during registration.' });
  }
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ? OR email = ?`,
    [username, username],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ error: 'Invalid username or password.' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(400).json({ error: 'Invalid username or password.' });
      }

      const userData = { id: user.id, username: user.username, email: user.email };
      const token = jwt.sign(userData, JWT_SECRET, { expiresIn: '7d' });

      return res.json({ token, user: userData });
    }
  );
});

// GET CURRENT USER (/api/me)
app.get('/api/me', authenticateToken, (req, res) => {
  db.get(`SELECT id, username, email FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    return res.json({ user });
  });
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  return res.json({ message: 'Logged out successfully' });
});

// FORGOT PASSWORD
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 3600000; // 1 hour

  db.run(
    `UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?`,
    [resetToken, expires, email],
    function (err) {
      if (err || this.changes === 0) {
        return res.status(404).json({ error: 'No account found with that email address.' });
      }
      return res.json({
        message: 'Reset token generated.',
        simulatedResetToken: resetToken
      });
    }
  );
});

// RESET PASSWORD
app.post('/api/auth/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;

  db.get(
    `SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_expires > ?`,
    [email, token, Date.now()],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ error: 'Invalid or expired reset token.' });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      db.run(
        `UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?`,
        [hashedPassword, user.id],
        (updateErr) => {
          if (updateErr) return res.status(500).json({ error: 'Failed to reset password.' });
          return res.json({ message: 'Password updated successfully.' });
        }
      );
    }
  );
});

// UPDATE PROFILE EMAIL
app.put('/api/user/profile', authenticateToken, (req, res) => {
  const { email } = req.body;
  db.run(`UPDATE users SET email = ? WHERE id = ?`, [email, req.user.id], function (err) {
    if (err) return res.status(400).json({ error: 'Email already in use or invalid.' });
    return res.json({ email });
  });
});

// CHANGE PASSWORD
app.put('/api/user/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User not found.' });

    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ error: 'Current password is incorrect.' });

    const newHashed = await bcrypt.hash(newPassword, 10);
    db.run(`UPDATE users SET password = ? WHERE id = ?`, [newHashed, req.user.id], (upErr) => {
      if (upErr) return res.status(500).json({ error: 'Failed to update password.' });
      return res.json({ message: 'Password changed successfully.' });
    });
  });
});

// ==========================================
// ADMIN ENDPOINTS
// ==========================================

app.get('/api/admin/users', authenticateToken, (req, res) => {
  db.get(`SELECT username FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err || !row || row.username.toLowerCase() !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }

    db.all(`SELECT id, username, email FROM users`, [], (dbErr, users) => {
      if (dbErr) return res.status(500).json({ error: dbErr.message });
      return res.json({ users });
    });
  });
});

app.delete('/api/users/:id', authenticateToken, (req, res) => {
  db.get(`SELECT username FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err || !row || row.username.toLowerCase() !== 'admin') {
      return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }

    const userIdToDelete = req.params.id;
    db.run(`DELETE FROM users WHERE id = ?`, [userIdToDelete], function (dbErr) {
      if (dbErr) return res.status(500).json({ error: dbErr.message });
      if (this.changes === 0) return res.status(404).json({ error: 'User not found.' });
      return res.json({ message: `User deleted successfully.` });
    });
  });
});

// ==========================================
// ROSTER / BROTHERS ENDPOINTS
// ==========================================

app.get('/api/brothers', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM brothers WHERE user_id = ?`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json(rows);
  });
});

app.post('/api/brothers', authenticateToken, (req, res) => {
  const { name, can_wt_reader, can_chairman, can_attendants, can_microvers, can_av } = req.body;
  db.run(
    `INSERT INTO brothers (user_id, name, can_wt_reader, can_chairman, can_attendants, can_microvers, can_av) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      req.user.id,
      name,
      can_wt_reader ? 1 : 0,
      can_chairman ? 1 : 0,
      can_attendants ? 1 : 0,
      can_microvers ? 1 : 0,
      can_av ? 1 : 0
    ],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ id: this.lastID, name });
    }
  );
});

app.put('/api/brothers/:id', authenticateToken, (req, res) => {
  const { can_wt_reader, can_chairman, can_attendants, can_microvers, can_av } = req.body;
  db.run(
    `UPDATE brothers SET can_wt_reader = ?, can_chairman = ?, can_attendants = ?, can_microvers = ?, can_av = ? WHERE id = ? AND user_id = ?`,
    [
      can_wt_reader ? 1 : 0,
      can_chairman ? 1 : 0,
      can_attendants ? 1 : 0,
      can_microvers ? 1 : 0,
      can_av ? 1 : 0,
      req.params.id,
      req.user.id
    ],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ success: true });
    }
  );
});

app.delete('/api/brothers/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM brothers WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true });
  });
});

// ==========================================
// AWAY DATES & EVENTS
// ==========================================

app.get('/api/away', authenticateToken, (req, res) => {
  db.all(
    `SELECT away_dates.id, away_dates.away_date, brothers.name AS brother_name 
     FROM away_dates JOIN brothers ON away_dates.brother_id = brothers.id 
     WHERE away_dates.user_id = ?`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows);
    }
  );
});

app.post('/api/away', authenticateToken, (req, res) => {
  const { brother_id, away_date } = req.body;
  db.run(
    `INSERT INTO away_dates (user_id, brother_id, away_date) VALUES (?, ?, ?)`,
    [req.user.id, brother_id, away_date],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ id: this.lastID });
    }
  );
});

app.delete('/api/away/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM away_dates WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true });
  });
});

app.get('/api/events', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM special_events WHERE user_id = ?`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json(rows);
  });
});

app.post('/api/events', authenticateToken, (req, res) => {
  const { event_date, description } = req.body;
  db.run(
    `INSERT INTO special_events (user_id, event_date, description) VALUES (?, ?, ?)`,
    [req.user.id, event_date, description],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ id: this.lastID });
    }
  );
});

app.delete('/api/events/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM special_events WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true });
  });
});

// ==========================================
// SCHEDULE GENERATOR ENDPOINTS
// ==========================================

app.get('/api/schedule', authenticateToken, (req, res) => {
  db.all(
    `SELECT * FROM schedules WHERE user_id = ? ORDER BY id ASC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json(rows || []);
    }
  );
});

app.post('/api/schedule/generate', authenticateToken, (req, res) => {
  const { month, year } = req.body;

  db.all(`SELECT * FROM brothers WHERE user_id = ?`, [req.user.id], (err, brothers) => {
    if (err || !brothers || brothers.length === 0) {
      return res.status(400).json({ error: 'No brothers available in roster to generate schedule.' });
    }

    db.all(`SELECT * FROM away_dates WHERE user_id = ?`, [req.user.id], (errAway, awayRows) => {
      db.all(`SELECT * FROM special_events WHERE user_id = ?`, [req.user.id], (errEvents, eventRows) => {
        let prevMonth = Number(month) - 1;
        let prevYear = Number(year);
        if (prevMonth === 0) {
          prevMonth = 12;
          prevYear = prevYear - 1;
        }

        db.all(
          `SELECT * FROM schedules WHERE user_id = ? AND month = ? AND year = ?`,
          [req.user.id, prevMonth, prevYear],
          (errPrev, prevRows) => {
            let prevMonthAssignments = { wt_reader: new Set(), chairman: new Set(), attendants: new Set(), microvers: new Set(), av: new Set() };
            
            if (prevRows && Array.isArray(prevRows)) {
              prevRows.forEach(row => {
                if (row && row.wt_reader) String(row.wt_reader || '').split(',').forEach(s => { if(s.trim()) prevMonthAssignments.wt_reader.add(s.trim()); });
                if (row && row.chairman) String(row.chairman || '').split(',').forEach(s => { if(s.trim()) prevMonthAssignments.chairman.add(s.trim()); });
                if (row && row.attendants) String(row.attendants || '').split(',').forEach(s => { if(s.trim()) prevMonthAssignments.attendants.add(s.trim()); });
                if (row && row.microvers) String(row.microvers || '').split(',').forEach(s => { if(s.trim()) prevMonthAssignments.microvers.add(s.trim()); });
                if (row && row.av) String(row.av || '').split(',').forEach(s => { if(s.trim()) prevMonthAssignments.av.add(s.trim()); });
              });
            }

            // Automatically find all Sundays in the given month/year
            const dates = [];
            let dateObj = new Date(year, month - 1, 1);
            
            while (dateObj.getDay() !== 0) {
              dateObj.setDate(dateObj.getDate() + 1);
            }
            
            while (dateObj.getMonth() === month - 1) {
              const day = String(dateObj.getDate()).padStart(2, '0');
              const mn = String(dateObj.getMonth() + 1).padStart(2, '0');
              const yr = dateObj.getFullYear();
              dates.push(`${day}.${mn}.${yr}`);
              
              dateObj.setDate(dateObj.getDate() + 7);
            }
            
            db.run(`DELETE FROM schedules WHERE user_id = ? AND month = ? AND year = ?`, [req.user.id, month, year], () => {
              const stmt = db.prepare(`INSERT INTO schedules (user_id, schedule_date, wt_reader, chairman, attendants, microvers, av, month, year) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);

              const monthlyCounts = {
                wt_reader: {},
                chairman: {},
                attendants: {},
                microvers: {},
                av: {}
              };

              // Helper function to normalize YYYY-MM-DD into DD.MM.YYYY for format matching
              const normalizeDate = (dbDate) => {
                if (!dbDate) return '';
                const cleaned = String(dbDate).trim();
                if (cleaned.includes('-')) {
                  const parts = cleaned.split('-');
                  if (parts.length === 3) {
                    return `${parts[2]}.${parts[1]}.${parts[0]}`;
                  }
                }
                return cleaned;
              };

              dates.forEach((dateStr) => {
                const targetDateFormatted = String(dateStr).trim();

                // 1. Calculate Saturday before this Sunday to check full weekend for events
                const [day, monthNum, yearNum] = targetDateFormatted.split('.').map(Number);
                const sundayDate = new Date(yearNum, monthNum - 1, day);
                const saturdayDate = new Date(sundayDate);
                saturdayDate.setDate(saturdayDate.getDate() - 1);

                const satDay = String(saturdayDate.getDate()).padStart(2, '0');
                const satMon = String(saturdayDate.getMonth() + 1).padStart(2, '0');
                const satYr = saturdayDate.getFullYear();
                const saturdayFormatted = `${satDay}.${satMon}.${satYr}`;

                // 2. Check if a Special Event falls on Saturday or Sunday
                const matchingEvent = (eventRows || []).find(e => {
                  const normalizedEventDate = normalizeDate(e.event_date);
                  return normalizedEventDate === targetDateFormatted || normalizedEventDate === saturdayFormatted;
                });

                if (matchingEvent) {
                  // Skip brother assignments for this week and write the event description instead
                  stmt.run(
                    req.user.id, 
                    targetDateFormatted, 
                    `EVENT: ${matchingEvent.description || 'Special Event'}`, 
                    '-', 
                    '-', 
                    '-', 
                    '-', 
                    month, 
                    year
                  );
                  return; // Skip to next week iteration
                }

                // 3. Away date filtering with normalization match
                const awayBrotherIds = (awayRows || [])
                  .filter(a => {
                    if (!a || !a.away_date) return false;
                    return normalizeDate(a.away_date) === targetDateFormatted;
                  })
                  .map(a => a.brother_id);

                const available = brothers.filter(b => b && !awayBrotherIds.includes(b.id));
                const assignedToday = new Set();

                const pickBrothers = (roleKey, count, enforceMonthlyLimit = false, enforceRestPeriod = true) => {
                  let eligible = available.filter(b => {
                    if (!b || b[roleKey] !== 1) return false;
                    if (assignedToday.has(b.id)) return false;

                    if (enforceMonthlyLimit) {
                      const currentCount = monthlyCounts[roleKey]?.[b.id] || 0;
                      if (currentCount >= 1) return false;
                    }

                    if (enforceRestPeriod) {
                      if (prevMonthAssignments[roleKey] && prevMonthAssignments[roleKey].has(b.name)) {
                        return false;
                      }
                    }

                    return true;
                  });

                  if (eligible.length < count) {
                    eligible = available.filter(b => b && b[roleKey] === 1 && !assignedToday.has(b.id));
                  }

                  const chosenNames = [];
                  for (let i = 0; i < count; i++) {
                    if (eligible.length === 0) break;
                    const randomIndex = Math.floor(Math.random() * eligible.length);
                    const chosen = eligible.splice(randomIndex, 1)[0];
                    
                    assignedToday.add(chosen.id);

                    if (enforceMonthlyLimit && monthlyCounts[roleKey]) {
                      monthlyCounts[roleKey][chosen.id] = (monthlyCounts[roleKey][chosen.id] || 0) + 1;
                    }

                    chosenNames.push(chosen.name);
                  }

                  return chosenNames.length > 0 ? chosenNames.join(', ') : 'N/A';
                };

                const reader = pickBrothers('can_wt_reader', 1, true, true);
                const chairman = pickBrothers('can_chairman', 1, true, true);
                const attendants = pickBrothers('can_attendants', 2, false, true);
                const microvers = pickBrothers('can_microvers', 2, false, true);
                const av = pickBrothers('can_av', 2, false, true);

                stmt.run(req.user.id, targetDateFormatted, reader, chairman, attendants, microvers, av, month, year);
              });

              stmt.finalize(() => {
                db.all(`SELECT * FROM schedules WHERE user_id = ? AND month = ? AND year = ?`, [req.user.id, month, year], (fetchErr, rows) => {
                  return res.json({ message: 'Schedule generated successfully', schedule: rows || [] });
                });
              });
            });
          }
        );
      });
    });
  });
});

app.put('/api/schedule/:id', authenticateToken, (req, res) => {
  const { wt_reader, chairman, attendants, microvers, av } = req.body;
  db.run(
    `UPDATE schedules SET wt_reader = ?, chairman = ?, attendants = ?, microvers = ?, av = ? WHERE id = ? AND user_id = ?`,
    [wt_reader, chairman, attendants, microvers, av, req.params.id, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      return res.json({ success: true });
    }
  );
});

app.delete('/api/schedule/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM schedules WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true });
  });
});

app.delete('/api/schedule/reset/all', authenticateToken, (req, res) => {
  db.run(`DELETE FROM schedules WHERE user_id = ?`, [req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ success: true });
  });
});

// Fallback to React App
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});