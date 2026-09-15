const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// 1. PostgreSQL Connection Pool setup using Supabase DATABASE_URL environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test connection on startup
pool.connect()
  .then(() => console.log('Connected to Supabase PostgreSQL successfully!'))
  .catch(err => console.error('PostgreSQL connection error:', err));

// 2. Automatically ensure database tables exist when the server starts
const initializeDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS brothers (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT,
          status TEXT DEFAULT 'active',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS schedules (
          id SERIAL PRIMARY KEY,
          brother_id INTEGER REFERENCES brothers(id) ON DELETE CASCADE,
          role TEXT NOT NULL,
          assignment_date DATE NOT NULL
      );
    `);
    console.log('Database tables verified/created successfully.');
  } catch (err) {
    console.error('Error initializing database tables:', err);
  }
};

initializeDatabase();

// ==========================================
// EXAMPLE API ROUTES (PostgreSQL / Async-Await)
// ==========================================

// Get all active brothers
app.get('/api/brothers', async (req, res) => {
  try {
    // PostgreSQL uses $1 instead of ? for parameters
    const result = await pool.query(
      'SELECT * FROM brothers WHERE status = $1 ORDER BY name ASC', 
      ['active']
    );
    // In pg, the actual rows are inside result.rows
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add a new brother
app.post('/api/brothers', async (req, res) => {
  const { name, email } = req.body;
  try {
    // RETURNING * sends back the newly inserted row (including its auto-generated serial ID)
    const result = await pool.query(
      'INSERT INTO brothers (name, email) VALUES ($1, $2) RETURNING *',
      [name, email]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add brother' });
  }
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});