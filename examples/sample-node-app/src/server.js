const crypto = require('node:crypto');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');

const app = express();
app.use(express.json());

const users = new Map();

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const id = uuid();
  const passwordHash = await bcrypt.hash(password, 12);
  users.set(email, { id, passwordHash });
  res.status(201).json({ id });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
  res.json({ token });
});

app.get('/session-id', (_req, res) => {
  res.json({ sessionId: crypto.randomBytes(32).toString('hex') });
});

module.exports = app;
