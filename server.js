const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Supabase Client Setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

console.log('✅ Supabase Client initialized');

// Middleware untuk autentikasi JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token tidak valid' });
    }
    req.user = user;
    next();
  });
}

// Middleware untuk API Key
function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'API Key tidak valid' });
  }
  
  next();
}

// ===== ROUTES =====

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'SMS Gateway Server Running (Supabase)',
    timestamp: Date.now() 
  });
});

// Login Admin
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password wajib diisi' });
  }

  try {
    const { data, error } = await supabase
      .from('admin')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !data) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const isValidPassword = bcrypt.compareSync(password, data.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }

    const token = jwt.sign(
      { id: data.id, username: data.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      token,
      username: data.username 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Endpoint untuk menerima SMS dari Android
app.post('/api/sms-masuk', authenticateApiKey, async (req, res) => {
  const { pengirim, isi_pesan, waktu, device_id } = req.body;

  if (!pengirim || !isi_pesan) {
    return res.status(400).json({ error: 'Data tidak lengkap' });
  }

  const timestamp = waktu || Date.now();

  try {
    const { data, error } = await supabase
      .from('sms_inbox')
      .insert([
        {
          pengirim,
          isi_pesan,
          waktu: timestamp,
          device_id: device_id || 'unknown'
        }
      ])
      .select()
      .single();

    if (error) {
      console.error('❌ Error menyimpan SMS:', error);
      return res.status(500).json({ error: 'Gagal menyimpan SMS' });
    }

    console.log('📩 SMS BARU:', data);

    // Broadcast ke semua WebSocket client
    broadcastToClients(data);

    res.json({ 
      success: true, 
      message: 'SMS berhasil disimpan',
      id: data.id 
    });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get All SMS (dengan pagination)
app.get('/api/sms', authenticateToken, async (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const offset = parseInt(req.query.offset) || 0;

  try {
    const { data, error } = await supabase
      .from('sms_inbox')
      .select('*')
      .order('id', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      console.error('Error fetching SMS:', error);
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ success: true, data: data || [] });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get SMS Count
app.get('/api/sms/count', authenticateToken, async (req, res) => {
  try {
    const { count, error } = await supabase
      .from('sms_inbox')
      .select('*', { count: 'exact', head: true });

    if (error) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ success: true, total: count || 0 });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete SMS
app.delete('/api/sms/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const { error } = await supabase
      .from('sms_inbox')
      .delete()
      .eq('id', id);

    if (error) {
      return res.status(500).json({ error: 'Database error' });
    }

    res.json({ success: true, message: 'SMS berhasil dihapus' });
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== WebSocket =====
wss.on('connection', (ws) => {
  console.log('🔌 Client WebSocket terhubung');

  ws.on('message', (message) => {
    console.log('Pesan dari client:', message.toString());
  });

  ws.on('close', () => {
    console.log('❌ Client WebSocket terputus');
  });

  ws.send(JSON.stringify({ 
    type: 'connected', 
    message: 'Terhubung ke SMS Gateway WebSocket' 
  }));
});

// Broadcast ke semua WebSocket client
function broadcastToClients(data) {
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({
        type: 'new_sms',
        data: data
      }));
    }
  });
}

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════╗
║   🚀 SMS GATEWAY SERVER RUNNING      ║
║   📡 Port: ${PORT}                        ║
║   🌐 WebSocket: ws://localhost:${PORT}   ║
║   💾 Database: Supabase               ║
╚═══════════════════════════════════════╝
  `);
});