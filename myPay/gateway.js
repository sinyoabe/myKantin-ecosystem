const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database('mypay_gateway.db');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// PIN Rahasia Operator / Bendahara untuk mengesahkan mutasi QRIS masuk
const GATEWAY_OPERATOR_PIN = process.env.GATEWAY_OPERATOR_PIN || '889900';
const failedPinAttempts = new Map();

db.exec(`
  CREATE TABLE IF NOT EXISTS merchants (
    merchant_id TEXT PRIMARY KEY,
    merchant_name TEXT NOT NULL,
    server_key TEXT NOT NULL,
    client_key TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    static_qris_payload TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS gateway_transactions (
    tx_id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    merchant_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    student_name TEXT NOT NULL,
    amount INTEGER NOT NULL,
    qris_payload TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    paid_via TEXT DEFAULT '',
    verified_by TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    settled_at DATETIME
  );
`);

try { db.exec("ALTER TABLE gateway_transactions ADD COLUMN verified_by TEXT DEFAULT ''"); } catch (e) {}

const mCount = db.prepare('SELECT COUNT(*) as c FROM merchants').get().c;
if (mCount === 0) {
  db.prepare(`
    INSERT INTO merchants (merchant_id, merchant_name, server_key, client_key, webhook_url, static_qris_payload)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    'MCH-KANTIN-01',
    'myKantin School Ecosystem',
    'MYPAY-SRV-9988776655',
    'MYPAY-CLI-1122334455',
    'http://localhost:3000/api/qris/webhook',
    ''
  );
}

// --- ENGINE KONVERTER QRIS STANDAR EMVCo (TLV + CRC16-CCITT) ---
function crc16(str) {
  let crc = 0xFFFF;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    }
  }
  return (crc & 0xFFFF).toString(16).toUpperCase().padStart(4, '0');
}

function buildDynamicQrisEMVCo(staticQris, amount, txId) {
  const amtStr = String(amount);
  const tag54 = `54${String(amtStr.length).padStart(2, '0')}${amtStr}`;

  if (staticQris && staticQris.includes('5802ID') && staticQris.length > 20) {
    let raw = staticQris.trim().slice(0, -4);
    raw = raw.replace('010211', '010212');
    raw = raw.replace(/54\d{2}\d+/, '');
    const parts = raw.split('5802ID');
    const payloadNoCrc = `${parts[0]}${tag54}5802ID${parts[1]}`;
    return payloadNoCrc + crc16(payloadNoCrc);
  }

  const merchantInfo = `0014ID.CO.MYPAY.WWW01159360091400000010208${txId.slice(-8)}`;
  const tag26 = `26${String(merchantInfo.length).padStart(2, '0')}${merchantInfo}`;
  const payloadNoCrc = `000201010212${tag26}520458125303360${tag54}5802ID5914MYKANTIN POS6008SEMARANG6304`;
  return payloadNoCrc + crc16(payloadNoCrc);
}

// --- API GATEWAY ---
app.get('/api/gateway/overview', (req, res) => {
  const merchant = db.prepare('SELECT merchant_id, merchant_name, client_key, webhook_url, static_qris_payload FROM merchants WHERE merchant_id = ?').get('MCH-KANTIN-01');
  const transactions = db.prepare('SELECT * FROM gateway_transactions ORDER BY created_at DESC LIMIT 50').all();
  res.json({ merchant, transactions });
});

app.post('/api/gateway/merchant/config', (req, res) => {
  const { webhookUrl, staticQrisPayload, operatorPin } = req.body;
  if (operatorPin !== GATEWAY_OPERATOR_PIN) {
    return res.status(403).json({ error: 'PIN Operator Gateway salah! Perubahan ditolak.' });
  }
  db.prepare('UPDATE merchants SET webhook_url = ?, static_qris_payload = ? WHERE merchant_id = ?').run(
    webhookUrl.trim(),
    (staticQrisPayload || '').trim(),
    'MCH-KANTIN-01'
  );
  res.json({ message: 'Konfigurasi Merchant & QRIS Engine berhasil diperbarui!' });
});

app.post('/v1/qris/charge', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const serverKey = authHeader.replace('Bearer ', '').trim();
  const merchant = db.prepare('SELECT * FROM merchants WHERE server_key = ?').get(serverKey);

  if (!merchant) {
    return res.status(401).json({ error: 'Unauthorized: Server Key tidak valid!' });
  }

  const { order_id, gross_amount, student_id, student_name } = req.body;
  const amount = parseInt(gross_amount);
  if (!order_id || !amount || amount < 1000 || amount > 500000) {
    return res.status(400).json({ error: 'Nominal transaksi harus antara Rp 1.000 - Rp 500.000' });
  }

  const txId = `MYPAY-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`;
  const qrisPayload = buildDynamicQrisEMVCo(merchant.static_qris_payload, amount, txId);

  db.prepare(`
    INSERT INTO gateway_transactions (tx_id, order_id, merchant_id, student_id, student_name, amount, qris_payload, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')
  `).run(txId, order_id, merchant.merchant_id, student_id, student_name || student_id, amount, qrisPayload);

  res.json({
    tx_id: txId,
    order_id,
    gross_amount: amount,
    status: 'PENDING',
    qris_string: qrisPayload,
    is_custom_static_qris: Boolean(merchant.static_qris_payload)
  });
});

app.get('/v1/qris/status/:txId', (req, res) => {
  const tx = db.prepare('SELECT tx_id, order_id, student_id, student_name, amount, qris_payload, status, paid_via, created_at, settled_at FROM gateway_transactions WHERE tx_id = ?').get(req.params.txId);
  if (!tx) return res.status(404).json({ error: 'Transaksi tidak ditemukan' });
  res.json(tx);
});

// Settlement Terkunci: Wajib PIN Operator / Bendahara Gateway
app.post('/v1/qris/settle/:txId', async (req, res) => {
  const txId = req.params.txId;
  const { paidVia, operatorPin } = req.body;

  const attempts = failedPinAttempts.get(txId) || 0;
  if (attempts >= 5) {
    return res.status(429).json({ error: 'Transaksi dikunci karena terlalu banyak percobaan PIN salah!' });
  }

  if (operatorPin !== GATEWAY_OPERATOR_PIN) {
    failedPinAttempts.set(txId, attempts + 1);
    return res.status(403).json({
      error: `PIN Otorisasi Bendahara SALAH! Percobaan gagal: ${attempts + 1}/5.`
    });
  }

  failedPinAttempts.delete(txId);
  const tx = db.prepare('SELECT * FROM gateway_transactions WHERE tx_id = ?').get(txId);
  if (!tx) return res.status(404).json({ error: 'Transaksi tidak ditemukan' });
  if (tx.status === 'SETTLEMENT') return res.json({ message: 'Transaksi sudah lunas sebelumnya', tx });

  const merchant = db.prepare('SELECT * FROM merchants WHERE merchant_id = ?').get(tx.merchant_id);

  db.prepare(`
    UPDATE gateway_transactions 
    SET status = 'SETTLEMENT', paid_via = ?, verified_by = 'OPERATOR_BENDAHARA', settled_at = CURRENT_TIMESTAMP 
    WHERE tx_id = ?
  `).run(paidVia || 'QRIS Terverifikasi', tx.tx_id);

  const updatedTx = db.prepare('SELECT * FROM gateway_transactions WHERE tx_id = ?').get(tx.tx_id);

  const rawSignature = `${updatedTx.order_id}${updatedTx.status}${updatedTx.amount}${merchant.server_key}`;
  const signatureKey = crypto.createHash('sha512').update(rawSignature).digest('hex');

  const webhookPayload = {
    tx_id: updatedTx.tx_id,
    order_id: updatedTx.order_id,
    student_id: updatedTx.student_id,
    gross_amount: updatedTx.amount,
    transaction_status: 'SETTLEMENT',
    paid_via: updatedTx.paid_via,
    verified_by: updatedTx.verified_by,
    signature_key: signatureKey
  };

  let webhookDelivered = false;
  let webhookError = '';
  try {
    const hookRes = await fetch(merchant.webhook_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-mypay-signature': signatureKey
      },
      body: JSON.stringify(webhookPayload)
    });
    webhookDelivered = hookRes.ok;
    if (!hookRes.ok) webhookError = `HTTP ${hookRes.status}`;
  } catch (err) {
    webhookError = err.message;
  }

  res.json({
    message: 'Mutasi QRIS disahkan & Webhook terkirim ke myKantin!',
    webhookDelivered,
    webhookError,
    tx: updatedTx
  });
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`🛡️ myPay Secure Payment Gateway berjalan di http://localhost:${PORT}`);
});
