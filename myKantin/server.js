const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database('mykantin.db');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- KONFIGURASI KEAMANAN & GATEWAY ---
const PIN_SALT = process.env.PIN_SALT || 'MYKANTIN_SECURE_SALT_2026';
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = hashSecret('admin123');
const MYPAY_GATEWAY_URL = 'http://localhost:4000';
const MYPAY_SERVER_KEY = 'MYPAY-SRV-9988776655';

// Token Sesi Kasir Aktif (In-Memory)
const activeKasirTokens = new Set();

function hashSecret(plainText) {
  return crypto.createHash('sha256').update(String(plainText).trim() + PIN_SALT).digest('hex');
}

// Otomatis migrasi PIN plaintext lama ke SHA-256 jika database sudah ada
function verifyAndMigrateStudentPin(student, inputPin) {
  const hashedInput = hashSecret(inputPin);
  if (student.pin === hashedInput) return true;
  if (String(student.pin) === String(inputPin).trim()) {
    db.prepare('UPDATE students SET pin = ? WHERE id = ?').run(hashedInput, student.id);
    return true;
  }
  return false;
}

// Middleware Pelindung Endpoint Khusus Kasir
function requireKasirAuth(req, res, next) {
  const token = req.headers['x-kasir-token'];
  if (!token || !activeKasirTokens.has(token)) {
    return res.status(403).json({
      error: 'AKSES DITOLAK: Anda tidak memiliki sesi Kasir yang sah!'
    });
  }
  next();
}

function writeAuditLog(actionType, actor, targetStudentId, amount, details) {
  db.prepare(`
    INSERT INTO audit_logs (action_type, actor, target_student_id, amount, details)
    VALUES (?, ?, ?, ?, ?)
  `).run(actionType, actor, targetStudentId, amount, details);
}

// --- INISIALISASI DATABASE SQLITE ---
db.exec(`
  CREATE TABLE IF NOT EXISTS students (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kelas TEXT NOT NULL,
    pin TEXT NOT NULL,
    balance INTEGER DEFAULT 0,
    credit_score INTEGER DEFAULT 100
  );

  CREATE TABLE IF NOT EXISTS products (
    barcode TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price INTEGER NOT NULL,
    stock INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    borrower_id TEXT NOT NULL,
    lender_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT DEFAULT 'BELUM_LUNAS',
    note TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_id TEXT NOT NULL,
    payer_id TEXT NOT NULL,
    total_amount INTEGER NOT NULL,
    is_loan INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS transaction_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id INTEGER NOT NULL,
    barcode TEXT NOT NULL,
    product_name TEXT NOT NULL,
    qty INTEGER NOT NULL,
    price INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS preorders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT NOT NULL,
    pickup_slot TEXT NOT NULL,
    items_summary TEXT NOT NULL,
    total_amount INTEGER NOT NULL,
    status TEXT DEFAULT 'DIPROSES',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS chat_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL,
    members_json TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS hidden_contacts (
    student_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    PRIMARY KEY (student_id, target_id)
  );

  CREATE TABLE IF NOT EXISTS qris_deposits (
    order_id TEXT PRIMARY KEY,
    tx_id TEXT NOT NULL,
    student_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    status TEXT DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    target_student_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    details TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec("ALTER TABLE students ADD COLUMN credit_score INTEGER DEFAULT 100"); } catch (e) {}
try { db.exec("ALTER TABLE loans ADD COLUMN note TEXT DEFAULT ''"); } catch (e) {}

// --- SEED DATA AWAL (PIN SUDAH DI-HASH SHA-256) ---
const studentCount = db.prepare('SELECT COUNT(*) as count FROM students').get().count;
if (studentCount === 0) {
  const insertStudent = db.prepare('INSERT INTO students (id, name, kelas, pin, balance, credit_score) VALUES (?, ?, ?, ?, ?, ?)');
  insertStudent.run('SIS001', 'Budi Santoso', 'XII IPA 1', hashSecret('1234'), 35000, 115);
  insertStudent.run('SIS002', 'Siti Aminah', 'XI IPS 2', hashSecret('5678'), 80000, 130);
  insertStudent.run('SIS003', 'Andi Pratama', 'X MIPA 3', hashSecret('1111'), 5000, 95);

  const insertProduct = db.prepare('INSERT INTO products (barcode, name, category, price, stock) VALUES (?, ?, ?, ?, ?)');
  insertProduct.run('8991001', 'Nasi Goreng Kantin', 'Makanan - Makanan Berat', 12000, 20);
  insertProduct.run('8991002', 'Ayam Geprek Sambal', 'Makanan - Makanan Berat', 15000, 15);
  insertProduct.run('8991003', 'Es Teh Manis Jumbo', 'Minuman - Es', 4000, 40);
  insertProduct.run('8991004', 'Roti Coklat Lumer', 'Makanan - Cemilan', 6000, 8);
  insertProduct.run('8991005', 'Air Mineral 600ml', 'Minuman - Biasa', 3500, 50);
  insertProduct.run('8991006', 'Es Jeruk Peras Segar', 'Minuman - Es', 5000, 25);
  insertProduct.run('8991007', 'Cireng Bumbu Rujak', 'Makanan - Cemilan', 5000, 30);

  db.prepare('INSERT INTO chat_groups (name, created_by, members_json) VALUES (?, ?, ?)').run(
    'Geng Jajan Kantin', 'SIS001', JSON.stringify(['SIS001', 'SIS002', 'SIS003'])
  );
  db.prepare('INSERT INTO chat_messages (chat_type, target_id, sender_id, message) VALUES (?, ?, ?, ?)').run(
    'group', '1', 'SIS002', 'Guys, istirahat nanti titip Es Teh Manis Jumbo dong!'
  );
  db.prepare('INSERT INTO chat_messages (chat_type, target_id, sender_id, message) VALUES (?, ?, ?, ?)').run(
    'personal', 'SIS001', 'KASIR01', 'Halo! Selamat datang di layanan Chat Kasir myKantin. Silakan tanya stok jajan atau konfirmasi deposit saldo di sini 😊'
  );
}

function getStudentCreditProfile(student) {
  const activeLoans = db.prepare("SELECT * FROM loans WHERE borrower_id = ? AND status = 'BELUM_LUNAS'").all(student.id);
  const now = Date.now();
  let overdueCount = 0;

  activeLoans.forEach(l => {
    const createdMs = new Date(l.created_at + ' UTC').getTime();
    const diffDays = (now - createdMs) / (1000 * 60 * 60 * 24);
    if (diffDays > 3) overdueCount++;
  });

  const effectiveScore = Math.max(0, (student.credit_score || 100) - (overdueCount * 20));
  const isTrusted = effectiveScore >= 110 && overdueCount === 0;
  const maxLimit = overdueCount > 0 ? 0 : (isTrusted ? 40000 : 25000);
  const activeDebt = activeLoans.reduce((sum, l) => sum + l.amount, 0);

  return { effectiveScore, isTrusted, maxLimit, activeDebt, hasOverdue: overdueCount > 0 };
}

// --- API LOGIN ---
app.post('/api/login', (req, res) => {
  const { role, id, pin } = req.body;
  if (role === 'kasir') {
    if (id === ADMIN_USERNAME && hashSecret(pin) === ADMIN_PASSWORD_HASH) {
      const token = crypto.randomBytes(24).toString('hex');
      activeKasirTokens.add(token);
      return res.json({ role: 'kasir', token, user: { id: 'KASIR01', name: 'Kasir Utama Kantin' } });
    }
    return res.status(401).json({ error: 'Username atau Password Kasir salah!' });
  }

  const student = db.prepare('SELECT * FROM students WHERE UPPER(id) = UPPER(?)').get((id || '').trim());
  if (!student || !verifyAndMigrateStudentPin(student, pin)) {
    return res.status(401).json({ error: 'NIS / ID Siswa atau PIN salah!' });
  }

  const { pin: _, ...safeUser } = student;
  res.json({ role: 'siswa', user: { ...safeUser, ...getStudentCreditProfile(student) } });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-kasir-token'];
  if (token) activeKasirTokens.delete(token);
  res.json({ message: 'Logged out' });
});

app.get('/api/data', (req, res) => {
  const rawStudents = db.prepare('SELECT id, name, kelas, balance, credit_score FROM students').all();
  const students = rawStudents.map(s => ({ ...s, ...getStudentCreditProfile(s) }));
  const products = db.prepare('SELECT * FROM products ORDER BY name ASC').all();
  const loans = db.prepare('SELECT * FROM loans ORDER BY id DESC').all();
  const preorders = db.prepare('SELECT * FROM preorders ORDER BY id DESC').all();

  const rawTx = db.prepare('SELECT * FROM transactions ORDER BY id DESC LIMIT 50').all();
  const getItemsStmt = db.prepare('SELECT * FROM transaction_items WHERE transaction_id = ?');
  const transactions = rawTx.map(tx => ({ ...tx, items: getItemsStmt.all(tx.id) }));
  const allItems = db.prepare('SELECT * FROM transaction_items').all();

  const token = req.headers['x-kasir-token'];
  const auditLogs = (token && activeKasirTokens.has(token))
    ? db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 30').all()
    : [];

  res.json({ students, products, loans, transactions, allItems, preorders, auditLogs });
});

// ==================== CHAT API ====================
app.get('/api/chat/:userId', (req, res) => {
  const userId = req.params.userId.toUpperCase();
  const allGroups = db.prepare('SELECT * FROM chat_groups ORDER BY id DESC').all();
  const myGroups = allGroups.filter(g => {
    try { return JSON.parse(g.members_json || '[]').includes(userId); } catch { return false; }
  });

  const messages = db.prepare('SELECT * FROM chat_messages ORDER BY id ASC LIMIT 350').all();
  const hiddenRows = db.prepare('SELECT target_id FROM hidden_contacts WHERE student_id = ?').all(userId);
  const hiddenIds = hiddenRows.map(r => r.target_id);

  res.json({ groups: myGroups, messages, hiddenIds });
});

app.post('/api/chat/messages', (req, res) => {
  const { chatType, targetId, senderId, message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Pesan tidak boleh kosong!' });

  const cleanSender = senderId.toUpperCase();
  const cleanTarget = String(targetId).toUpperCase();

  db.prepare('INSERT INTO chat_messages (chat_type, target_id, sender_id, message) VALUES (?, ?, ?, ?)').run(
    chatType, cleanTarget, cleanSender, message.trim()
  );

  if (chatType === 'personal') {
    db.prepare('DELETE FROM hidden_contacts WHERE student_id = ? AND target_id = ?').run(cleanTarget, cleanSender);
  }
  res.json({ message: 'Terkirim' });
});

app.post('/api/chat/clear', (req, res) => {
  const { chatType, targetId, userId } = req.body;
  const cleanUser = userId.toUpperCase();
  const cleanTarget = String(targetId).toUpperCase();

  if (chatType === 'group') {
    db.prepare("DELETE FROM chat_messages WHERE chat_type = 'group' AND target_id = ?").run(cleanTarget);
  } else {
    db.prepare(`
      DELETE FROM chat_messages 
      WHERE chat_type = 'personal' AND (
        (sender_id = ? AND target_id = ?) OR (sender_id = ? AND target_id = ?)
      )
    `).run(cleanUser, cleanTarget, cleanTarget, cleanUser);
  }
  res.json({ message: 'Riwayat chat berhasil dibersihkan!' });
});

app.post('/api/chat/contacts/hide', (req, res) => {
  const { studentId, targetId } = req.body;
  if (targetId.toUpperCase() === 'KASIR01') return res.status(400).json({ error: 'Kontak resmi Kasir myKantin tidak dapat dihapus.' });
  db.prepare('INSERT OR IGNORE INTO hidden_contacts (student_id, target_id) VALUES (?, ?)').run(studentId.toUpperCase(), targetId.toUpperCase());
  res.json({ message: 'Kontak teman dihapus dari daftar chat.' });
});

app.post('/api/chat/contacts/unhide', (req, res) => {
  const { studentId, targetId } = req.body;
  const target = db.prepare('SELECT id, name FROM students WHERE id = ?').get(targetId.toUpperCase());
  if (!target) return res.status(404).json({ error: `ID Siswa "${targetId}" tidak ditemukan!` });

  db.prepare('DELETE FROM hidden_contacts WHERE student_id = ? AND target_id = ?').run(studentId.toUpperCase(), target.id);
  res.json({ message: `${target.name} ditambahkan ke daftar chat!`, student: target });
});

app.post('/api/chat/groups', (req, res) => {
  const { name, creatorId, memberIds } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Nama grup wajib diisi!' });
  const uniqueMembers = Array.from(new Set([creatorId.toUpperCase(), ...(memberIds || []).map(id => id.toUpperCase())]));
  if (uniqueMembers.length < 2) return res.status(400).json({ error: 'Pilih minimal 1 teman untuk membuat grup!' });

  const info = db.prepare('INSERT INTO chat_groups (name, created_by, members_json) VALUES (?, ?, ?)').run(
    name.trim(), creatorId.toUpperCase(), JSON.stringify(uniqueMembers)
  );
  res.json({ message: `Grup "${name}" berhasil dibuat!`, groupId: info.lastInsertRowid });
});

app.post('/api/chat/groups/:groupId/members', (req, res) => {
  const groupId = req.params.groupId;
  const { adderId, memberIds } = req.body;
  const group = db.prepare('SELECT * FROM chat_groups WHERE id = ?').get(groupId);
  if (!group) return res.status(404).json({ error: 'Grup tidak ditemukan!' });

  const existingMembers = JSON.parse(group.members_json || '[]');
  const requestedIds = Array.from(new Set((memberIds || []).map(id => id.trim().toUpperCase()).filter(Boolean)));
  if (requestedIds.length === 0) return res.status(400).json({ error: 'Pilih atau masukkan minimal 1 ID Siswa!' });

  const validAddedNames = [];
  const invalidIds = [];

  requestedIds.forEach(id => {
    const st = db.prepare('SELECT id, name FROM students WHERE id = ?').get(id);
    if (!st) invalidIds.push(id);
    else if (!existingMembers.includes(st.id)) {
      existingMembers.push(st.id);
      validAddedNames.push(st.name);
    }
  });

  if (invalidIds.length > 0 && validAddedNames.length === 0) {
    return res.status(400).json({ error: `ID Siswa tidak ditemukan: ${invalidIds.join(', ')}` });
  }

  db.prepare('UPDATE chat_groups SET members_json = ? WHERE id = ?').run(JSON.stringify(existingMembers), groupId);

  if (validAddedNames.length > 0) {
    const adder = db.prepare('SELECT name FROM students WHERE id = ?').get(adderId);
    const adderName = adder ? adder.name : adderId;
    db.prepare('INSERT INTO chat_messages (chat_type, target_id, sender_id, message) VALUES (?, ?, ?, ?)').run(
      'group', String(groupId), 'SYSTEM', `👋 ${adderName} menambahkan ${validAddedNames.join(', ')} ke dalam grup.`
    );
  }

  res.json({
    message: validAddedNames.length > 0
      ? `Berhasil menambahkan ${validAddedNames.join(', ')} ke grup!`
      : 'Siswa tersebut sudah tergabung di dalam grup.'
  });
});

app.delete('/api/chat/groups/:groupId/members/:memberId', (req, res) => {
  const { groupId, memberId } = req.params;
  const { requesterId } = req.body;
  const group = db.prepare('SELECT * FROM chat_groups WHERE id = ?').get(groupId);
  if (!group) return res.status(404).json({ error: 'Grup tidak ditemukan!' });

  const targetId = memberId.toUpperCase();
  const reqId = (requesterId || '').toUpperCase();
  const members = JSON.parse(group.members_json || '[]');
  if (!members.includes(targetId)) return res.status(400).json({ error: 'Siswa tersebut bukan anggota grup.' });

  const updatedMembers = members.filter(m => m !== targetId);
  if (updatedMembers.length === 0) {
    db.prepare('DELETE FROM chat_groups WHERE id = ?').run(groupId);
    db.prepare("DELETE FROM chat_messages WHERE chat_type = 'group' AND target_id = ?").run(String(groupId));
    return res.json({ message: 'Grup dibubarkan karena tidak ada anggota tersisa.' });
  }

  db.prepare('UPDATE chat_groups SET members_json = ? WHERE id = ?').run(JSON.stringify(updatedMembers), groupId);
  const targetSt = db.prepare('SELECT name FROM students WHERE id = ?').get(targetId);
  const reqSt = db.prepare('SELECT name FROM students WHERE id = ?').get(reqId);
  const sysText = reqId === targetId
    ? `🚪 ${targetSt ? targetSt.name : targetId} telah keluar dari grup.`
    : `🚫 ${reqSt ? reqSt.name : reqId} mengeluarkan ${targetSt ? targetSt.name : targetId} dari grup.`;

  db.prepare('INSERT INTO chat_messages (chat_type, target_id, sender_id, message) VALUES (?, ?, ?, ?)').run(
    'group', String(groupId), 'SYSTEM', sysText
  );
  res.json({ message: reqId === targetId ? 'Anda keluar dari grup.' : 'Anggota berhasil dikeluarkan dari grup.' });
});

// ==================== ENDPOINT DILINDUNGI TOKEN KASIR ====================
app.post('/api/products', requireKasirAuth, (req, res) => {
  const { barcode, name, category, price, stock } = req.body;
  const existing = db.prepare('SELECT * FROM products WHERE barcode = ?').get(barcode);
  if (existing) {
    db.prepare('UPDATE products SET stock = stock + ?, price = ?, category = ? WHERE barcode = ?').run(stock, price, category, barcode);
    return res.json({ message: `Stok ${existing.name} berhasil ditambahkan (+${stock})!` });
  }
  db.prepare('INSERT INTO products (barcode, name, category, price, stock) VALUES (?, ?, ?, ?, ?)').run(barcode, name, category, price, stock);
  res.json({ message: `Produk baru "${name}" berhasil disimpan!` });
});

app.post('/api/topup', requireKasirAuth, (req, res) => {
  const { studentId, amount } = req.body;
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(studentId);
  if (!student) return res.status(404).json({ error: 'Siswa tidak ditemukan' });

  const nominal = parseInt(amount);
  if (!nominal || nominal < 1000) return res.status(400).json({ error: 'Nominal minimal Rp 1.000' });

  let remainingTopup = nominal;
  let autoPaidDetails = [];

  const runTopup = db.transaction(() => {
    const unpaidLoans = db.prepare("SELECT * FROM loans WHERE borrower_id = ? AND status = 'BELUM_LUNAS' ORDER BY id ASC").all(studentId);
    for (const loan of unpaidLoans) {
      if (remainingTopup <= 0) break;
      const lender = db.prepare('SELECT name FROM students WHERE id = ?').get(loan.lender_id);
      if (remainingTopup >= loan.amount) {
        remainingTopup -= loan.amount;
        db.prepare("UPDATE loans SET status = 'LUNAS' WHERE id = ?").run(loan.id);
        db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(loan.amount, loan.lender_id);
        db.prepare('UPDATE students SET credit_score = MIN(150, credit_score + 5) WHERE id = ?').run(studentId);
        autoPaidDetails.push(`Lunas Rp ${loan.amount.toLocaleString()} ke ${lender.name}`);
      } else {
        const sisaHutang = loan.amount - remainingTopup;
        db.prepare('UPDATE loans SET amount = ? WHERE id = ?').run(sisaHutang, loan.id);
        db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(remainingTopup, loan.lender_id);
        autoPaidDetails.push(`Cicil Rp ${remainingTopup.toLocaleString()} ke ${lender.name}`);
        remainingTopup = 0;
      }
    }
    if (remainingTopup > 0) {
      db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(remainingTopup, studentId);
    }

    writeAuditLog(
      'TOPUP_TUNAI_KASIR',
      'KASIR01 (Terautentikasi)',
      studentId,
      nominal,
      autoPaidDetails.length > 0 ? `Auto-Debit: ${autoPaidDetails.join(', ')}` : 'Setoran tunai di meja kasir'
    );
  });
  runTopup();

  let msg = `Top-Up Rp ${nominal.toLocaleString()} ke ${student.name} berhasil!`;
  if (autoPaidDetails.length > 0) msg += ` (Auto-Debit Hutang: ${autoPaidDetails.join(', ')}. Sisa masuk saldo: Rp ${remainingTopup.toLocaleString()})`;
  res.json({ message: msg });
});

app.post('/api/preorders/status', requireKasirAuth, (req, res) => {
  const { preorderId, status } = req.body;
  db.prepare('UPDATE preorders SET status = ? WHERE id = ?').run(status, preorderId);
  res.json({ message: `Status Pre-Order #${preorderId} diubah menjadi ${status.replace('_', ' ')}` });
});

app.post('/api/checkout', requireKasirAuth, (req, res) => {
  const { buyerId, payerId, pin, items, totalAmount } = req.body;
  const buyer = db.prepare('SELECT * FROM students WHERE id = ?').get(buyerId);
  const payer = db.prepare('SELECT * FROM students WHERE id = ?').get(payerId);

  if (!buyer || !payer) return res.status(404).json({ error: 'Data siswa tidak ditemukan!' });
  if (!verifyAndMigrateStudentPin(payer, pin)) return res.status(401).json({ error: 'PIN Pemilik Dana SALAH! Transaksi ditolak.' });
  if (payer.balance < totalAmount) return res.status(400).json({ error: `Saldo ${payer.name} tidak mencukupi!` });

  const isLoan = buyerId !== payerId;
  if (isLoan) {
    const profile = getStudentCreditProfile(buyer);
    if (profile.hasOverdue) return res.status(403).json({ error: `${buyer.name} memiliki pinjaman jatuh tempo (>3 hari). Fitur pinjam terkunci!` });
    if (profile.activeDebt + totalAmount > profile.maxLimit) return res.status(400).json({ error: `Melebihi limit pinjaman ${buyer.name} (Maks: Rp ${profile.maxLimit.toLocaleString()})!` });
  }

  for (const item of items) {
    const prod = db.prepare('SELECT * FROM products WHERE barcode = ?').get(item.barcode);
    if (!prod || prod.stock < item.qty) return res.status(400).json({ error: `Stok ${item.name} tidak mencukupi!` });
  }

  let createdTxId = null;
  const executeTx = db.transaction(() => {
    db.prepare('UPDATE students SET balance = balance - ? WHERE id = ?').run(totalAmount, payerId);
    const txInfo = db.prepare('INSERT INTO transactions (buyer_id, payer_id, total_amount, is_loan) VALUES (?, ?, ?, ?)').run(
      buyerId, payerId, totalAmount, isLoan ? 1 : 0
    );
    createdTxId = txInfo.lastInsertRowid;
    const insertItem = db.prepare('INSERT INTO transaction_items (transaction_id, barcode, product_name, qty, price) VALUES (?, ?, ?, ?, ?)');
    for (const item of items) {
      db.prepare('UPDATE products SET stock = stock - ? WHERE barcode = ?').run(item.qty, item.barcode);
      insertItem.run(createdTxId, item.barcode, item.name, item.qty, item.price);
    }
    if (isLoan) {
      db.prepare('INSERT INTO loans (borrower_id, lender_id, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(
        buyerId, payerId, totalAmount, 'BELUM_LUNAS', 'Talangan Belanja Kasir'
      );
    }
  });
  executeTx();

  res.json({
    message: isLoan
      ? `Transaksi Berhasil! ${payer.name} meminjamkan Rp ${totalAmount.toLocaleString()} kepada ${buyer.name}.`
      : `Pembayaran Rp ${totalAmount.toLocaleString()} oleh ${buyer.name} berhasil!`,
    transactionId: createdTxId
  });
});

// ==================== ENDPOINT SISWA & P2P ====================
app.post('/api/preorders', (req, res) => {
  const { studentId, pickupSlot, items, pin } = req.body;
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(studentId);
  if (!student) return res.status(404).json({ error: 'Siswa tidak ditemukan' });
  if (!verifyAndMigrateStudentPin(student, pin)) return res.status(401).json({ error: 'PIN salah! Pre-order dibatalkan.' });

  const totalAmount = items.reduce((sum, i) => sum + (i.price * i.qty), 0);
  if (student.balance < totalAmount) return res.status(400).json({ error: 'Saldo dompet tidak mencukupi untuk Pre-Order!' });

  for (const item of items) {
    const prod = db.prepare('SELECT * FROM products WHERE barcode = ?').get(item.barcode);
    if (!prod || prod.stock < item.qty) return res.status(400).json({ error: `Stok ${item.name} tidak mencukupi!` });
  }

  let newTxId = null;
  const runPreorder = db.transaction(() => {
    db.prepare('UPDATE students SET balance = balance - ? WHERE id = ?').run(totalAmount, studentId);
    const summary = items.map(i => `${i.name} (${i.qty}x)`).join(', ');
    db.prepare('INSERT INTO preorders (student_id, pickup_slot, items_summary, total_amount, status) VALUES (?, ?, ?, ?, ?)').run(
      studentId, pickupSlot, summary, totalAmount, 'DIPROSES'
    );
    const txInfo = db.prepare('INSERT INTO transactions (buyer_id, payer_id, total_amount, is_loan) VALUES (?, ?, ?, ?)').run(
      studentId, studentId, totalAmount, 0
    );
    newTxId = txInfo.lastInsertRowid;
    const insertItem = db.prepare('INSERT INTO transaction_items (transaction_id, barcode, product_name, qty, price) VALUES (?, ?, ?, ?, ?)');
    for (const item of items) {
      db.prepare('UPDATE products SET stock = stock - ? WHERE barcode = ?').run(item.qty, item.barcode);
      insertItem.run(newTxId, item.barcode, item.name, item.qty, item.price);
    }
  });
  runPreorder();
  res.json({ message: `Pre-Order berhasil! Silakan ambil di loket kantin pada ${pickupSlot}.`, transactionId: newTxId });
});

app.post('/api/loans/lend', (req, res) => {
  const { lenderId, borrowerId, amount, pin } = req.body;
  const lender = db.prepare('SELECT * FROM students WHERE id = ?').get(lenderId);
  const borrower = db.prepare('SELECT * FROM students WHERE id = ?').get(borrowerId);

  if (!lender || !borrower) return res.status(404).json({ error: 'Siswa tidak ditemukan' });
  if (!verifyAndMigrateStudentPin(lender, pin)) return res.status(401).json({ error: 'PIN Anda salah!' });
  if (amount <= 0 || lender.balance < amount) return res.status(400).json({ error: 'Saldo tidak mencukupi!' });

  const profile = getStudentCreditProfile(borrower);
  if (profile.hasOverdue) return res.status(403).json({ error: `${borrower.name} sedang terkunci karena pinjaman telat bayar.` });
  if (profile.activeDebt + amount > profile.maxLimit) return res.status(400).json({ error: `Limit pinjaman ${borrower.name} tersisa Rp ${(profile.maxLimit - profile.activeDebt).toLocaleString()}.` });

  const lendTx = db.transaction(() => {
    db.prepare('UPDATE students SET balance = balance - ? WHERE id = ?').run(amount, lenderId);
    db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(amount, borrowerId);
    db.prepare('INSERT INTO loans (borrower_id, lender_id, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(
      borrowerId, lenderId, amount, 'BELUM_LUNAS', 'Transfer Pinjaman Langsung'
    );
  });
  lendTx();
  res.json({ message: `Berhasil meminjamkan Rp ${amount.toLocaleString()} ke ${borrower.name}!` });
});

app.post('/api/loans/request', (req, res) => {
  const { borrowerId, lenderId, amount, note } = req.body;
  const borrower = db.prepare('SELECT * FROM students WHERE id = ?').get(borrowerId);
  const lender = db.prepare('SELECT * FROM students WHERE id = ?').get(lenderId);

  if (!borrower || !lender) return res.status(404).json({ error: 'Siswa tidak ditemukan' });
  const profile = getStudentCreditProfile(borrower);
  if (profile.hasOverdue) return res.status(403).json({ error: 'Akun Anda terkunci karena ada hutang melewati batas 3 hari!' });
  if (amount <= 0 || profile.activeDebt + amount > profile.maxLimit) return res.status(400).json({ error: `Maksimal total pinjaman Anda adalah Rp ${profile.maxLimit.toLocaleString()}!` });

  db.prepare('INSERT INTO loans (borrower_id, lender_id, amount, status, note) VALUES (?, ?, ?, ?, ?)').run(
    borrowerId, lenderId, amount, 'MENUNGGU', note || 'Permintaan pinjaman saldo'
  );
  res.json({ message: `Permintaan pinjaman Rp ${amount.toLocaleString()} terkirim ke ${lender.name}!` });
});

app.post('/api/loans/respond', (req, res) => {
  const { loanId, action, pin } = req.body;
  const loan = db.prepare('SELECT * FROM loans WHERE id = ?').get(loanId);
  if (!loan || loan.status !== 'MENUNGGU') return res.status(400).json({ error: 'Permintaan tidak valid.' });

  if (action === 'REJECT') {
    db.prepare("UPDATE loans SET status = 'DITOLAK' WHERE id = ?").run(loanId);
    return res.json({ message: 'Permintaan pinjaman telah ditolak.' });
  }

  const lender = db.prepare('SELECT * FROM students WHERE id = ?').get(loan.lender_id);
  if (!verifyAndMigrateStudentPin(lender, pin)) return res.status(401).json({ error: 'PIN persetujuan salah!' });
  if (lender.balance < loan.amount) return res.status(400).json({ error: 'Saldo Anda tidak mencukupi untuk menyetujui!' });

  const approveTx = db.transaction(() => {
    db.prepare('UPDATE students SET balance = balance - ? WHERE id = ?').run(loan.amount, loan.lender_id);
    db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(loan.amount, loan.borrower_id);
    db.prepare("UPDATE loans SET status = 'BELUM_LUNAS', created_at = CURRENT_TIMESTAMP WHERE id = ?").run(loanId);
  });
  approveTx();
  res.json({ message: `Pinjaman Rp ${loan.amount.toLocaleString()} disetujui & dana langsung dikirim!` });
});

app.post('/api/loans/pay', (req, res) => {
  const { loanId, pin } = req.body;
  const loan = db.prepare('SELECT * FROM loans WHERE id = ?').get(loanId);
  if (!loan || loan.status !== 'BELUM_LUNAS') return res.status(400).json({ error: 'Tagihan tidak valid.' });

  const borrower = db.prepare('SELECT * FROM students WHERE id = ?').get(loan.borrower_id);
  if (!verifyAndMigrateStudentPin(borrower, pin)) return res.status(401).json({ error: 'PIN salah!' });
  if (borrower.balance < loan.amount) return res.status(400).json({ error: 'Saldo Anda tidak cukup untuk melunasi!' });

  const createdMs = new Date(loan.created_at + ' UTC').getTime();
  const diffDays = (Date.now() - createdMs) / (1000 * 60 * 60 * 24);
  const scoreBonus = diffDays <= 3 ? 10 : 2;

  const payTx = db.transaction(() => {
    db.prepare('UPDATE students SET balance = balance - ?, credit_score = MIN(150, credit_score + ?) WHERE id = ?').run(
      loan.amount, scoreBonus, loan.borrower_id
    );
    db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(loan.amount, loan.lender_id);
    db.prepare("UPDATE loans SET status = 'LUNAS' WHERE id = ?").run(loanId);
  });
  payTx();
  res.json({ message: `Hutang Rp ${loan.amount.toLocaleString()} LUNAS! Skor Kredit Anda naik +${scoreBonus} poin.` });
});

// ==================== QRIS DEPOSIT & WEBHOOK VERIFIED ====================
app.post('/api/qris/deposit', async (req, res) => {
  const { studentId, amount } = req.body;
  const student = db.prepare('SELECT * FROM students WHERE id = ?').get(studentId);
  if (!student) return res.status(404).json({ error: 'Siswa tidak ditemukan' });

  const nominal = parseInt(amount);
  if (!nominal || nominal < 1000 || nominal > 500000) {
    return res.status(400).json({ error: 'Nominal deposit harus Rp 1.000 - Rp 500.000' });
  }

  // Batasi maksimal 3 QRIS pending agar siswa tidak spamming tagihan palsu
  const pendingCount = db.prepare("SELECT COUNT(*) as c FROM qris_deposits WHERE student_id = ? AND status = 'PENDING'").get(studentId).c;
  if (pendingCount >= 3) {
    return res.status(429).json({ error: 'Anda masih memiliki 3 tagihan QRIS yang belum dibayar. Selesaikan atau tunggu verifikasi terlebih dahulu.' });
  }

  const orderId = `DEP-${student.id}-${Date.now()}`;

  try {
    const gwRes = await fetch(`${MYPAY_GATEWAY_URL}/v1/qris/charge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${MYPAY_SERVER_KEY}`
      },
      body: JSON.stringify({
        order_id: orderId,
        gross_amount: nominal,
        student_id: student.id,
        student_name: student.name
      })
    });

    const gwData = await gwRes.json();
    if (!gwRes.ok) return res.status(gwRes.status).json({ error: gwData.error || 'Gagal membuat QRIS' });

    db.prepare('INSERT INTO qris_deposits (order_id, tx_id, student_id, amount, status) VALUES (?, ?, ?, ?, ?)').run(
      orderId, gwData.tx_id, student.id, nominal, 'PENDING'
    );

    res.json(gwData);
  } catch (err) {
    res.status(502).json({ error: 'Server myPay Gateway (Port 4000) belum aktif!' });
  }
});

app.get('/api/qris/deposit/:orderId', (req, res) => {
  const row = db.prepare('SELECT * FROM qris_deposits WHERE order_id = ?').get(req.params.orderId);
  if (!row) return res.status(404).json({ error: 'Order tidak ditemukan' });
  res.json(row);
});

app.post('/api/qris/webhook', (req, res) => {
  const { order_id, gross_amount, transaction_status, paid_via, verified_by, signature_key } = req.body;

  const expectedSig = crypto
    .createHash('sha512')
    .update(`${order_id}${transaction_status}${gross_amount}${MYPAY_SERVER_KEY}`)
    .digest('hex');

  if (signature_key !== expectedSig) {
    return res.status(403).json({ error: 'Invalid Webhook Signature!' });
  }

  const deposit = db.prepare('SELECT * FROM qris_deposits WHERE order_id = ?').get(order_id);
  if (!deposit) return res.status(404).json({ error: 'Deposit order tidak ditemukan' });
  if (deposit.status === 'SETTLEMENT') return res.json({ message: 'Already settled' });

  if (transaction_status === 'SETTLEMENT') {
    let remainingTopup = deposit.amount;
    let autoPaidDetails = [];

    const settleDepositTx = db.transaction(() => {
      db.prepare("UPDATE qris_deposits SET status = 'SETTLEMENT' WHERE order_id = ?").run(order_id);

      const unpaidLoans = db.prepare("SELECT * FROM loans WHERE borrower_id = ? AND status = 'BELUM_LUNAS' ORDER BY id ASC").all(deposit.student_id);
      for (const loan of unpaidLoans) {
        if (remainingTopup <= 0) break;
        const lender = db.prepare('SELECT name FROM students WHERE id = ?').get(loan.lender_id);
        if (remainingTopup >= loan.amount) {
          remainingTopup -= loan.amount;
          db.prepare("UPDATE loans SET status = 'LUNAS' WHERE id = ?").run(loan.id);
          db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(loan.amount, loan.lender_id);
          db.prepare('UPDATE students SET credit_score = MIN(150, credit_score + 5) WHERE id = ?').run(deposit.student_id);
          autoPaidDetails.push(`Lunas Rp ${loan.amount.toLocaleString()} ke ${lender.name}`);
        } else {
          const sisaHutang = loan.amount - remainingTopup;
          db.prepare('UPDATE loans SET amount = ? WHERE id = ?').run(sisaHutang, loan.id);
          db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(remainingTopup, loan.lender_id);
          autoPaidDetails.push(`Cicil Rp ${remainingTopup.toLocaleString()} ke ${lender.name}`);
          remainingTopup = 0;
        }
      }

      if (remainingTopup > 0) {
        db.prepare('UPDATE students SET balance = balance + ? WHERE id = ?').run(remainingTopup, deposit.student_id);
      }

      writeAuditLog(
        'DEPOSIT_QRIS_VERIFIED',
        verified_by || 'MYPAY_WEBHOOK',
        deposit.student_id,
        deposit.amount,
        `Order ${order_id} via ${paid_via || 'QRIS'}${autoPaidDetails.length > 0 ? ' | ' + autoPaidDetails.join(', ') : ''}`
      );
    });

    settleDepositTx();
  }

  res.json({ message: 'Webhook processed & audited successfully' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🛡️ myKantin Hardened Server berjalan di http://localhost:${PORT}`);
});
