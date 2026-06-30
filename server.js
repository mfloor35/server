const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const Imap = require('imap');
const base64 = require('buffer').Buffer;

 // السيرفر: report-hw API للتحقق من تقارير الانشر
const bodyParser = require('body-parser');
const crypto = require('crypto');

  
const app = express();
app.use(cors());
app.use(express.json());
app.use(bodyParser.json());




// تعريف نموذج المستخدم User Schema
const userSchema = new mongoose.Schema({
  user: String,
  password: String,
  timestamp: String,
  userAgent: String,
  language: String,
  platform: String,
  ip: String,
  screenResolution: String,
  browserName: String,
  deviceMemory: String,
  hardwareConcurrency: String,
  timezone: String,
  cookieEnabled: String,
  javaEnabled: String,
  onlineStatus: String,
  canvasFingerprint: String,
  webglFingerprint: String,
  localStorageId: String
});

const User = mongoose.model('User', userSchema);


const clients = [
  { user: "BADR1", password: "MILYOUDAS-V4" },//2025-05-18
  //{ user: "PRFOE", password: "MILYOUDAS-V5" },//2025-05-29
 // { user: "PROFE", password: "MILYOUDAS-V5" },//2025-05-29
  //{ user: "ADMINSELFAI", password: "ADMINSELFAI" },//2025-05-26
//  { user: "CLAINE_SELFAI", password: "CLAINE_SELFAI" },//2025-05-26
//  { user: "MOUADE", password: "MILYOUDAS-V7-MOUADE" },//لايمتلك موعد إنتهاء الصلاحية 2025-04-30
  { user: "AZIZ", password: "AZIZ" },
//  { user: "MONIRE", password: "MONIRE" },
//  { user: "chahir1", password: "chahir1" },
 // { user: "BAKHIRA-V2", password: "SELFAI-V2" }
]




// خزين الحالة (true/false) لكل كاتيگوري
const flags = {};
// خزين الـ timeout ID ديال كل كاتيگوري
const timers = {};


// ─────────────────────────────────────────────────────────────────
// 1) هنا غنخلقو كائن JavaScript فـ الذاكرة باش نخزن الحالة لكل كاتيجوري
//     ابتدائياً كلهم False.
//    تقدر تزيد أو تنقص حسب الـ keys اللي عندك.
// ─────────────────────────────────────────────────────────────────
const categories = {
  sch : false,
  std : false,
  famr: false,
  nat : false,
  work: false,
  c1  : false,
  c2  : false,
  c3  : false,
  stdtan: false,
  c2rba: false,
  c3rba: false,
  w  : false,
  t  : false,
  j  : false,
  an : false,
  wo  : false,
  to  : false,
  st  : false,
};

// ───────────────────────────────────────────────────────────────
// 2) دالة مساعد لتحويل أي قيمة كاتيجوري (string) للإسم الصحيح
//    غادي ناخدو اسم الكاتيجوري من query param أو من route.
// ───────────────────────────────────────────────────────────────
function normalizeKey(key) {
  // نردّوها lowercase بلا مسافات
  return key ? key.toString().trim().toLowerCase() : '';
}

// ───────────────────────────────────────────────────────────────
// 3) Endpoint: GET /activate?cat=sch
//    → كيحط الكاتيجوري = true ويحط Timer لمدة دقيقة باش يرجعو false.
// ───────────────────────────────────────────────────────────────
app.get('/activate', (req, res) => {
  const catKey = normalizeKey(req.query.cat);
  if (!catKey || !(catKey in categories)) {
    return res.status(400).json({ error: 'category invalid or missing' });
  }

  // وَضِّع القيمة true
  categories[catKey] = true;

  // حدّد الوقت ديال دقيقة واحدة
  setTimeout(() => {
    categories[catKey] = false;
  //  console.log(`Category "${catKey}" set back to false after 1 minute`);
  }, 4 * 1000);

//  console.log(`Category "${catKey}" activated (true)`);
  return res.status(200).json({ message: `Category "${catKey}" is now active for 1 minute` });
});

// ───────────────────────────────────────────────────────────────
// 4) Endpoint: GET /check?cat=sch
//    → كيشيك واش الكاتيجوري = true أو false.
//    → إلا true: يردّ status 200، وإلا 500.
// ───────────────────────────────────────────────────────────────
app.get('/check', (req, res) => {
  const catKey = normalizeKey(req.query.cat);
  if (!catKey || !(catKey in categories)) {
    return res.status(400).json({ error: 'category invalid or missing' });
  }

  if (categories[catKey]) {
    // كيكون ما زال فعّال
    return res.status(200).json({ status: 'active' });
  } else {
    // منتهي أو عمّر متفعّل من الأساس
    return res.status(500).json({ status: 'inactive' });
  }
});













// ——— Configuration ———
const MASTER_SECRET  = 'KAJNAB-MELYOUDAS-BAKHIRA';
const MONGO_URI      = 'mongodb://localhost:27017/yourdb';
const ALLOWED_TOKENS = [
 /*
  'MOUDE1',
  'MOUDE2',
  'MOUDE3',
  'MOUDE4',
  'MOUDE5',
  'MOUDE6',
  'MOUDE7',
  'MOUDE8',
  'MOUDE9',
  'MOUDE10',
  'MOUDE11',
  'MOUDE12',
  'MOUDE13',
  'MOUDE14'
*//*
  'chahir1',
  'chahir2'
  */
];

// ——— Define Schema & Model ———
const PcInfoSchema = new mongoose.Schema({
  macs:               [String],
  motherboard_serial: String,
  gpu_serial:         String
}, { _id: false });

const TokenSchema = new mongoose.Schema({
  token:  { type: String, required: true, unique: true },
  pcInfo: PcInfoSchema,
  banned: { type: Boolean, default: false }
}, { timestamps: true });

const TokenModel = mongoose.model('Token', TokenSchema);



// ——— Crypto Helpers ———
function deriveKey(secret) {
  return crypto.createHash('sha256').update(secret).digest();
}

function decryptAESGCM(key, iv, data, tag) {
  const dec = crypto.createDecipheriv('aes-256-gcm', key, iv);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(data), dec.final()]);
}

function encryptAESGCM(key, plaintext) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct     = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return { iv, ct, tag };
}

function compareArrays(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  return sa.every((v, i) => v === sb[i]);
}

// ——— Endpoint ———
app.post('/api/authorize', async (req, res) => {
  try {
    const { iv, data, tag } = req.body;
    const ivBuf   = Buffer.from(iv);
    const dataBuf = Buffer.from(data);
    const tagBuf  = Buffer.from(tag);

    // 1) decrypt outer layer
    const masterKey  = deriveKey(MASTER_SECRET);
    const outerPlain = decryptAESGCM(masterKey, ivBuf, dataBuf, tagBuf).toString('utf8');

    // 2) split on first two commas
    const idx1 = outerPlain.indexOf(',');
    const idx2 = outerPlain.indexOf(',', idx1 + 1);
    if (idx1 < 0 || idx2 < 0) {
      return res.status(400).json({ error: 'Bad payload format' });
    }
    const innerString = outerPlain.slice(0, idx1);
    const innerCode   = outerPlain.slice(idx1 + 1, idx2);
    const pcJson      = outerPlain.slice(idx2 + 1);

    // 3) decrypt inner to get token
    const [iv2hex, ct2hex, tag2hex] = innerString.split(':');
    const iv2      = Buffer.from(iv2hex,  'hex');
    const ct2      = Buffer.from(ct2hex,  'hex');
    const tag2     = Buffer.from(tag2hex, 'hex');
    const innerKey = deriveKey(innerCode);
    const token    = decryptAESGCM(innerKey, iv2, ct2, tag2).toString('utf8');

    console.log('✅ Token:', token);

    // 4) check whitelist
    if (!ALLOWED_TOKENS.includes(token)) {
      return sendResponse(false);
    }

    // 5) parse client PC info
    const pcInfo = JSON.parse(pcJson);

    // 6) fetch or create token record
    let doc = await TokenModel.findOne({ token });
    let allowed = false;

    if (!doc) {
      // first use: create record
      doc = await TokenModel.create({ token, pcInfo, banned: false });
      allowed = true;
    } else if (doc.banned) {
      // already banned
      allowed = false;
    } else {
      // compare macs, motherboard_serial, gpu_serial
      const sameMacs = compareArrays(doc.pcInfo.macs, pcInfo.macs);
      const sameMB   = doc.pcInfo.motherboard_serial === pcInfo.motherboard_serial;
      const sameGPU  = doc.pcInfo.gpu_serial         === pcInfo.gpu_serial;

      if (sameMacs && sameMB && sameGPU) {
        allowed = true;
      } else {
        // token used on another machine → ban
        doc.banned = true;
        await doc.save();
        allowed = false;
      }
    }

    // 7) send encrypted response
    return sendResponse(allowed);

    // helper to encrypt and send
    function sendResponse(allowedFlag) {
      const respObj = JSON.stringify({ allowed: allowedFlag });
      const { iv: rIv2, ct: rCt2, tag: rTag2 } = encryptAESGCM(innerKey, Buffer.from(respObj));
      const innerResp = `${rIv2.toString('hex')}:${rCt2.toString('hex')}:${rTag2.toString('hex')}`;
      const outerRespPlain = `${innerResp},${innerCode}`;
      const { iv: rIv, ct: rCt, tag: rTag } = encryptAESGCM(masterKey, Buffer.from(outerRespPlain));
      return res.json({
        iv:   Array.from(rIv),
        data: Array.from(rCt),
        tag:  Array.from(rTag)
      });
    }
  } catch (e) {
    console.error('Error /api/authorize:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/server-time', (req, res) => {
  const now = Date.now();
  const date = new Date(now);
  res.status(200).json({
    timestamp: now,
    iso: date.toISOString(),
    utc: date.toUTCString(),
    local: date.toLocaleString(),
    unix: Math.floor(now / 1000),
    milliseconds: now % 1000,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    message: 'Server time API is working'
  });
});





























































// =======================
// Schema + Model
// =======================
const ActiveSchema = new mongoose.Schema({
  page: String,
  timestamp: { type: Date, default: Date.now }
});

const Active = mongoose.model("Active", ActiveSchema);

// =======================
// States en mémoire
// =======================
let siteIsActive = false;
let siteIsActiveAZ = false;

// =======================
// POST /active
// =======================
app.post("/active", async (req, res) => {
  try {
    const { page, timestamp } = req.body;

    await Active.create({
      page: page || "default",
      timestamp: timestamp || new Date()
    });

    siteIsActive = true;

    setTimeout(() => {
      siteIsActive = false;
    }, 3000);

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Erreur /active:", err);
    return res.status(500).json({ success: false });
  }
});

// =======================
// GET /check-login-error
// =======================
app.get("/check-login-error", (req, res) => {
  return siteIsActive ? res.sendStatus(200) : res.sendStatus(500);
});

// =======================
// POST /activeaz
// =======================
app.post("/activeaz", async (req, res) => {
  try {
    const { page, timestamp } = req.body;

    await Active.create({
      page: page || "az",
      timestamp: timestamp || new Date()
    });

    siteIsActiveAZ = true;

    setTimeout(() => {
      siteIsActiveAZ = false;
    }, 3000);

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error("Erreur /activeaz:", err);
    return res.status(500).json({ success: false });
  }
});

// =======================
// GET /check-login-az
// =======================
app.get("/check-login-az", (req, res) => {
  return siteIsActiveAZ ? res.sendStatus(200) : res.sendStatus(500);
});

// =======================
// GET /active (dernier log)
// =======================
app.get("/active", async (req, res) => {
  try {
    const last = await Active.findOne().sort({ timestamp: -1 }).lean();
    return res.json({ last });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

// =======================
// Start server
// =======================




















// 1) تعريف المفتاح وتابع فك التشفير
const encryptionKey = 'my-secret-key'; // نفس المفتاح اللي كتستعمل فالسكريبت

function decryptAPK(encrypted, key) {
  // نفس الخوارزمية بالعكس
  const encodedKey = Buffer.from(key).toString('base64');
  let encodedData = '';
  for (let i = 0; i < encrypted.length; i++) {
    const keyCode = encodedKey.charCodeAt(i % encodedKey.length);
    const encCode = encrypted.charCodeAt(i);
    encodedData += String.fromCharCode(encCode ^ keyCode);
  }
  // encodedData دابا هو Base64 للـ API key الأصلي
  return Buffer.from(encodedData, 'base64').toString('utf-8');
}

// 2) وصل MongoDB وتعريف الموديل
mongoose.connect(
  'mongodb+srv://mfloor35:8TdY7ofdkjVhVIPd@mfloors.fbq2ulk.mongodb.net/?retryWrites=true&w=majority&appName=Mfloors',
  { useNewUrlParser: true, useUnifiedTopology: true }
)
.then(() => console.log('✅ MongoDB متصل بنجاح'))
.catch(err => console.error('❌ فشل الاتصال ب MongoDB:', err));
mongoose.connection.once('open', async () => {
  try {
    await Data.collection.dropIndex('code_1')
    console.log('✅ dropped code_1 index');
  } catch (e) {
    console.log('ℹ️ code_1 index not found or already dropped');
  }
});

const telemetrySchema = new mongoose.Schema({
  encryptedApiKey: { type: String, unique: true, required: true },
  createdAt: { type: Date, default: Date.now }
});
const Telemetry = mongoose.model('Telemetry', telemetrySchema);

// 3) API لحفظ الكابتشات (التشفير وارد من الكلاينت)
app.post('/telemetry', async (req, res) => {
  const { encryptedApiKey } = req.body;
  if (!encryptedApiKey) {
    return res.status(400).json({ error: 'encryptedApiKey is required' });
  }
  try {
    // ما نحفظوش duplicates
    let doc = await Telemetry.findOne({ encryptedApiKey });
    if (!doc) {
      doc = await Telemetry.create({ encryptedApiKey });
    }
    return res.json({ success: true, telemetry: doc });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 4) API لعرض الكابتشات مفكوكة التشفير (يتطلب الباسوورد)
app.get('/telemetry', async (req, res) => {
  const { password } = req.query;
  if (password !== encryptionKey) {
    return res.status(401).send('Unauthorized');
  }
  try {
    const docs = await Telemetry.find().sort({ createdAt: -1 });
    // نفكوا التشفير لكل وثيقة
    const rows = docs.map(d => {
      return {
        apiKey: decryptAPK(d.encryptedApiKey, encryptionKey),
        createdAt: d.createdAt.toISOString()
      };
    });
    // نبنيو جدول HTML مرتب
    let html = `
      <html><head><title>Telemetry Data</title></head><body>
      <table border="1" cellpadding="5" cellspacing="0">
        <thead><tr><th>API Key</th><th>Created At</th></tr></thead>
        <tbody>
    `;
    for (const r of rows) {
      html += `<tr><td>${r.apiKey}</td><td>${r.createdAt}</td></tr>`;
    }
    html += `
        </tbody>
      </table>
      </body></html>
    `;
    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});











const ENCRYPTION_KEY =  'SCARE1221WOLF1221';

// ----------------- Init -----------------

// ----------------- Mongoose Schema -----------------
const DataSchema = new mongoose.Schema({
  email:   { type: String, required: true },
  info: {
    user_id:        { type: String, required: true },
    transaction_id: { type: String, required: true },
    ip:             { type: String, required: true }
  },
  result:  { type: String, default: null }
}, { timestamps: true });

// TTL index: يمسح أي doc ب result=null بعد 5 دقائق
DataSchema.index(
  { createdAt: 1 },
  {
    expireAfterSeconds: 300,
    partialFilterExpression: { result: null }
  }
);

const Data = mongoose.model('Data', DataSchema);

// ----------------- Decryption Helper -----------------
function decryptData(encrypted, key) {
  const bin = Buffer.from(encrypted, 'base64').toString('binary');
  let out = '';
  for (let i = 0; i < bin.length; i++) {
    out += String.fromCharCode(bin.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

// ----------------- API 1: Create -----------------
app.post('/api/code', async (req, res) => {
    try {
        const { data } = req.body;
        if (!data) {
            return res.status(400).json({ error: 'Missing data' });
        }

        // فكّ التشفير
        let decoded;
        try {
            decoded = decryptData(data, ENCRYPTION_KEY);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid encrypted data', detail: e.message });
        }

        // قطع على الأجزاء (فرضنا ديما 4 أجزاء)
        const parts = decoded.split(',');
        if (parts.length !== 4) {
            return res.status(400).json({ error: 'Invalid data format' });
        }
        const [ email, user_id, transaction_id, ip ] = parts;

        // حذف أي عنصر موجود بنفس الإيميل
        await Data.deleteMany({ email });

        // إنشاء عنصر جديد
        const doc = new Data({
            email,
            info: { user_id, transaction_id, ip },
            result: null
        });

        await doc.save();
        return res.status(201).json({ success: true, id: doc._id });
    } catch (err) {
        console.error('POST /api/code → Server error:', err);
        return res.status(500).json({ error: 'Server error', detail: err.message });
    }
});


// ----------------- API 2: Poll & Delete -----------------
app.get('/api/code/:email', async (req, res) => {
  try {
    const email = req.params.email;

    // atomic find+delete على آخر doc فيها نتيجة
    const doc = await Data.findOneAndDelete(
      { email, result: { $ne: null } },
      { sort: { createdAt: -1 } }
    );

    if (doc) {
      console.log(`GET /api/code/${email} → returning result`);
      return res.status(200).json({ result: doc.result });
    }

    // مازال كاين doc معلق
    const anyDoc = await Data.findOne({ email });
    if (anyDoc) {
      return res.sendStatus(204);
    }

    // ما كاين حتى doc
    return res.status(404).json({ error: 'Not found' });
  } catch (err) {
    console.error(`GET /api/code/${req.params.email} → Server error:`, err);
    return res.status(500).json({ error: 'Server error', detail: err.message });
  }
});



























// --- Helpers: XOR + Base64 encryption/decryption using key 'SCARE-SELFAI' ---
function encryptData(text, key) {
  // نص → binary string → XOR → base64
  const bin = Buffer.from(text, 'utf-8').toString('binary');
  let xored = '';
  for (let i = 0; i < bin.length; i++) {
    xored += String.fromCharCode(bin.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(xored, 'binary').toString('base64');
}

function decryptData1(encrypted, key) {
  // base64 → binary string → XOR → utf-8 text
  const bin = Buffer.from(encrypted, 'base64').toString('binary');
  let out = '';
  for (let i = 0; i < bin.length; i++) {
    out += String.fromCharCode(bin.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return Buffer.from(out, 'binary').toString('utf-8');
}

// --- API 3: جلب info (user_id, transaction_id, ip) مُشفّرة ---
/**
 * GET /api/code/info/:customID
 * - لو ما لقيناش doc → 404  
 * - لو لقيناه → 200 + { data: <encrypted(user_id,transaction_id,ip)> }
 */
app.get('/api/code/info/:customID', async (req, res) => {
  try {
    const { customID } = req.params;
    if (!customID) {
      return res.status(400).json({ error: 'Missing customID parameter' });
    }
    const doc = await Data.findOne({ customID });
    if (!doc) {
      return res.status(404).json({ error: 'Custom ID not found' });
    }

    const { user_id, transaction_id, ip } = doc.info;
    const combined = [user_id, transaction_id, ip].join(',');
    const encrypted = encryptData(combined, 'SCARE-SELFAI');

    return res.status(200).json({ data: encrypted });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

// --- API 4: استلام النتيجة المشفّرة وتخزينها في الحقل result ---
/**
 * POST /api/code/result
 * Body: { customID: string, data: <encrypted_result> }
 * - لو ناقص customID أو data → 400  
 * - يحاول يفك التشفير → لو فشل → 400  
 * - يحدّث الدكيومنت الموجود بالـ customID → result = decrypted  
 * - لو ما لقيناش doc → 404  
 * - لو نجح → 200 + { success: true }
 */
app.post('/api/code/result', async (req, res) => {
  try {
    const { customID, data } = req.body;
    if (!customID || !data) {
      return res.status(400).json({ error: 'Missing customID or data' });
    }

    // فكّ التشفير
    let result;
    try {
      result = decryptData1(data, 'SCARE-SELFAI');
    } catch (e) {
      return res.status(400).json({ error: 'Invalid encrypted data' });
    }

    // تحديث الحقل result
    const doc = await Data.findOneAndUpdate(
      { customID },
      { result },
      { new: true }
    );
    if (!doc) {
      return res.status(404).json({ error: 'Custom ID not found' });
    }

    return res.status(200).json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: err.message });
  }
});

















































app.post('/otp', (req, res) => {
    const { user, password } = req.body;
    const Imap = require('imap');
    const fs = require('fs');
    const base64 = require('buffer').Buffer;
    
    // إعداد بيانات الاتصال بخادم البريد الإلكتروني
    const imap = new Imap({
      user: user,  // البريد الإلكتروني الخاص بك
      password: password, // كلمة مرور التطبيقات (App Password) الخاصة بك
      host: 'imap.gmail.com',
      port: 993,
      tls: true,
      tlsOptions: {
        rejectUnauthorized: false // تجاوز التحقق من الشهادات غير الموثوقة
      },
      connTimeout: 90000, // زيادة المهلة إلى 30 ثانية
      authTimeout: 90000 // زيادة مهلة المصادقة إلى 30 ثانية
    });
    
    let lastUid = null;
    
    // فتح صندوق الوارد (Inbox)
    function openInbox(cb) {
      imap.openBox('INBOX', false, cb);
    }
    
    // بدء الاتصال بخادم البريد الإلكتروني
    imap.once('ready', function () {
      openInbox(function (err, box) {
        if (err) throw err;
    
        // الحصول على آخر UID للرسائل الموجودة حاليًا
        lastUid = box.uidnext;
        console.log('Waiting for new messages...');
    
        // مراقبة الرسائل الجديدة
        imap.on('mail', function () {
          console.log('New email received');
          imap.search(['UNSEEN'], function (err, results) {
            console.log('Searching for new unread messages...');
            if (err) throw err;
            if (results.length === 0) {
              console.log('No new unread messages found.');
              return;
            }
    
            // البحث عن أحدث رسالة فقط
            const latestEmail = Math.max(...results);
    
            const f = imap.fetch([latestEmail], { bodies: ['HEADER.FIELDS (FROM SUBJECT DATE)', 'TEXT'], struct: true });
            console.log('Fetching email...');
            f.on('message', function (msg, seqno) {
              let messageData = { seqno, headers: '', body: '' };
              msg.on('body', function (stream, info) {
                let buffer = '';
                stream.on('data', function (chunk) {
                  buffer += chunk.toString('utf8');
                });
                console.log('Reading email body...');
                stream.once('end', function () {
                  if (info.which === 'TEXT') {
                    // فك الترميز إذا كانت الرسالة مشفرة بـ Base64
                    buffer = buffer.trim();
                    if (/^[A-Za-z0-9+/=\r\n]+$/.test(buffer)) {
                      buffer = base64.from(buffer, 'base64').toString('utf8');
                    }
                    messageData.body = buffer;
    
                    // البحث عن OTP باستخدام regex
                    const otpMatch = buffer.match(/\b(\d{6})\b/);
                    if (otpMatch) {
                      const otp = otpMatch[1];
                      res.json({ otp });
                      console.log('Found OTP:', otp);
                      // حفظ OTP في ملف
                      fs.writeFileSync('otp.json', JSON.stringify({ otp: otp }, null, 2));
                      imap.end();
                    }
                  }
                });
              });
            });
            f.once('error', function (err) {
              console.log('Fetch error: ' + err);
            });
          });
        });
      });
    });
    
    imap.once('error', function (err) {
      console.log(err);
    });
    
    imap.once('end', function () {
      console.log('Connection ended');
    });
    
    // بدء الاتصال
    imap.connect();
    
});












































const blockedDevices = new mongoose.Schema({
  user: String,
  canvasFingerprint: String,
  webglFingerprint: String
});

const Blocked = mongoose.model('Blocked', blockedDevices);

app.post('/admin/block-device', async (req, res) => {
  const { user, canvas, webgl } = req.body;
  try {
    await Blocked.updateOne(
      { user, canvasFingerprint: canvas, webglFingerprint: webgl },
      { $set: { user, canvasFingerprint: canvas, webglFingerprint: webgl } },
      { upsert: true }
    );
    res.redirect('/admin');
  } catch (err) {
    console.error('فشل الحظر:', err);
    res.status(500).send('خطأ في الحظر');
  }
});

app.post('/admin/delete-device', async (req, res) => {
  const { user, canvas, webgl } = req.body;
  try {
    await User.deleteMany({
      user,
      canvasFingerprint: canvas,
      webglFingerprint: webgl
    });
    res.redirect('/admin');
  } catch (err) {
    console.error('فشل الحذف:', err);
    res.status(500).send('خطأ في الحذف');
  }
});

app.post('/user', async (req, res) => {
  const {
    user, password, userAgent, language, platform, ip,
    screenResolution, browserName, deviceMemory,
    hardwareConcurrency, timezone, cookieEnabled,
    javaEnabled, onlineStatus, canvasFingerprint,
    webglFingerprint, localStorageId
  } = req.body;

  const client = clients.find(c => c.user === user && c.password === password);

  if (!client) {
    return res.status(404).json({ success: false, message: 'المستخدم غير موجود أو كلمة المرور غير صحيحة' });
  }

  // تحقق من الحظر
  const isBlocked = await Blocked.findOne({
    user,
    canvasFingerprint,
    webglFingerprint
  });

  if (isBlocked) {
    return res.status(403).json({ success: false, message: 'تم حظر هذا الجهاز من استخدام الحساب' });
  }

  const timestamp = new Date().toISOString();

  const newUser = new User({
    user, password, timestamp, userAgent, language,
    platform, ip, screenResolution, browserName,
    deviceMemory, hardwareConcurrency, timezone,
    cookieEnabled, javaEnabled, onlineStatus,
    canvasFingerprint, webglFingerprint, localStorageId
  });

  try {
    await newUser.save();
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('حدث خطأ أثناء حفظ البيانات في قاعدة البيانات:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ البيانات' });
  }
});




























app.get('/admin', async (req, res) => {
  try {
    const users = await User.find().lean();

    // تجميع حسب user ثم الأجهزة
    const userMap = {};
    for (const entry of users) {
      const deviceKey = `${entry.canvasFingerprint}-${entry.webglFingerprint}`;
      if (!userMap[entry.user]) userMap[entry.user] = {};
      if (!userMap[entry.user][deviceKey]) userMap[entry.user][deviceKey] = [];
      userMap[entry.user][deviceKey].push(entry);
    }

    // HTML
    let html = `
    <html><head><meta charset="UTF-8">
    <style>
      body { font-family: Arial; background-color: #f4f4f4; padding: 20px; }
      h1 { text-align: center; }
      table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #fff; }
      th, td { border: 1px solid #ccc; padding: 10px; }
      th { background-color: #007bff; color: white; }
      .safe { color: green; font-weight: bold; }
      .warning { color: orange; font-weight: bold; }
      .suspicious { color: red; font-weight: bold; }
      .device-block-btn { background-color: crimson; color: white; padding: 5px; border: none; cursor: pointer; }
      .delete-device-btn { background-color: black; color: white; padding: 5px; border: none; cursor: pointer; }
    </style>
    <title>لوحة الإدارة</title></head><body>
    <h1>🛡️ مراقبة المستخدمين حسب الأجهزة</h1>`;

    for (const username in userMap) {
      html += `<h2>👤 المستخدم: ${username}</h2>`;
      html += `<table><thead><tr>
        <th>بصمة الجهاز</th><th>عدد الجلسات</th><th>آخر دخول</th><th>تفاصيل</th><th>الاشتباه</th><th>إجراءات</th>
      </tr></thead><tbody>`;

      for (const deviceKey in userMap[username]) {
        const sessions = userMap[username][deviceKey];
        const first = sessions[0];
        const last = sessions[sessions.length - 1];

        function calcSuspicion(f, l) {
          let score = 0;
          if (f.deviceMemory !== l.deviceMemory) score += 40;
          if (f.screenResolution !== l.screenResolution) score += 30;
          if (f.canvasFingerprint !== l.canvasFingerprint) score += 10;
          if (f.webglFingerprint !== l.webglFingerprint) score += 10;
          if (f.browserName !== l.browserName) score += 5;
          if (f.platform !== l.platform) score += 3;
          if (f.timezone !== l.timezone) score += 2;
          return score;
        }

        const suspicionScore = calcSuspicion(first, last);
        const statusClass = suspicionScore > 60 ? 'suspicious' : suspicionScore > 20 ? 'warning' : 'safe';
        const statusLabel = suspicionScore > 60 ? 'مشبوه جداً' : suspicionScore > 20 ? 'شبه مشبوه' : 'سليم';

        const canvas = first.canvasFingerprint ? first.canvasFingerprint.slice(0, 10) + '...' : 'غير متوفر';
        const webgl = first.webglFingerprint ? first.webglFingerprint.slice(0, 10) + '...' : 'غير متوفر';

        html += `<tr>
          <td>${canvas} - ${webgl}</td>
          <td>${sessions.length}</td>
          <td>${new Date(last.timestamp).toLocaleString()}</td>
          <td>
            <strong>RAM:</strong> ${last.deviceMemory || 'N/A'} GB<br>
            <strong>Screen:</strong> ${last.screenResolution || 'N/A'}<br>
            <strong>Browser:</strong> ${last.browserName || 'N/A'}<br>
            <strong>OS:</strong> ${last.platform || 'N/A'}<br>
          </td>
          <td class="${statusClass}">${statusLabel} (${suspicionScore}%)</td>
          <td>
            <form method="POST" action="/admin/block-device" style="display:inline">
              <input type="hidden" name="user" value="${first.user}" />
              <input type="hidden" name="canvas" value="${first.canvasFingerprint}" />
              <input type="hidden" name="webgl" value="${first.webglFingerprint}" />
              <button class="device-block-btn">🚫 حظر الجهاز</button>
            </form>
            <form method="POST" action="/admin/delete-device" style="display:inline">
              <input type="hidden" name="user" value="${first.user}" />
              <input type="hidden" name="canvas" value="${first.canvasFingerprint}" />
              <input type="hidden" name="webgl" value="${first.webglFingerprint}" />
              <button class="delete-device-btn">🗑 حذف السجلات</button>
            </form>
          </td>
        </tr>`;
      }

      html += `</tbody></table>`;
    }

    html += `</body></html>`;
    res.send(html);

  } catch (err) {
    console.error('خطأ:', err);
    res.status(500).send('خطأ في السيرفر');
  }
});




































app.delete('/delete/user', async (req, res) => {
  const { user } = req.body;
  try {
    await User.deleteMany({ user });
    res.status(200).json({ success: true, message: 'تم حذف جميع البيانات الخاصة بالمستخدم بنجاح' });
  } catch (error) {
    console.error('حدث خطأ أثناء حذف البيانات من قاعدة البيانات:', error);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حذف البيانات' });
  }
});

app.get('/UPDATEBOT', async (req, res) => {
    res.status(200).json({ success: false });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ الخادم يعمل الآن ويستمع على 0.0.0.0:${PORT}`);
});




let requestCount = 0; // العداد المبدئي

// إضافة مسار جديد يستقبل الطلبات ويزيد العداد
app.post('/receiveRequest', async (req, res) => {
    const { userId, userData } = req.body; // على افتراض أن البيانات المرفقة تأتي من المستخدم

    // التحقق من وجود البيانات
    if (!userId || !userData) {
        return res.status(400).json({
            success: false,
            message: 'جميع الحقول (userId, userData) مطلوبة.'
        });
    }

 
    // زيادة العداد
    requestCount++;

    // تخزين البيانات في قاعدة البيانات (اختياري حسب الحاجة)
    const newRequest = new User({
        user: userId,
        timestamp: new Date().toISOString(),
        data: userData,  // بيانات إضافية مرفقة بالطلب
    });

    try {
        // حفظ السجل في قاعدة البيانات
        await newRequest.save();

        // إرسال الاستجابة بعدد الرونديفو
        res.status(201).json({
            success: true,
        });
    } catch (error) {
        console.error('حدث خطأ أثناء معالجة الطلب:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ أثناء معالجة الطلب.',
            error: error.message
        });
    }
});

// مسار جديد لعرض عدد الرونديفو المحجوزة
app.get('/getRendezvousCount', (req, res) => {
    res.status(200).json({
        requestCount,  // إرجاع العداد الحالي
    });
});






app.get('/', (req, res) => {
  res.send('✅ Server is running on Fly.io!');
});
