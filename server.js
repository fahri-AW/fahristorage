import "dotenv/config";
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { pool, initializeDatabase, run, get, all } from "./db.js";
import bcrypt from "bcryptjs";
import multer from "multer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { google } from "googleapis";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Readable } from "node:stream";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const required = [
  "SESSION_SECRET",
  "ADMIN_USERNAME",
  "ADMIN_PASSWORD",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "TOKEN_ENCRYPTION_KEY"
];

for (const key of required) {
  if (!process.env[key]) {
    console.error(`Konfigurasi ${key} belum diisi.`);
    process.exit(1);
  }
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET harus minimal 32 karakter.");
}

if (!/^[a-fA-F0-9]{64}$/.test(process.env.TOKEN_ENCRYPTION_KEY)) {
  throw new Error("TOKEN_ENCRYPTION_KEY harus 64 karakter hex.");
}

const app = express();
const PORT = Number(process.env.PORT || 3000);

const maxFileBytes =
  Number(process.env.MAX_FILE_SIZE_MB || (process.env.VERCEL ? 4 : 50)) *
  1024 * 1024;

const PgSessionStore = connectPgSimple(session);

const encrypt = (value) => {
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, "hex"),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value)),
    cipher.final()
  ]);

  return Buffer.concat([
    iv,
    cipher.getAuthTag(),
    encrypted
  ]).toString("base64");
};

const decrypt = (value) => {
  const data = Buffer.from(value, "base64");

  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const encrypted = data.subarray(28);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(process.env.TOKEN_ENCRYPTION_KEY, "hex"),
    iv
  );

  decipher.setAuthTag(tag);

  return JSON.parse(
    Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]).toString()
  );
};

const oauth = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = [
  "https://www.googleapis.com/auth/drive"
];

const driveForTokens = (tokens) => {
  const auth = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  auth.setCredentials(tokens);

  auth.on("tokens", async (fresh) => {
    try {
      const row = await get(
        "SELECT value FROM settings WHERE key='google_tokens'"
      );

      if (row) {
        const current = decrypt(row.value);

        await run(
          "UPDATE settings SET value=? WHERE key='google_tokens'",
          [encrypt({ ...current, ...fresh })]
        );
      }
    } catch (e) {
      console.error("Gagal memperbarui token Google:", e.message);
    }
  });

  return google.drive({
    version: "v3",
    auth
  });
};

async function getDrive() {
  const row = await get(
    "SELECT value FROM settings WHERE key='google_tokens'"
  );

  if (!row) {
    throw new Error(
      "Google Drive belum dihubungkan oleh administrator."
    );
  }

  return driveForTokens(decrypt(row.value));
}

async function getRootFolder(drive) {
  if (process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID) {
    return process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID;
  }

  const setting = await get(
    "SELECT value FROM settings WHERE key='drive_root_folder'"
  );

  if (setting) return setting.value;

  const created = await drive.files.create({
    requestBody: {
      name: "Drive Storage Personal",
      mimeType: "application/vnd.google-apps.folder"
    },
    fields: "id"
  });

  await run(
    `INSERT INTO settings(key,value)
     VALUES('drive_root_folder',?)
     ON CONFLICT(key)
     DO UPDATE SET value=EXCLUDED.value`,
    [created.data.id]
  );

  return created.data.id;
}

async function getCategoryFolder(drive, category) {
  const root = await getRootFolder(drive);

  const safeName = category
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'");

  const found = await drive.files.list({
    q: `'${root}' in parents and name='${safeName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
    fields: "files(id,name)",
    pageSize: 1
  });

  if (found.data.files?.length) {
    return found.data.files[0].id;
  }

  const created = await drive.files.create({
    requestBody: {
      name: category,
      mimeType: "application/vnd.google-apps.folder",
      parents: [root]
    },
    fields: "id"
  });

  return created.data.id;
}

app.disable("x-powered-by");
app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'self'"],
      frameAncestors: ["'self'"]
    }
  },
  crossOriginResourcePolicy: {
    policy: "same-site"
  }
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

app.use(session({
  store: new PgSessionStore({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});

app.use(express.static(
  path.join(__dirname, "public"),
  {
    index: "index.html",
    etag: true
  }
));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: maxFileBytes,
    files: 1
  }
});

const categories = [
  "Skripsi",
  "Akademik",
  "Pekerjaan",
  "Pribadi",
  "Keuangan",
  "Foto & Gambar",
  "Lainnya"
];

function sameOrigin(req, res, next) {
  const origin = req.get("origin");

  if (origin) {
    try {
      if (new URL(origin).host !== req.get("host")) {
        return res.status(403).json({
          error: "Asal permintaan tidak diizinkan."
        });
      }
    } catch {
      return res.status(403).json({
        error: "Header Origin tidak valid."
      });
    }
  }

  next();
}

app.use(
  ["/api/login", "/api/logout", "/api/upload", "/api/users"],
  sameOrigin
);

app.use("/api/files", (req, res, next) => {
  return ["POST", "PATCH", "DELETE"].includes(req.method)
    ? sameOrigin(req, res, next)
    : next();
});

function auth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "Silakan login terlebih dahulu."
    });
  }

  next();
}

function admin(req, res, next) {
  if (req.session.user?.role !== "admin") {
    return res.status(403).json({
      error: "Akses khusus admin."
    });
  }

  next();
}

function canAccessFile(user, file) {
  return user.role === "admin" ||
    String(file.uploaded_by) === String(user.id);
}

function safeName(name) {
  return path.basename(name)
    .replace(/[\\/\0]/g, "_")
    .slice(0, 180);
}

async function bootstrap() {
  const existing = await get(
    "SELECT id FROM users WHERE username=?",
    [process.env.ADMIN_USERNAME]
  );

  if (!existing) {
    const hash = await bcrypt.hash(
      process.env.ADMIN_PASSWORD,
      12
    );

    await run(
      "INSERT INTO users(username,password_hash,role) VALUES(?,?,'admin')",
      [process.env.ADMIN_USERNAME, hash]
    );

    console.log(
      `Admin awal dibuat: ${process.env.ADMIN_USERNAME}`
    );
  }
}

await initializeDatabase();
await bootstrap();

app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const user = await get(
      "SELECT * FROM users WHERE username=? AND active=1",
      [username]
    );

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Username atau password salah."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({
          error: "Gagal membuat sesi."
        });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      res.json({
        user: req.session.user
      });
    });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Terjadi kesalahan saat login."
    });
  }
});

app.post("/api/logout", auth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
  });
});

// Google Drive OAuth
app.get("/auth/google", auth, admin, (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");

  req.session.googleOAuthState = state;

  res.redirect(oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state
  }));
});

app.get("/auth/google/callback", auth, admin, async (req, res) => {
  try {
    if (
      !req.query.state ||
      req.query.state !== req.session.googleOAuthState
    ) {
      return res.status(400).send("OAuth state tidak valid.");
    }

    delete req.session.googleOAuthState;

    const { tokens } = await oauth.getToken(
      String(req.query.code || "")
    );

    const old = await get(
      "SELECT value FROM settings WHERE key='google_tokens'"
    );

    const merged = old
      ? { ...decrypt(old.value), ...tokens }
      : tokens;

    await run(
      `INSERT INTO settings(key,value)
       VALUES('google_tokens',?)
       ON CONFLICT(key)
       DO UPDATE SET value=EXCLUDED.value`,
      [encrypt(merged)]
    );

    const drive = driveForTokens(merged);

    await getRootFolder(drive);

    res.redirect("/?drive=connected");
  } catch (e) {
    console.error("Google OAuth callback error:", e);

    res.status(500).send(
      "Gagal menghubungkan Google Drive. Periksa konfigurasi OAuth."
    );
  }
});

app.get("/api/drive-status", auth, admin, async (_req, res) => {
  const row = await get(
    "SELECT value FROM settings WHERE key='google_tokens'"
  );

  res.json({
    connected: Boolean(row)
  });
});

app.get("/api/categories", auth, async (_req, res) => {
  try {
    const rows = await all(
      "SELECT DISTINCT category FROM files ORDER BY category"
    );

    const savedCategories = rows
      .map(row => row.category)
      .filter(Boolean);

    const result = [...new Set([
      ...categories,
      ...savedCategories
    ])];

    res.json(result);
  } catch (error) {
    console.error("Gagal mengambil kategori:", error);
    res.status(500).json({ error: "Gagal mengambil daftar kategori." });
  }
});

// UPLOAD GOOGLE DRIVE
app.post("/api/upload", auth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "Pilih file terlebih dahulu."
      });
    }

    const category = categories.includes(req.body.category)
      ? req.body.category
      : "Lainnya";

    const drive = await getDrive();
    const folderId = await getCategoryFolder(drive, category);
    const originalName = safeName(req.file.originalname);

    const uploaded = await drive.files.create({
      requestBody: {
        name: originalName,
        parents: [folderId]
      },
      media: {
        mimeType: req.file.mimetype || "application/octet-stream",
        body: Readable.from([req.file.buffer])
      },
      fields: "id,name,mimeType,size,webViewLink"
    });

    try {
      await run(
        `INSERT INTO files
         (drive_id,name,mime_type,size,category,uploaded_by,drive_url)
         VALUES(?,?,?,?,?,?,?)`,
        [
          uploaded.data.id,
          uploaded.data.name,
          uploaded.data.mimeType || req.file.mimetype,
          Number(uploaded.data.size || req.file.size),
          category,
          req.session.user.id,
          uploaded.data.webViewLink || null
        ]
      );
    } catch (dbError) {
      await drive.files.delete({
        fileId: uploaded.data.id
      }).catch(() => {});

      throw dbError;
    }

    await run(
      `INSERT INTO upload_history
       (file_name,category,action,user_id)
       VALUES(?,?,?,?)`,
      [
        originalName,
        category,
        "UPLOAD",
        req.session.user.id
      ]
    );

    res.json({
      ok: true,
      message: "File tersimpan di Google Drive.",
      file: {
        id: uploaded.data.id,
        name: uploaded.data.name,
        category
      }
    });

  } catch (e) {
    console.error("Upload error:", e);

    res.status(500).json({
      error: e.message || "Upload gagal."
    });
  }
});

app.get("/api/files", auth, async (req, res) => {
  try {
    const search = String(req.query.search || "")
      .trim()
      .slice(0, 100);

    const category = String(req.query.category || "").trim();
    const params = [];

    let sql = `
      SELECT f.*, u.username AS uploader
      FROM files f
      JOIN users u ON u.id=f.uploaded_by
      WHERE 1=1
    `;

    if (req.session.user.role !== "admin") {
      sql += " AND f.uploaded_by=?";
      params.push(req.session.user.id);
    }

    if (search) {
      sql += " AND f.name LIKE ?";
      params.push(`%${search}%`);
    }

    if (category && categories.includes(category)) {
      sql += " AND f.category=?";
      params.push(category);
    }

    sql += " ORDER BY f.created_at DESC LIMIT 300";

    const rows = await all(sql, params);

    res.json(rows);
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Gagal mengambil daftar file."
    });
  }
});

app.get("/api/files/:id/preview", auth, async (req, res) => {
  try {
    const file = await get(
      "SELECT * FROM files WHERE id=?",
      [req.params.id]
    );

    if (!file || !canAccessFile(req.session.user, file)) {
      return res.status(404).send("File tidak ditemukan.");
    }

    const allowed =
      file.mime_type === "application/pdf" ||
      [
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/bmp"
      ].includes(file.mime_type);

    if (!allowed) {
      return res.status(415).send(
        "Preview hanya tersedia untuk PDF dan gambar."
      );
    }

    const drive = await getDrive();

    const result = await drive.files.get(
      {
        fileId: file.drive_id,
        alt: "media"
      },
      {
        responseType: "stream"
      }
    );

    res.setHeader("Content-Type", file.mime_type);
    res.setHeader(
      "Content-Disposition",
      `inline; filename*=UTF-8''${encodeURIComponent(file.name)}`
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; sandbox"
    );

    result.data.pipe(res);
  } catch (e) {
    console.error(e);
    res.status(500).send("Gagal membuka preview.");
  }
});

app.get("/api/files/:id/download", auth, async (req, res) => {
  try {
    const file = await get(
      "SELECT * FROM files WHERE id=?",
      [req.params.id]
    );

    if (!file || !canAccessFile(req.session.user, file)) {
      return res.status(404).send("File tidak ditemukan.");
    }

    const drive = await getDrive();

    const result = await drive.files.get(
      {
        fileId: file.drive_id,
        alt: "media"
      },
      {
        responseType: "stream"
      }
    );

    res.setHeader(
      "Content-Type",
      file.mime_type || "application/octet-stream"
    );

    res.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodeURIComponent(file.name)}`
    );

    res.setHeader("X-Content-Type-Options", "nosniff");

    result.data.pipe(res);
  } catch (e) {
    console.error(e);
    res.status(500).send("Download gagal.");
  }
});

app.delete("/api/files/:id", auth, async (req, res) => {
  try {
    const file = await get(
      "SELECT * FROM files WHERE id=?",
      [req.params.id]
    );

    if (!file || !canAccessFile(req.session.user, file)) {
      return res.status(404).json({
        error: "File tidak ditemukan."
      });
    }

    const drive = await getDrive();

    await drive.files.delete({
      fileId: file.drive_id
    });

    await run(
      "DELETE FROM files WHERE id=?",
      [file.id]
    );

    await run(
      `INSERT INTO upload_history
       (file_name,category,action,user_id)
       VALUES(?,?,?,?)`,
      [
        file.name,
        file.category,
        "DELETE",
        req.session.user.id
      ]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Gagal menghapus file."
    });
  }
});

app.get("/api/history", auth, async (req, res) => {
  try {
    const params = [];

    let sql = `
      SELECT h.*, u.username
      FROM upload_history h
      JOIN users u ON u.id=h.user_id
    `;

    if (req.session.user.role !== "admin") {
      sql += " WHERE h.user_id=?";
      params.push(req.session.user.id);
    }

    sql += " ORDER BY h.created_at DESC LIMIT 100";

    res.json(await all(sql, params));
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Gagal mengambil riwayat."
    });
  }
});

// Manajemen akun
app.get("/api/users", auth, admin, async (_req, res) => {
  const users = await all(
    "SELECT id,username,role,active,created_at FROM users ORDER BY id"
  );

  res.json(users);
});

app.post("/api/users", auth, admin, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    const role = req.body.role === "admin" ? "admin" : "user";

    if (!/^[a-zA-Z0-9._-]{3,30}$/.test(username)) {
      return res.status(400).json({
        error: "Username 3-30 karakter: huruf, angka, titik, _ atau -."
      });
    }

    if (password.length < 10) {
      return res.status(400).json({
        error: "Password minimal 10 karakter."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    await run(
      "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
      [username, hash, role]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);

    res.status(400).json({
      error: e.message.includes("UNIQUE")
        ? "Username sudah digunakan."
        : "Gagal membuat pengguna."
    });
  }
});

app.patch("/api/users/:id", auth, admin, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (id === Number(req.session.user.id)) {
      return res.status(400).json({
        error: "Admin tidak dapat menonaktifkan akunnya sendiri."
      });
    }

    const target = await get(
      "SELECT id FROM users WHERE id=?",
      [id]
    );

    if (!target) {
      return res.status(404).json({
        error: "Pengguna tidak ditemukan."
      });
    }

    await run(
      "UPDATE users SET active=? WHERE id=?",
      [req.body.active ? 1 : 0, id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);

    res.status(500).json({
      error: "Gagal memperbarui pengguna."
    });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      error: err.code === "LIMIT_FILE_SIZE"
        ? `Ukuran file melebihi batas ${process.env.MAX_FILE_SIZE_MB || 4} MB.`
        : err.message
    });
  }

  console.error(err);

  res.status(500).json({
    error: "Terjadi kesalahan pada server."
  });
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(
      `Drive Storage berjalan di ${
        process.env.APP_BASE_URL || `http://localhost:${PORT}`
      }`
    );
  });
}

export default app;
