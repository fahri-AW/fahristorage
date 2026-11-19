
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
import { pipeline } from "node:stream/promises";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const required = [
  "SESSION_SECRET",
  "ADMIN_USERNAME",
  "ADMIN_PASSWORD",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "TOKEN_ENCRYPTION_KEY",
  "DATABASE_URL"
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error(`Konfigurasi ${key} belum diisi di Vercel.`);
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

const categories = [
  "Skripsi",
  "Akademik",
  "Pekerjaan",
  "Pribadi",
  "Keuangan",
  "Foto & Gambar",
  "Lainnya"
];

/* =========================
   ENKRIPSI TOKEN GOOGLE
========================= */

function encrypt(value) {
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
}

function decrypt(value) {
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
}

/* =========================
   GOOGLE OAUTH
========================= */

const oauth = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const SCOPES = [
  "https://www.googleapis.com/auth/drive"
];

/*
 * Membuat koneksi Google Drive.
 * Refresh token lama tetap dipertahankan jika Google
 * tidak mengirimkan refresh token baru.
 */

function driveForTokens(tokens) {
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

      if (!row) return;

      const current = decrypt(row.value);

      const updated = {
        ...current,
        ...fresh,
        refresh_token:
          fresh.refresh_token || current.refresh_token
      };

      await run(
        "UPDATE settings SET value=? WHERE key='google_tokens'",
        [encrypt(updated)]
      );
    } catch (error) {
      console.error(
        "Gagal memperbarui token Google:",
        error.message
      );
    }
  });

  return google.drive({
    version: "v3",
    auth
  });
}

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

/* =========================
   FOLDER GOOGLE DRIVE
========================= */

async function getRootFolder(drive) {
  if (process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID) {
    return process.env.GOOGLE_DRIVE_ROOT_FOLDER_ID;
  }

  const setting = await get(
    "SELECT value FROM settings WHERE key='drive_root_folder'"
  );

  if (setting) {
    return setting.value;
  }

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

  const escapedName = category
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'");

  const found = await drive.files.list({
    q: `'${root}' in parents and name='${escapedName}' and mimeType='application/vnd.google-apps.folder' and trashed=false`,
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

/* =========================
   MIDDLEWARE
========================= */

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

app.use(express.json({
  limit: "1mb"
}));

app.use(express.urlencoded({
  extended: false
}));

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

/* =========================
   KEAMANAN REQUEST
========================= */

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

app.use([
  "/api/login",
  "/api/logout",
  "/api/upload",
  "/api/users"
], sameOrigin);

app.use("/api/files", (req, res, next) => {
  if (["POST", "PATCH", "DELETE"].includes(req.method)) {
    return sameOrigin(req, res, next);
  }

  next();
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
  return (
    user.role === "admin" ||
    String(file.uploaded_by) === String(user.id)
  );
}

function safeName(name) {
  return path.basename(name)
    .replace(/[\\/\0]/g, "_")
    .slice(0, 180);
}

/* =========================
   DATABASE BOOTSTRAP
========================= */

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
      `INSERT INTO users(username,password_hash,role)
       VALUES(?,?,'admin')`,
      [
        process.env.ADMIN_USERNAME,
        hash
      ]
    );

    console.log("Admin awal berhasil dibuat.");
  }
}

await initializeDatabase();
await bootstrap();

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    service: "DriveSpace Personal"
  });
});

app.get("/api/me", (req, res) => {
  res.json({
    user: req.session.user || null
  });
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const username = String(
      req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    const user = await get(
      "SELECT * FROM users WHERE username=? AND active=1",
      [username]
    );

    if (
      !user ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Username atau password salah."
      });
    }

    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({
          error: "Gagal membuat sesi."
        });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };

      req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({
            error: "Gagal menyimpan sesi."
          });
        }

        res.json({
          user: req.session.user
        });
      });
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Terjadi kesalahan saat login."
    });
  }
});

app.post("/api/logout", auth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");

    res.json({
      ok: true
    });
  });
});

/* =========================
   GOOGLE DRIVE OAUTH
========================= */

app.get("/auth/google", auth, admin, (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");

  req.session.googleOAuthState = state;

  req.session.save((error) => {
    if (error) {
      return res.status(500).send(
        "Gagal menyimpan sesi OAuth."
      );
    }

    res.redirect(oauth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: SCOPES,
      state
    }));
  });
});

app.get(
  "/auth/google/callback",
  auth,
  admin,
  async (req, res) => {
    try {
      if (
        !req.query.state ||
        req.query.state !== req.session.googleOAuthState
      ) {
        return res.status(400).send(
          "OAuth state tidak valid."
        );
      }

      delete req.session.googleOAuthState;

      const { tokens } = await oauth.getToken(
        String(req.query.code || "")
      );

      const old = await get(
        "SELECT value FROM settings WHERE key='google_tokens'"
      );

      const oldTokens = old
        ? decrypt(old.value)
        : {};

      const merged = {
        ...oldTokens,
        ...tokens,
        refresh_token:
          tokens.refresh_token || oldTokens.refresh_token
      };

      if (!merged.refresh_token) {
        throw new Error(
          "Google tidak memberikan refresh token. Cabut akses aplikasi dari Google Account, lalu hubungkan kembali."
        );
      }

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
    } catch (error) {
      console.error(
        "Google OAuth error:",
        error.message
      );

      res.status(500).send(
        "Gagal menghubungkan Google Drive. Periksa konfigurasi OAuth."
      );
    }
  }
);

/* =========================
   STATUS GOOGLE DRIVE
========================= */

app.get("/api/drive-status", auth, admin, async (_req, res) => {
  try {
    const row = await get(
      "SELECT value FROM settings WHERE key='google_tokens'"
    );

    res.json({
      connected: Boolean(row)
    });
  } catch (error) {
    console.error(
      "Drive status error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal memeriksa koneksi Google Drive."
    });
  }
});

/* =========================
   INFORMASI PENYIMPANAN
========================= */

app.get("/api/storage", auth, async (req, res) => {
  try {
    const [stats, folderStats] = await Promise.all([
      get(
        `SELECT
          COUNT(*) AS total_files,
          COALESCE(SUM(size), 0) AS total_size
         FROM files
         ${
           req.session.user.role === "admin"
             ? ""
             : "WHERE uploaded_by=?"
         }`,
        req.session.user.role === "admin"
          ? []
          : [req.session.user.id]
      ),

      all(
        `SELECT
          category,
          COUNT(*) AS total_files,
          COALESCE(SUM(size), 0) AS total_size
         FROM files
         ${
           req.session.user.role === "admin"
             ? ""
             : "WHERE uploaded_by=?"
         }
         GROUP BY category
         ORDER BY category`,
        req.session.user.role === "admin"
          ? []
          : [req.session.user.id]
      )
    ]);

    let storage = {
      used: null,
      driveUsed: null,
      limit: null,
      remaining: null,
      percentage: null,
      unlimited: false
    };

    let connected = false;
    let reconnectRequired = false;

    try {
      const drive = await getDrive();

      const about = await drive.about.get({
        fields: "storageQuota,user"
      });

      const quota = about.data.storageQuota || {};

      const used = Number(quota.usage || 0);
      const driveUsed = Number(quota.usageInDrive || 0);

      const limit = quota.limit
        ? Number(quota.limit)
        : null;

      storage = {
        used,
        driveUsed,
        limit,

        remaining:
          limit !== null
            ? Math.max(0, limit - used)
            : null,

        percentage:
          limit !== null && limit > 0
            ? Math.min(100, (used / limit) * 100)
            : null,

        unlimited: limit === null
      };

      connected = true;
    } catch (googleError) {
      const errorCode =
        googleError.response?.data?.error;

      console.error(
        "Google Drive storage error:",
        errorCode || googleError.message
      );

      reconnectRequired = [
        "invalid_grant",
        "invalid_token"
      ].includes(errorCode);
    }

    const folderMap = new Map(
      folderStats.map(folder => [
        folder.category,
        {
          name: folder.category,
          totalFiles: Number(folder.total_files),
          totalSize: Number(folder.total_size)
        }
      ])
    );

    const folderNames = [
      "Skripsi",
      "Akademik",
      "Pekerjaan",
      "Pribadi",
      "Keuangan",
      "Foto & Gambar",
      "Lainnya"
    ];

    const folders = [
      ...folderNames.map(name =>
        folderMap.get(name) || {
          name,
          totalFiles: 0,
          totalSize: 0
        }
      ),

      ...Array.from(folderMap.values()).filter(
        folder => !folderNames.includes(folder.name)
      )
    ];

    res.json({
      connected,
      reconnectRequired,

      storage,

      files: {
        total: Number(stats.total_files),
        totalSize: Number(stats.total_size)
      },

      folders
    });

  } catch (error) {
    console.error(
      "Storage information error:",
      error.message
    );

    res.status(500).json({
      connected: false,
      error: "Gagal mengambil informasi penyimpanan."
    });
  }
});

/* =========================
   DAFTAR KATEGORI
========================= */

app.get("/api/categories", auth, async (_req, res) => {
  try {
    const rows = await all(
      "SELECT DISTINCT category FROM files ORDER BY category"
    );

    const savedCategories = rows
      .map(row => row.category)
      .filter(Boolean);

    const result = [
      ...new Set([
        ...categories,
        ...savedCategories
      ])
    ];

    res.json(result);

  } catch (error) {
    console.error(
      "Category error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal mengambil daftar kategori."
    });
  }
});

/* =========================
   UPLOAD FILE
========================= */

app.post(
  "/api/upload",
  auth,
  upload.single("file"),
  async (req, res) => {
    let uploadedFileId = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Pilih file terlebih dahulu."
        });
      }

      const selectedCategory = String(
        req.body.category || ""
      ).trim();

      let category;

      if (
        categories.includes(selectedCategory) &&
        selectedCategory !== "Lainnya"
      ) {
        category = selectedCategory;

      } else if (selectedCategory === "Lainnya") {
        category = String(
          req.body.customCategory || ""
        ).trim();

        if (
          !category ||
          category.length > 80 ||
          /[\\/:*?"<>|]/.test(category)
        ) {
          return res.status(400).json({
            error: "Nama folder khusus tidak valid."
          });
        }

      } else {
        return res.status(400).json({
          error: "Kategori folder tidak valid."
        });
      }

      const drive = await getDrive();

      const folderId = await getCategoryFolder(
        drive,
        category
      );

      const originalName = safeName(
        req.file.originalname
      );

      /*
       * Google API membutuhkan stream.
       * Readable.from() digunakan agar Buffer
       * dapat dikirim sebagai stream.
       */

      const fileStream = Readable.from(
        req.file.buffer
      );

      const uploaded = await drive.files.create({
        requestBody: {
          name: originalName,
          parents: [folderId]
        },

        media: {
          mimeType:
            req.file.mimetype || "application/octet-stream",
          body: fileStream
        },

        fields: "id,name,mimeType,size,webViewLink"
      });

      uploadedFileId = uploaded.data.id;

      try {
        await run(
          `INSERT INTO files
           (drive_id,name,mime_type,size,category,uploaded_by,drive_url)
           VALUES(?,?,?,?,?,?,?)`,
          [
            uploaded.data.id,
            uploaded.data.name,

            uploaded.data.mimeType ||
              req.file.mimetype ||
              "application/octet-stream",

            Number(uploaded.data.size || req.file.size),
            category,
            req.session.user.id,
            uploaded.data.webViewLink || null
          ]
        );

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

      } catch (databaseError) {
        await drive.files.delete({
          fileId: uploadedFileId
        }).catch(() => {});

        throw databaseError;
      }

      res.json({
        ok: true,
        message: "File berhasil disimpan ke Google Drive.",

        file: {
          id: uploaded.data.id,
          name: uploaded.data.name,
          category
        }
      });

    } catch (error) {
      console.error(
        "Upload error:",
        error.message
      );

      res.status(500).json({
        error: error.message || "Upload gagal."
      });
    }
  }
);

/* =========================
   DAFTAR FILE
========================= */

app.get("/api/files", auth, async (req, res) => {
  try {
    const search = String(
      req.query.search || ""
    ).trim().slice(0, 100);

    const category = String(
      req.query.category || ""
    ).trim();

    const params = [];

    let sql = `
      SELECT f.*, u.username AS uploader
      FROM files f
      JOIN users u ON u.id = f.uploaded_by
      WHERE 1=1
    `;

    if (req.session.user.role !== "admin") {
      sql += " AND f.uploaded_by=?";
      params.push(req.session.user.id);
    }

    if (search) {
      sql += " AND f.name ILIKE ?";
      params.push(`%${search}%`);
    }

    if (category) {
      sql += " AND f.category=?";
      params.push(category);
    }

    sql += " ORDER BY f.created_at DESC LIMIT 300";

    const rows = await all(sql, params);

    res.json(rows);

  } catch (error) {
    console.error(
      "File list error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal mengambil daftar file."
    });
  }
});

/* =========================
   GOOGLE DRIVE OAUTH
========================= */

app.get("/auth/google", auth, admin, (req, res) => {
  const state = crypto.randomBytes(24).toString("hex");

  req.session.googleOAuthState = state;

  req.session.save((error) => {
    if (error) {
      return res.status(500).send(
        "Gagal menyimpan sesi OAuth."
      );
    }

    res.redirect(oauth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: SCOPES,
      state
    }));
  });
});

app.get(
  "/auth/google/callback",
  auth,
  admin,
  async (req, res) => {
    try {
      if (
        !req.query.state ||
        req.query.state !== req.session.googleOAuthState
      ) {
        return res.status(400).send(
          "OAuth state tidak valid."
        );
      }

      delete req.session.googleOAuthState;

      const { tokens } = await oauth.getToken(
        String(req.query.code || "")
      );

      const old = await get(
        "SELECT value FROM settings WHERE key='google_tokens'"
      );

      const oldTokens = old
        ? decrypt(old.value)
        : {};

      const merged = {
        ...oldTokens,
        ...tokens,
        refresh_token:
          tokens.refresh_token || oldTokens.refresh_token
      };

      if (!merged.refresh_token) {
        throw new Error(
          "Google tidak memberikan refresh token. Cabut akses aplikasi dari Google Account, lalu hubungkan kembali."
        );
      }

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
    } catch (error) {
      console.error(
        "Google OAuth error:",
        error.message
      );

      res.status(500).send(
        "Gagal menghubungkan Google Drive. Periksa konfigurasi OAuth."
      );
    }
  }
);

/* =========================
   STATUS GOOGLE DRIVE
========================= */

app.get("/api/drive-status", auth, admin, async (_req, res) => {
  try {
    const row = await get(
      "SELECT value FROM settings WHERE key='google_tokens'"
    );

    res.json({
      connected: Boolean(row)
    });
  } catch (error) {
    console.error(
      "Drive status error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal memeriksa koneksi Google Drive."
    });
  }
});

/* =========================
   INFORMASI PENYIMPANAN
========================= */

app.get("/api/storage", auth, async (req, res) => {
  try {
    const [stats, folderStats] = await Promise.all([
      get(
        `SELECT
          COUNT(*) AS total_files,
          COALESCE(SUM(size), 0) AS total_size
         FROM files
         ${
           req.session.user.role === "admin"
             ? ""
             : "WHERE uploaded_by=?"
         }`,
        req.session.user.role === "admin"
          ? []
          : [req.session.user.id]
      ),

      all(
        `SELECT
          category,
          COUNT(*) AS total_files,
          COALESCE(SUM(size), 0) AS total_size
         FROM files
         ${
           req.session.user.role === "admin"
             ? ""
             : "WHERE uploaded_by=?"
         }
         GROUP BY category
         ORDER BY category`,
        req.session.user.role === "admin"
          ? []
          : [req.session.user.id]
      )
    ]);

    let storage = {
      used: null,
      driveUsed: null,
      limit: null,
      remaining: null,
      percentage: null,
      unlimited: false
    };

    let connected = false;
    let reconnectRequired = false;

    try {
      const drive = await getDrive();

      const about = await drive.about.get({
        fields: "storageQuota,user"
      });

      const quota = about.data.storageQuota || {};

      const used = Number(quota.usage || 0);
      const driveUsed = Number(quota.usageInDrive || 0);

      const limit = quota.limit
        ? Number(quota.limit)
        : null;

      storage = {
        used,
        driveUsed,
        limit,

        remaining:
          limit !== null
            ? Math.max(0, limit - used)
            : null,

        percentage:
          limit !== null && limit > 0
            ? Math.min(100, (used / limit) * 100)
            : null,

        unlimited: limit === null
      };

      connected = true;
    } catch (googleError) {
      const errorCode =
        googleError.response?.data?.error;

      console.error(
        "Google Drive storage error:",
        errorCode || googleError.message
      );

      reconnectRequired = [
        "invalid_grant",
        "invalid_token"
      ].includes(errorCode);
    }

    const folderMap = new Map(
      folderStats.map(folder => [
        folder.category,
        {
          name: folder.category,
          totalFiles: Number(folder.total_files),
          totalSize: Number(folder.total_size)
        }
      ])
    );

    const folderNames = [
      "Skripsi",
      "Akademik",
      "Pekerjaan",
      "Pribadi",
      "Keuangan",
      "Foto & Gambar",
      "Lainnya"
    ];

    const folders = [
      ...folderNames.map(name =>
        folderMap.get(name) || {
          name,
          totalFiles: 0,
          totalSize: 0
        }
      ),

      ...Array.from(folderMap.values()).filter(
        folder => !folderNames.includes(folder.name)
      )
    ];

    res.json({
      connected,
      reconnectRequired,

      storage,

      files: {
        total: Number(stats.total_files),
        totalSize: Number(stats.total_size)
      },

      folders
    });

  } catch (error) {
    console.error(
      "Storage information error:",
      error.message
    );

    res.status(500).json({
      connected: false,
      error: "Gagal mengambil informasi penyimpanan."
    });
  }
});

/* =========================
   DAFTAR KATEGORI
========================= */

app.get("/api/categories", auth, async (_req, res) => {
  try {
    const rows = await all(
      "SELECT DISTINCT category FROM files ORDER BY category"
    );

    const savedCategories = rows
      .map(row => row.category)
      .filter(Boolean);

    const result = [
      ...new Set([
        ...categories,
        ...savedCategories
      ])
    ];

    res.json(result);

  } catch (error) {
    console.error(
      "Category error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal mengambil daftar kategori."
    });
  }
});

/* =========================
   UPLOAD FILE
========================= */

app.post(
  "/api/upload",
  auth,
  upload.single("file"),
  async (req, res) => {
    let uploadedFileId = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Pilih file terlebih dahulu."
        });
      }

      const selectedCategory = String(
        req.body.category || ""
      ).trim();

      let category;

      if (
        categories.includes(selectedCategory) &&
        selectedCategory !== "Lainnya"
      ) {
        category = selectedCategory;

      } else if (selectedCategory === "Lainnya") {
        category = String(
          req.body.customCategory || ""
        ).trim();

        if (
          !category ||
          category.length > 80 ||
          /[\\/:*?"<>|]/.test(category)
        ) {
          return res.status(400).json({
            error: "Nama folder khusus tidak valid."
          });
        }

      } else {
        return res.status(400).json({
          error: "Kategori folder tidak valid."
        });
      }

      const drive = await getDrive();

      const folderId = await getCategoryFolder(
        drive,
        category
      );

      const originalName = safeName(
        req.file.originalname
      );

      /*
       * Google API membutuhkan stream.
       * Readable.from() digunakan agar Buffer
       * dapat dikirim sebagai stream.
       */

      const fileStream = Readable.from(
        req.file.buffer
      );

      const uploaded = await drive.files.create({
        requestBody: {
          name: originalName,
          parents: [folderId]
        },

        media: {
          mimeType:
            req.file.mimetype || "application/octet-stream",
          body: fileStream
        },

        fields: "id,name,mimeType,size,webViewLink"
      });

      uploadedFileId = uploaded.data.id;

      try {
        await run(
          `INSERT INTO files
           (drive_id,name,mime_type,size,category,uploaded_by,drive_url)
           VALUES(?,?,?,?,?,?,?)`,
          [
            uploaded.data.id,
            uploaded.data.name,

            uploaded.data.mimeType ||
              req.file.mimetype ||
              "application/octet-stream",

            Number(uploaded.data.size || req.file.size),
            category,
            req.session.user.id,
            uploaded.data.webViewLink || null
          ]
        );

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

      } catch (databaseError) {
        await drive.files.delete({
          fileId: uploadedFileId
        }).catch(() => {});

        throw databaseError;
      }

      res.json({
        ok: true,
        message: "File berhasil disimpan ke Google Drive.",

        file: {
          id: uploaded.data.id,
          name: uploaded.data.name,
          category
        }
      });

    } catch (error) {
      console.error(
        "Upload error:",
        error.message
      );

      res.status(500).json({
        error: error.message || "Upload gagal."
      });
    }
  }
);

/* =========================
   DAFTAR FILE
========================= */

app.get("/api/files", auth, async (req, res) => {
  try {
    const search = String(
      req.query.search || ""
    ).trim().slice(0, 100);

    const category = String(
      req.query.category || ""
    ).trim();

    const params = [];

    let sql = `
      SELECT f.*, u.username AS uploader
      FROM files f
      JOIN users u ON u.id = f.uploaded_by
      WHERE 1=1
    `;

    if (req.session.user.role !== "admin") {
      sql += " AND f.uploaded_by=?";
      params.push(req.session.user.id);
    }

    if (search) {
      sql += " AND f.name ILIKE ?";
      params.push(`%${search}%`);
    }

    if (category) {
      sql += " AND f.category=?";
      params.push(category);
    }

    sql += " ORDER BY f.created_at DESC LIMIT 300";

    const rows = await all(sql, params);

    res.json(rows);

  } catch (error) {
    console.error(
      "File list error:",
      error.message
    );

    res.status(500).json({
      error: "Gagal mengambil daftar file."
    });
  }
});
