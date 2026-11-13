
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

    // Mendukung kategori bawaan dan folder khusus.
    if (category) {
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

    if (!res.headersSent) {
      res.status(500).send("Gagal membuka preview.");
    } else {
      res.destroy(e);
    }
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

    if (!res.headersSent) {
      res.status(500).send("Download gagal.");
    } else {
      res.destroy(e);
    }
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

// MANAJEMEN AKUN
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

// ERROR HANDLER
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
