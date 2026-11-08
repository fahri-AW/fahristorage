# DriveSpace Personal - Vercel Edition

Aplikasi penyimpanan file dengan Google Drive sebagai media file dan PostgreSQL sebagai penyimpan akun, metadata, token OAuth terenkripsi, serta session.

## Stack
- Node.js 20+
- Express 4
- PostgreSQL (Neon atau provider PostgreSQL lain)
- Google Drive API OAuth 2.0
- Vercel Functions
- express-session + connect-pg-simple

## Persiapan
1. Buat database PostgreSQL di Neon: https://neon.tech/
2. Salin pooled connection string PostgreSQL.
3. Buat OAuth Client ID bertipe Web application di Google Cloud.
4. Aktifkan Google Drive API.
5. Tambahkan Authorized redirect URI:
   `https://fahristorage.vercel.app/auth/google/callback`
6. Pastikan OAuth consent screen mengizinkan akun Google yang akan dipakai. Jika status Testing, tambahkan akun sebagai Test User.

## Deploy melalui GitHub
1. Buat repository GitHub baru, misalnya `fahristorage`.
2. Upload seluruh isi folder proyek ini ke root repository.
3. Jangan upload `.env`, file JSON kredensial, `node_modules`, atau folder `data`.
4. Hubungkan repository ke project Vercel `fahristorage`.
5. Pada Vercel, buka Settings > Environment Variables dan isi variabel dari `.env.example`.
6. Pastikan `DATABASE_URL` menggunakan connection string PostgreSQL yang valid.
7. Deploy ulang dari Vercel.

## Environment variables
- `DATABASE_URL`: PostgreSQL connection string.
- `SESSION_SECRET`: random secret minimal 32 karakter.
- `TOKEN_ENCRYPTION_KEY`: tepat 64 karakter hexadecimal (32 byte).
- `ADMIN_USERNAME`, `ADMIN_PASSWORD`: akun admin pertama.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`: OAuth credentials.
- `GOOGLE_REDIRECT_URI`: `https://fahristorage.vercel.app/auth/google/callback`.
- `APP_BASE_URL`: `https://fahristorage.vercel.app`.
- `NODE_ENV`: `production`.
- `MAX_FILE_SIZE_MB`: batas upload. Untuk Vercel gunakan 4 MB karena batas payload function Vercel sekitar 4.5 MB termasuk multipart. Untuk file besar, perlu desain upload langsung/resumable ke Google Drive atau backend terpisah.

Generate secret secara lokal:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Gunakan hasil pertama untuk `SESSION_SECRET`, hasil kedua untuk `TOKEN_ENCRYPTION_KEY`.

## Lokal
```bash
npm install
copy .env.example .env
# Isi .env dengan kredensial dan DATABASE_URL
npm run check
npm start
```
Buka http://localhost:3000.

Untuk pengujian OAuth lokal, ubah `GOOGLE_REDIRECT_URI` menjadi
`http://localhost:3000/auth/google/callback` dan tambahkan URI tersebut ke Google Cloud.

## Catatan
- Database PostgreSQL dibuat otomatis saat fungsi pertama kali dijalankan.
- Session disimpan di PostgreSQL.
- File disimpan di Google Drive.
- Jangan commit `.env` atau kredensial.
- Untuk penggunaan publik, lakukan pengujian end-to-end dan tinjauan keamanan sebelum membagikan domain.
