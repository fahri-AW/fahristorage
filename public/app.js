const $ = (s) => document.querySelector(s);
let currentUser = null;
let allCategories = [];
let searchTimer = null;

async function api(url, options = {}) {
  const response = await fetch(url, { credentials: "same-origin", ...options });
  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json") ? await response.json() : null;
  if (!response.ok) throw new Error(data?.error || `Permintaan gagal (${response.status})`);
  return data;
}
function formatSize(bytes) {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let n = Number(bytes), i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}
function dateLabel(value) {
  if (!value) return "—";
  const d = new Date(value.replace(" ", "T") + (value.includes("Z") ? "" : "Z"));
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString("id-ID", {dateStyle:"medium",timeStyle:"short"});
}
function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function init() {
  try {
    const me = await api("/api/me");
    if (!me.user) return showLogin();
    currentUser = me.user;
    showApp();
  } catch { showLogin(); }
}
function showLogin() {
  $("#loginView").hidden = false;
  $("#appView").hidden = true;
}
async function showApp() {
  $("#loginView").hidden = true;
  $("#appView").hidden = false;
  $("#profileName").textContent = currentUser.username;
  $("#profileRole").textContent = currentUser.role;
  $("#avatar").textContent = currentUser.username.slice(0,1).toUpperCase();
  $("#usersNav").hidden = currentUser.role !== "admin";
  $("#connectDrive").hidden = currentUser.role !== "admin";
  await loadCategories();
  await loadFiles();
  if (currentUser.role === "admin") await checkDrive();
}
async function loadCategories() {
  allCategories = await api("/api/categories");
  const select = $("#categoryFilter");
  select.innerHTML = '<option value="">Semua kategori</option>' +
    allCategories.map(c => `<option value="${escapeHTML(c)}">${escapeHTML(c)}</option>`).join("");
}
async function loadFiles() {
  try {
    const params = new URLSearchParams();
    if ($("#searchInput").value.trim()) params.set("search", $("#searchInput").value.trim());
    if ($("#categoryFilter").value) params.set("category", $("#categoryFilter").value);
    const files = await api("/api/files?" + params.toString());
    $("#fileCount").textContent = files.length;
    $("#fileGrid").innerHTML = "";
    $("#emptyState").hidden = files.length > 0;
    for (const f of files) {
      const isPdf = f.mime_type === "application/pdf";
      const isImage = f.mime_type?.startsWith("image/");
      const icon = isPdf ? "PDF" : isImage ? "IMG" : "FILE";
      const card = document.createElement("article");
      card.className = "file-card";
      card.innerHTML = `
        <div class="file-top">
          <div class="file-icon ${isPdf ? "pdf" : isImage ? "image" : ""}">${icon}</div>
          <div class="file-menu">
            ${(isPdf || isImage) ? `<button data-action="preview" title="Pratinjau">◉</button>` : ""}
            <button data-action="download" title="Unduh">↓</button>
            <button data-action="delete" title="Hapus">⋯</button>
          </div>
        </div>
        <div class="file-name" title="${escapeHTML(f.name)}">${escapeHTML(f.name)}</div>
        <div class="file-meta"><span>${formatSize(f.size)}</span><span>${dateLabel(f.created_at)}</span></div>
        <span class="category-tag">${escapeHTML(f.category)}</span>
        ${currentUser.role === "admin" ? `<div class="file-meta" style="margin-top:10px">Diunggah oleh ${escapeHTML(f.uploader)}</div>` : ""}`;
      card.querySelectorAll("[data-action]").forEach(btn => btn.addEventListener("click", () => {
        const action = btn.dataset.action;
        if (action === "preview") previewFile(f);
        if (action === "download") location.href = `/api/files/${f.id}/download`;
        if (action === "delete") deleteFile(f);
      }));
      $("#fileGrid").append(card);
    }
  } catch (e) { toast(e.message, true); }
}
function toast(message, error = false) {
  const el = $("#uploadMessage");
  el.textContent = message;
  el.style.color = error ? "var(--red)" : "var(--green)";
}
async function uploadOne(file, category) {
  const form = new FormData();
  form.append("file", file);
  form.append("category", category);
  const response = await fetch("/api/upload", { method:"POST", body:form, credentials:"same-origin" });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "Upload gagal");
}
async function uploadFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  const category = prompt("Pilih kategori berikut:\n" + allCategories.join(", "), "Akademik") || "Lainnya";
  const selected = allCategories.includes(category) ? category : "Lainnya";
  $("#uploadProgress").hidden = false;
  $("#uploadProgress div").style.width = "0%";
  $("#chooseFile").disabled = true;
  try {
    for (let i = 0; i < files.length; i++) {
      toast(`Mengunggah ${files[i].name} (${i+1}/${files.length})...`);
      await uploadOne(files[i], selected);
      $("#uploadProgress div").style.width = `${Math.round((i+1)/files.length*100)}%`;
    }
    toast(`${files.length} file berhasil disimpan ke Google Drive.`);
    await loadFiles();
  } catch (e) { toast(e.message, true); }
  finally {
    $("#chooseFile").disabled = false;
    setTimeout(() => { $("#uploadProgress").hidden = true; }, 900);
    $("#fileInput").value = "";
  }
}
async function previewFile(file) {
  $("#previewTitle").textContent = file.name;
  const url = `/api/files/${file.id}/preview`;
  $("#previewContent").innerHTML = file.mime_type === "application/pdf"
    ? `<iframe title="Preview PDF" src="${url}"></iframe>`
    : `<img alt="${escapeHTML(file.name)}" src="${url}">`;
  $("#previewModal").hidden = false;
}
async function deleteFile(file) {
  if (!confirm(`Hapus "${file.name}" dari Google Drive?`)) return;
  try { await api(`/api/files/${file.id}`, { method:"DELETE" }); await loadFiles(); }
  catch(e) { alert(e.message); }
}
async function loadHistory() {
  const rows = await api("/api/history");
  $("#historyBody").innerHTML = rows.map(r => `<tr>
    <td><span class="${r.action === "UPLOAD" ? "status-active" : "status-off"}">${r.action === "UPLOAD" ? "↑ Upload" : "× Hapus"}</span></td>
    <td>${escapeHTML(r.file_name)}</td><td>${escapeHTML(r.category)}</td>
    <td>${escapeHTML(r.username)}</td><td>${dateLabel(r.created_at)}</td></tr>`).join("") ||
    '<tr><td colspan="5">Belum ada aktivitas.</td></tr>';
}
async function loadUsers() {
  const users = await api("/api/users");
  $("#usersBody").innerHTML = users.map(u => `<tr>
    <td>${escapeHTML(u.username)}</td><td>${u.role}</td>
    <td class="${u.active ? "status-active" : "status-off"}">${u.active ? "Aktif" : "Nonaktif"}</td>
    <td>${dateLabel(u.created_at)}</td>
    <td>${u.id === currentUser.id ? "Akun Anda" : `<button class="outline small-btn" data-user="${u.id}" data-active="${u.active ? 0 : 1}">${u.active ? "Nonaktifkan" : "Aktifkan"}</button>`}</td>
    </tr>`).join("");
  $("#usersBody").querySelectorAll("button[data-user]").forEach(btn => btn.addEventListener("click", async () => {
    await api(`/api/users/${btn.dataset.user}`, {method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({active:btn.dataset.active === "1"})});
    loadUsers();
  }));
}
async function checkDrive() {
  try {
    const data = await api("/api/drive-status");
    $("#driveState").textContent = data.connected ? "Akun Drive terhubung" : "Belum terhubung";
    $("#connectDrive").hidden = data.connected;
  } catch { $("#driveState").textContent = "Status tidak tersedia"; }
}
function navigate(page) {
  ["files","history","users"].forEach(p => $(`#${p}Page`).hidden = p !== page);
  document.querySelectorAll(".nav").forEach(b => b.classList.toggle("active", b.dataset.page === page));
  $("#pageTitle").textContent = ({files:"Semua file",history:"Riwayat aktivitas",users:"Pengguna"})[page];
  if (page === "history") loadHistory();
  if (page === "users") loadUsers();
}
$("#loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  $("#loginError").textContent = "";
  const body = Object.fromEntries(new FormData(e.currentTarget));
  try { const data = await api("/api/login", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}); currentUser = data.user; showApp(); }
  catch(err) { $("#loginError").textContent = err.message; }
});
$("#logoutBtn").addEventListener("click", async () => {
  try { await api("/api/logout", { method:"POST" }); currentUser = null; showLogin(); }
  catch (err) { toast(err.message, true); }
});
$("#connectDrive").addEventListener("click", () => location.href = "/auth/google");
$("#topUpload").addEventListener("click", () => $("#fileInput").click());
$("#chooseFile").addEventListener("click", () => $("#fileInput").click());
$("#fileInput").addEventListener("change", e => uploadFiles(e.target.files));
$("#searchInput").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(loadFiles, 250); });
$("#categoryFilter").addEventListener("change", loadFiles);
document.querySelectorAll(".nav").forEach(b => b.addEventListener("click", () => navigate(b.dataset.page)));
$("#closePreview").addEventListener("click", () => $("#previewModal").hidden = true);
$("#previewModal").addEventListener("click", e => { if (e.target.dataset.close) $("#previewModal").hidden = true; });
$("#dropZone").addEventListener("dragover", e => { e.preventDefault(); $("#dropZone").classList.add("drag"); });
$("#dropZone").addEventListener("dragleave", () => $("#dropZone").classList.remove("drag"));
$("#dropZone").addEventListener("drop", e => { e.preventDefault(); $("#dropZone").classList.remove("drag"); uploadFiles(e.dataTransfer.files); });
$("#userForm").addEventListener("submit", async e => {
  e.preventDefault();
  const body = Object.fromEntries(new FormData(e.currentTarget));
  try {
    await api("/api/users",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    $("#userMessage").textContent = "Pengguna berhasil dibuat.";
    e.currentTarget.reset(); loadUsers();
  } catch(err) { $("#userMessage").textContent = err.message; }
});
init();
