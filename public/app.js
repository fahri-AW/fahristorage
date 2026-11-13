const $ = (selector) => document.querySelector(selector);

let currentUser = null;
let allCategories = [];
let searchTimer = null;
let pendingFiles = [];
let previewFrame = null;

const DEFAULT_CATEGORIES = [
  "Skripsi",
  "Akademik",
  "Pekerjaan",
  "Pribadi",
  "Keuangan",
  "Foto & Gambar",
  "Lainnya"
];

async function api(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options
  });

  const type = response.headers.get("content-type") || "";
  const data = type.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    throw new Error(data?.error || `Permintaan gagal (${response.status})`);
  }

  return data;
}

function formatSize(bytes) {
  if (!bytes) return "—";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Number(bytes);
  let index = 0;

  while (number >= 1024 && index < units.length - 1) {
    number /= 1024;
    index++;
  }

  return `${number.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function dateLabel(value) {
  if (!value) return "—";

  const normalized = String(value).includes("T")
    ? String(value)
    : String(value).replace(" ", "T");

  const date = new Date(
    normalized.endsWith("Z") ? normalized : `${normalized}Z`
  );

  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString("id-ID", {
        dateStyle: "medium",
        timeStyle: "short"
      });
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

function toast(message, error = false) {
  const element = $("#uploadMessage");
  element.textContent = message;
  element.style.color = error ? "var(--red)" : "var(--green)";
}

async function init() {
  try {
    const result = await api("/api/me");

    if (!result.user) {
      showLogin();
      return;
    }

    currentUser = result.user;
    await showApp();
  } catch {
    showLogin();
  }
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
  $("#avatar").textContent = currentUser.username.slice(0, 1).toUpperCase();

  $("#usersNav").hidden = currentUser.role !== "admin";
  $("#connectDrive").hidden = currentUser.role !== "admin";

  await loadCategories();
  await loadFiles();

  if (currentUser.role === "admin") {
    await checkDrive();
  }
}

async function loadCategories() {
  try {
    const result = await api("/api/categories");
    allCategories = Array.isArray(result) && result.length
      ? [...new Set([...DEFAULT_CATEGORIES, ...result])]
      : DEFAULT_CATEGORIES;

    const filter = $("#categoryFilter");
    const previousValue = filter.value;

    filter.innerHTML =
      '<option value="">Semua kategori</option>' +
      allCategories.map(category =>
        `<option value="${escapeHTML(category)}">${escapeHTML(category)}</option>`
      ).join("");

    filter.value = previousValue;
  } catch {
    allCategories = DEFAULT_CATEGORIES;
  }
}

async function loadFiles() {
  try {
    const params = new URLSearchParams();
    const search = $("#searchInput").value.trim();
    const category = $("#categoryFilter").value;

    if (search) params.set("search", search);
    if (category) params.set("category", category);

    const files = await api(`/api/files?${params.toString()}`);

    $("#fileCount").textContent = files.length;
    $("#fileGrid").innerHTML = "";
    $("#emptyState").hidden = files.length > 0;

    for (const file of files) {
      const isPdf = file.mime_type === "application/pdf";
      const isImage = file.mime_type?.startsWith("image/");
      const canPrint = isPdf || isImage;

      const icon = isPdf ? "PDF" : isImage ? "IMG" : "FILE";
      const iconClass = isPdf ? "pdf" : isImage ? "image" : "";

      const card = document.createElement("article");
      card.className = "file-card";

      card.innerHTML = `
        <div class="file-top">
          <div class="file-icon ${iconClass}">${icon}</div>
          <div class="file-menu">
            ${canPrint
              ? `<button data-action="preview" title="Pratinjau">◉</button>
                 <button data-action="print" title="Cetak file">▣</button>`
              : ""}
            <button data-action="download" title="Unduh">↓</button>
            <button data-action="delete" title="Hapus">⋯</button>
          </div>
        </div>

        <div class="file-name" title="${escapeHTML(file.name)}">
          ${escapeHTML(file.name)}
        </div>

        <div class="file-meta">
          <span>${formatSize(file.size)}</span>
          <span>${dateLabel(file.created_at)}</span>
        </div>

        <span class="category-tag">${escapeHTML(file.category)}</span>

        ${currentUser.role === "admin"
          ? `<div class="file-uploader">Diunggah oleh ${escapeHTML(file.uploader)}</div>`
          : ""}
      `;

      card.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => {
          const action = button.dataset.action;

          if (action === "preview") previewFile(file);
          if (action === "print") printFile(file);
          if (action === "download") {
            window.location.href = `/api/files/${encodeURIComponent(file.id)}/download`;
          }
          if (action === "delete") deleteFile(file);
        });
      });

      $("#fileGrid").append(card);
    }
  } catch (error) {
    toast(error.message, true);
  }
}

/* =========================
   UPLOAD DAN PEMILIHAN FOLDER
========================= */

function openUploadDialog(fileList) {
  pendingFiles = [...fileList];

  if (!pendingFiles.length) return;

  $("#selectedFilesCount").textContent =
    `${pendingFiles.length} file`;

  $("#uploadCategory").value = "Akademik";
  $("#customFolderName").value = "";
  $("#customFolderWrap").hidden = true;
  $("#uploadDialogError").textContent = "";

  $("#uploadModal").hidden = false;
}

function closeUploadDialog() {
  $("#uploadModal").hidden = true;
  pendingFiles = [];
  $("#fileInput").value = "";
}

function updateCustomFolderField() {
  const isOther = $("#uploadCategory").value === "Lainnya";

  $("#customFolderWrap").hidden = !isOther;

  if (isOther) {
    $("#customFolderName").focus();
  }
}

async function uploadOne(file, category) {
  const form = new FormData();

  form.append("file", file);
  form.append("category", category);

  const response = await fetch("/api/upload", {
    method: "POST",
    body: form,
    credentials: "same-origin"
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(result.error || `Upload ${file.name} gagal.`);
  }
}

async function startUpload() {
  if (!pendingFiles.length) return;

  const selectedCategory = $("#uploadCategory").value;
  let category = selectedCategory;

  if (selectedCategory === "Lainnya") {
    category = $("#customFolderName").value.trim();

    if (!category) {
      $("#uploadDialogError").textContent = "Nama folder wajib diisi.";
      $("#customFolderName").focus();
      return;
    }

    if (category.length > 80 || /[\\/:*?"<>|]/.test(category)) {
      $("#uploadDialogError").textContent =
        "Nama folder maksimal 80 karakter dan tidak boleh mengandung karakter \\ / : * ? \" < > |.";
      return;
    }
  }

  const files = [...pendingFiles];

  $("#confirmUpload").disabled = true;
  $("#cancelUpload").disabled = true;
  $("#closeUploadModal").disabled = true;

  $("#uploadModal").hidden = true;
  $("#uploadProgress").hidden = false;
  $("#progressBar").style.width = "0%";

  $("#chooseFile").disabled = true;
  $("#topUpload").disabled = true;

  let uploadedCount = 0;

  try {
    for (let index = 0; index < files.length; index++) {
      toast(`Mengunggah ${files[index].name} (${index + 1}/${files.length})...`);

      await uploadOne(files[index], category);

      uploadedCount++;
      $("#progressBar").style.width =
        `${Math.round((uploadedCount / files.length) * 100)}%`;
    }

    toast(`${uploadedCount} file berhasil disimpan ke folder ${category}.`);

    await loadCategories();
    await loadFiles();
  } catch (error) {
    toast(
      `${uploadedCount} dari ${files.length} file berhasil diunggah. ${error.message}`,
      true
    );

    await loadFiles();
  } finally {
    pendingFiles = [];

    $("#confirmUpload").disabled = false;
    $("#cancelUpload").disabled = false;
    $("#closeUploadModal").disabled = false;

    $("#chooseFile").disabled = false;
    $("#topUpload").disabled = false;

    $("#fileInput").value = "";

    setTimeout(() => {
      $("#uploadProgress").hidden = true;
    }, 1200);
  }
}

/* =========================
   PREVIEW DAN PRINT
========================= */

function previewFile(file) {
  const url = `/api/files/${encodeURIComponent(file.id)}/preview`;

  $("#previewTitle").textContent = file.name;
  $("#previewContent").innerHTML = "";

  const frame = document.createElement("iframe");
  frame.title = `Pratinjau ${file.name}`;
  frame.src = url;
  frame.className = "preview-frame";

  $("#previewContent").append(frame);
  $("#previewModal").hidden = false;

  previewFrame = frame;
}

function printFile(file) {
  const supported =
    file.mime_type === "application/pdf" ||
    file.mime_type?.startsWith("image/");

  if (!supported) {
    alert("Cetak langsung hanya tersedia untuk PDF dan gambar.");
    return;
  }

  previewFile(file);

  const frame = previewFrame;

  frame.addEventListener("load", () => {
    setTimeout(() => {
      try {
        frame.contentWindow.focus();
        frame.contentWindow.print();
      } catch (error) {
        alert("Browser tidak dapat membuka fitur cetak. Gunakan tombol Print pada pratinjau.");
      }
    }, 700);
  }, { once: true });
}

function closePreview() {
  $("#previewModal").hidden = true;
  $("#previewContent").innerHTML = "";
  previewFrame = null;
}

async function deleteFile(file) {
  if (!confirm(`Hapus "${file.name}" dari Google Drive?`)) return;

  try {
    await api(`/api/files/${encodeURIComponent(file.id)}`, {
      method: "DELETE"
    });

    toast("File berhasil dihapus.");
    await loadFiles();
  } catch (error) {
    alert(error.message);
  }
}

/* =========================
   RIWAYAT DAN PENGGUNA
========================= */

async function loadHistory() {
  try {
    const rows = await api("/api/history");

    $("#historyBody").innerHTML = rows.map(row => `
      <tr>
        <td>
          <span class="${row.action === "UPLOAD" ? "status-active" : "status-off"}">
            ${row.action === "UPLOAD" ? "↑ Upload" : "× Hapus"}
          </span>
        </td>
        <td>${escapeHTML(row.file_name)}</td>
        <td>${escapeHTML(row.category)}</td>
        <td>${escapeHTML(row.username)}</td>
        <td>${dateLabel(row.created_at)}</td>
      </tr>
    `).join("") || '<tr><td colspan="5">Belum ada aktivitas.</td></tr>';
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadUsers() {
  try {
    const users = await api("/api/users");

    $("#usersBody").innerHTML = users.map(user => `
      <tr>
        <td>${escapeHTML(user.username)}</td>
        <td>${escapeHTML(user.role)}</td>
        <td class="${user.active ? "status-active" : "status-off"}">
          ${user.active ? "Aktif" : "Nonaktif"}
        </td>
        <td>${dateLabel(user.created_at)}</td>
        <td>
          ${user.id === currentUser.id
            ? "Akun Anda"
            : `<button class="outline small-btn"
                 data-user="${user.id}"
                 data-active="${user.active ? 0 : 1}">
                 ${user.active ? "Nonaktifkan" : "Aktifkan"}
               </button>`}
        </td>
      </tr>
    `).join("");

    $("#usersBody").querySelectorAll("button[data-user]").forEach(button => {
      button.addEventListener("click", async () => {
        try {
          await api(`/api/users/${button.dataset.user}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              active: button.dataset.active === "1"
            })
          });

          await loadUsers();
        } catch (error) {
          alert(error.message);
        }
      });
    });
  } catch (error) {
    toast(error.message, true);
  }
}

async function checkDrive() {
  try {
    const data = await api("/api/drive-status");

    $("#driveState").textContent = data.connected
      ? "Akun Drive terhubung"
      : "Belum terhubung";

    $("#connectDrive").hidden = data.connected;
  } catch {
    $("#driveState").textContent = "Status tidak tersedia";
  }
}

/* =========================
   NAVIGASI
========================= */

function navigate(page) {
  ["files", "history", "users"].forEach(name => {
    $(`#${name}Page`).hidden = name !== page;
  });

  document.querySelectorAll(".nav").forEach(button => {
    button.classList.toggle("active", button.dataset.page === page);
  });

  $("#pageTitle").textContent = ({
    files: "Semua file",
    history: "Riwayat aktivitas",
    users: "Pengguna"
  })[page];

  if (page === "history") loadHistory();
  if (page === "users") loadUsers();
}

/* =========================
   EVENT LISTENERS
========================= */

$("#loginForm").addEventListener("submit", async event => {
  event.preventDefault();
  $("#loginError").textContent = "";

  const body = Object.fromEntries(new FormData(event.currentTarget));

  try {
    const result = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    currentUser = result.user;
    await showApp();
  } catch (error) {
    $("#loginError").textContent = error.message;
  }
});

$("#logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
    currentUser = null;
    showLogin();
  } catch (error) {
    toast(error.message, true);
  }
});

$("#connectDrive").addEventListener("click", () => {
  window.location.href = "/auth/google";
});

$("#topUpload").addEventListener("click", () => {
  $("#fileInput").click();
});

$("#chooseFile").addEventListener("click", () => {
  $("#fileInput").click();
});

$("#fileInput").addEventListener("change", event => {
  openUploadDialog(event.target.files);
});

$("#uploadCategory").addEventListener("change", updateCustomFolderField);

$("#confirmUpload").addEventListener("click", startUpload);

$("#cancelUpload").addEventListener("click", closeUploadDialog);
$("#closeUploadModal").addEventListener("click", closeUploadDialog);

$("#uploadModal").addEventListener("click", event => {
  if (event.target.dataset.closeUpload) closeUploadDialog();
});

$("#searchInput").addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadFiles, 300);
});

$("#categoryFilter").addEventListener("change", loadFiles);

document.querySelectorAll(".nav").forEach(button => {
  button.addEventListener("click", () => navigate(button.dataset.page));
});

$("#closePreview").addEventListener("click", closePreview);

$("#previewModal").addEventListener("click", event => {
  if (event.target.dataset.closePreview) closePreview();
});

$("#printPreview").addEventListener("click", () => {
  if (!previewFrame) return;

  try {
    previewFrame.contentWindow.focus();
    previewFrame.contentWindow.print();
  } catch {
    alert("Fitur cetak tidak dapat dibuka oleh browser.");
  }
});

$("#dropZone").addEventListener("dragover", event => {
  event.preventDefault();
  $("#dropZone").classList.add("drag");
});

$("#dropZone").addEventListener("dragleave", () => {
  $("#dropZone").classList.remove("drag");
});

$("#dropZone").addEventListener("drop", event => {
  event.preventDefault();
  $("#dropZone").classList.remove("drag");
  openUploadDialog(event.dataTransfer.files);
});

$("#userForm").addEventListener("submit", async event => {
  event.preventDefault();

  const form = event.currentTarget;
  const body = Object.fromEntries(new FormData(form));

  try {
    await api("/api/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    $("#userMessage").textContent = "Pengguna berhasil dibuat.";
    form.reset();
    await loadUsers();
  } catch (error) {
    $("#userMessage").textContent = error.message;
  }
});

init();
