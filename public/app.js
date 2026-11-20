
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

// =========================
// API HELPER
// =========================

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
    throw new Error(
      data?.error || `Permintaan gagal (${response.status})`
    );
  }

  return data;
}

// =========================
// FORMAT DATA
// =========================

function formatSize(bytes) {
  if (bytes === null || bytes === undefined || bytes === "") {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let number = Number(bytes);

  if (!Number.isFinite(number) || number < 0) return "0 B";

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

// =========================
// NOTIFIKASI
// =========================

function toast(message, error = false) {
  const element = $("#uploadMessage");

  if (!element) return;

  element.textContent = message;
  element.style.color = error
    ? "var(--red)"
    : "var(--green)";
}

// =========================
// LOGIN DAN INISIALISASI
// =========================

async function init() {
  try {
    const result = await api("/api/me");

    if (!result.user) {
      showLogin();
      return;
    }

    currentUser = result.user;
    await showApp();

  } catch (error) {
    console.error("Inisialisasi gagal:", error);
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
  $("#avatar").textContent =
    currentUser.username.slice(0, 1).toUpperCase();

  $("#usersNav").hidden = currentUser.role !== "admin";
  $("#connectDrive").hidden = currentUser.role !== "admin";

  await loadCategories();
  await loadFiles();
  await loadStorage();

  if (currentUser.role === "admin") {
    await checkDrive();
  }
}

// =========================
// KATEGORI
// =========================

async function loadCategories() {
  try {
    const result = await api("/api/categories");

    allCategories = Array.isArray(result)
      ? [...new Set([...DEFAULT_CATEGORIES, ...result])]
      : DEFAULT_CATEGORIES;

    const filter = $("#categoryFilter");
    const previousValue = filter.value;

    filter.innerHTML =
      '<option value="">Semua kategori</option>' +
      allCategories.map(category => `
        <option value="${escapeHTML(category)}">
          ${escapeHTML(category)}
        </option>
      `).join("");

    if (allCategories.includes(previousValue)) {
      filter.value = previousValue;
    }

  } catch (error) {
    console.error("Gagal memuat kategori:", error);
    allCategories = DEFAULT_CATEGORIES;
  }
}

// =========================
// DASHBOARD PENYIMPANAN
// =========================

function formatStorage(bytes) {
  const value = Number(bytes || 0);

  if (!Number.isFinite(value) || value < 0) return "0 B";

  if (value < 1024) {
    return `${value.toFixed(0)} B`;
  }

  if (value < 1024 ** 2) {
    return `${(value / 1024).toFixed(1)} KB`;
  }

  if (value < 1024 ** 3) {
    return `${(value / 1024 ** 2).toFixed(1)} MB`;
  }

  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

async function loadStorage() {
  try {
    const data = await api("/api/storage");

    const storage = data.storage || {};
    const files = data.files || {};

    $("#storageUsed").textContent =
      formatStorage(storage.used);

    $("#storageDriveUsed").textContent =
      formatStorage(storage.driveUsed);

    $("#storageFileCount").textContent =
      `${Number(files.total || 0)} file`;

    $("#storageFileSize").textContent =
      formatStorage(files.totalSize);

    if (
      storage.unlimited ||
      storage.limit === null ||
      storage.limit === undefined ||
      Number(storage.limit) <= 0
    ) {
      $("#storageDescription").textContent =
        "Batas kapasitas tidak tersedia";

      $("#storagePercentage").textContent = "--";
      $("#storageRemaining").textContent =
        "Kapasitas tidak diketahui";

      $("#storageProgressBar").style.width = "0%";

    } else {
      const percentage = Math.min(
        100,
        Math.max(0, Number(storage.percentage) || 0)
      );

      $("#storageDescription").textContent =
        `Dari kapasitas ${formatStorage(storage.limit)}`;

      $("#storagePercentage").textContent =
        `${percentage.toFixed(1)}% digunakan`;

      $("#storageRemaining").textContent =
        `Sisa ${formatStorage(storage.remaining)}`;

      $("#storageProgressBar").style.width =
        `${percentage}%`;
    }

    $("#storageStatus").textContent =
      "● Informasi penyimpanan berhasil dimuat";

    renderFolders(data.folders || []);

  } catch (error) {
    console.error("Gagal memuat penyimpanan:", error);

    $("#storageUsed").textContent = "Tidak tersedia";

    $("#storageDescription").textContent =
      "Gagal mengambil informasi penyimpanan";

    $("#storageStatus").textContent =
      "● Periksa koneksi Google Drive";

    $("#folderGrid").innerHTML = `
      <div class="folder-loading">
        Informasi folder belum dapat dimuat.
      </div>
    `;
  }
}

// =========================
// RENDER FOLDER
// =========================

function renderFolders(folders) {
  const icons = {
    "Skripsi": "📚",
    "Akademik": "🎓",
    "Pekerjaan": "💼",
    "Pribadi": "👤",
    "Keuangan": "💰",
    "Foto & Gambar": "🖼️",
    "Lainnya": "📁"
  };

  $("#folderTotal").textContent =
    `${folders.length} Folder`;

  if (!folders.length) {
    $("#folderGrid").innerHTML = `
      <div class="folder-loading">
        Belum ada folder atau file tersimpan.
      </div>
    `;
    return;
  }

  $("#folderGrid").innerHTML = folders.map(folder => `
    <article class="folder-card"
      data-folder="${escapeHTML(folder.name)}">

      <div class="folder-icon">
        ${icons[folder.name] || "📁"}
      </div>

      <h3>${escapeHTML(folder.name)}</h3>

      <p>${Number(folder.totalFiles || 0)} file tersimpan</p>

      <strong>${formatStorage(folder.totalSize)}</strong>

    </article>
  `).join("");

  document.querySelectorAll(".folder-card").forEach(card => {
    card.addEventListener("click", () => {
      const category = card.dataset.folder;

      $("#categoryFilter").value = category;
      loadFiles();

      document.querySelector(".toolbar")?.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });
    });
  });
}

// =========================
// DAFTAR FILE
// =========================

async function loadFiles() {
  try {
    const params = new URLSearchParams();

    const search = $("#searchInput").value.trim();
    const category = $("#categoryFilter").value;

    if (search) params.set("search", search);
    if (category) params.set("category", category);

    const files = await api(
      `/api/files?${params.toString()}`
    );

    $("#fileCount").textContent = files.length;
    $("#fileGrid").innerHTML = "";
    $("#emptyState").hidden = files.length > 0;

    for (const file of files) {
      const isPdf = file.mime_type === "application/pdf";
      const isImage = file.mime_type?.startsWith("image/");
      const canPrint = isPdf || isImage;

      const icon = isPdf
        ? "PDF"
        : isImage
          ? "IMG"
          : "FILE";

      const iconClass = isPdf
        ? "pdf"
        : isImage
          ? "image"
          : "";

      const card = document.createElement("article");
      card.className = "file-card";

      card.innerHTML = `
        <div class="file-top">
          <div class="file-icon ${iconClass}">
            ${icon}
          </div>

          <div class="file-menu">
            ${canPrint ? `
              <button data-action="preview" title="Pratinjau">◉</button>
              <button data-action="print" title="Cetak file">▣</button>
            ` : ""}

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

        <span class="category-tag">
          ${escapeHTML(file.category)}
        </span>

        ${currentUser.role === "admin" ? `
          <div class="file-uploader">
            Diunggah oleh ${escapeHTML(file.uploader)}
          </div>
        ` : ""}
      `;

      card.querySelectorAll("[data-action]").forEach(button => {
        button.addEventListener("click", () => {
          const action = button.dataset.action;

          if (action === "preview") {
            previewFile(file);
          }

          if (action === "print") {
            printFile(file);
          }

          if (action === "download") {
            window.location.href =
              `/api/files/${encodeURIComponent(file.id)}/download`;
          }

          if (action === "delete") {
            deleteFile(file);
          }
        });
      });

      $("#fileGrid").append(card);
    }

  } catch (error) {
    toast(error.message, true);
    console.error("Gagal memuat file:", error);
  }
}

// =========================
// UPLOAD DAN PEMILIHAN FOLDER
// =========================

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
  const isOther =
    $("#uploadCategory").value === "Lainnya";

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
    const error = new Error(
      result.error || `Upload ${file.name} gagal.`
    );
    error.code = result.code || null;
    throw error;
  }
}

async function startUpload() {
  if (!pendingFiles.length) return;

  const selectedCategory = $("#uploadCategory").value;
  let category = selectedCategory;

  if (selectedCategory === "Lainnya") {
    category = $("#customFolderName").value.trim();

    if (!category) {
      $("#uploadDialogError").textContent =
        "Nama folder wajib diisi.";

      $("#customFolderName").focus();
      return;
    }

    if (
      category.length > 80 ||
      /[\\/:*?"<>|]/.test(category)
    ) {
      $("#uploadDialogError").textContent =
        "Nama folder maksimal 80 karakter dan tidak boleh mengandung karakter khusus.";
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
      toast(
        `Mengunggah ${files[index].name} (${index + 1}/${files.length})...`
      );

      await uploadOne(files[index], category);

      uploadedCount++;

      $("#progressBar").style.width =
        `${Math.round((uploadedCount / files.length) * 100)}%`;
    }

    toast(
      `${uploadedCount} file berhasil disimpan ke folder ${category}.`
    );

    await loadCategories();
    await loadFiles();
    await loadStorage();

  } catch (error) {
    if (error.code === "GOOGLE_REAUTH_REQUIRED") {
      $("#driveState").textContent = "Koneksi Drive perlu diperbarui";
      $("#connectDrive").hidden = false;
      $("#connectDrive").textContent = "Hubungkan ulang Drive";
    }

    toast(
      `${uploadedCount} dari ${files.length} file berhasil diunggah. ${error.message}`,
      true
    );

    await loadFiles();
    await loadStorage();

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

// =========================
// PREVIEW DAN PRINT
// =========================

function previewFile(file) {
  const url =
    `/api/files/${encodeURIComponent(file.id)}/preview`;

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
      } catch {
        alert(
          "Browser tidak dapat membuka fitur cetak. Gunakan tombol Print pada pratinjau."
        );
      }
    }, 700);
  }, { once: true });
}

function closePreview() {
  $("#previewModal").hidden = true;
  $("#previewContent").innerHTML = "";
  previewFrame = null;
}

// =========================
// HAPUS FILE
// =========================

async function deleteFile(file) {
  if (!confirm(`Hapus "${file.name}" dari Google Drive?`)) {
    return;
  }

  try {
    await api(
      `/api/files/${encodeURIComponent(file.id)}`,
      { method: "DELETE" }
    );

    await loadFiles();
    await loadStorage();

    toast("File berhasil dihapus.");

  } catch (error) {
    alert(error.message);
  }
}

// =========================
// RIWAYAT AKTIVITAS
// =========================

async function loadHistory() {
  try {
    const rows = await api("/api/history");

    $("#historyBody").innerHTML = rows.map(row => `
      <tr>
        <td>
          <span class="${
            row.action === "UPLOAD"
              ? "status-active"
              : "status-off"
          }">
            ${row.action === "UPLOAD" ? "↑ Upload" : "× Hapus"}
          </span>
        </td>

        <td>${escapeHTML(row.file_name)}</td>
        <td>${escapeHTML(row.category)}</td>
        <td>${escapeHTML(row.username)}</td>
        <td>${dateLabel(row.created_at)}</td>
      </tr>
    `).join("") ||
      '<tr><td colspan="5">Belum ada aktivitas.</td></tr>';

  } catch (error) {
    toast(error.message, true);
  }
}

// =========================
// MANAJEMEN PENGGUNA
// =========================

async function loadUsers() {
  try {
    const users = await api("/api/users");

    $("#usersBody").innerHTML = users.map(user => `
      <tr>
        <td>${escapeHTML(user.username)}</td>
        <td>${escapeHTML(user.role)}</td>

        <td class="${
          user.active ? "status-active" : "status-off"
        }">
          ${user.active ? "Aktif" : "Nonaktif"}
        </td>

        <td>${dateLabel(user.created_at)}</td>

        <td>
          ${
            user.id === currentUser.id
              ? "Akun Anda"
              : `
                <button
                  class="outline small-btn"
                  data-user="${escapeHTML(user.id)}"
                  data-active="${user.active ? 0 : 1}">
                  ${user.active ? "Nonaktifkan" : "Aktifkan"}
                </button>
              `
          }
        </td>
      </tr>
    `).join("");

    $("#usersBody")
      .querySelectorAll("button[data-user]")
      .forEach(button => {
        button.addEventListener("click", async () => {
          try {
            await api(
              `/api/users/${encodeURIComponent(button.dataset.user)}`,
              {
                method: "PATCH",
                headers: {
                  "Content-Type": "application/json"
                },
                body: JSON.stringify({
                  active: button.dataset.active === "1"
                })
              }
            );

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

// =========================
// GOOGLE DRIVE
// =========================

async function checkDrive() {
  try {
    const data = await api("/api/drive-status");
    const reconnect = Boolean(data.reconnectRequired);

    $("#driveState").textContent = data.connected
      ? "Akun Drive terhubung"
      : reconnect
        ? "Koneksi Drive perlu diperbarui"
        : "Belum terhubung";

    $("#connectDrive").hidden = Boolean(data.connected);
    $("#connectDrive").textContent = reconnect
      ? "Hubungkan ulang Drive"
      : "Hubungkan Drive";

  } catch (error) {
    console.error("Gagal memeriksa Drive:", error);
    $("#driveState").textContent = "Status tidak tersedia";
    $("#connectDrive").hidden = false;
    $("#connectDrive").textContent = "Hubungkan ulang Drive";
  }
}

// =========================
// NAVIGASI
// =========================

function navigate(page) {
  ["files", "history", "users"].forEach(name => {
    $(`#${name}Page`).hidden = name !== page;
  });

  document.querySelectorAll(".nav").forEach(button => {
    button.classList.toggle(
      "active",
      button.dataset.page === page
    );
  });

  $("#pageTitle").textContent = ({
    files: "Semua file",
    history: "Riwayat aktivitas",
    users: "Pengguna"
  })[page] || "DriveSpace";

  if (page === "history") loadHistory();
  if (page === "users") loadUsers();
}

// =========================
// EVENT LISTENERS
// =========================

// Login
$("#loginForm").addEventListener("submit", async event => {
  event.preventDefault();

  $("#loginError").textContent = "";

  const body = Object.fromEntries(
    new FormData(event.currentTarget)
  );

  try {
    const result = await api("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    currentUser = result.user;
    await showApp();

  } catch (error) {
    $("#loginError").textContent = error.message;
  }
});

// Logout
$("#logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/logout", {
      method: "POST"
    });

    currentUser = null;
    showLogin();

  } catch (error) {
    toast(error.message, true);
  }
});

// Google Drive
$("#connectDrive").addEventListener("click", () => {
  window.location.href = "/auth/google";
});

// Upload
$("#topUpload").addEventListener("click", () => {
  $("#fileInput").click();
});

$("#chooseFile").addEventListener("click", () => {
  $("#fileInput").click();
});

$("#fileInput").addEventListener("change", event => {
  openUploadDialog(event.target.files);
});

$("#uploadCategory").addEventListener(
  "change",
  updateCustomFolderField
);

$("#confirmUpload").addEventListener(
  "click",
  startUpload
);

$("#cancelUpload").addEventListener(
  "click",
  closeUploadDialog
);

$("#closeUploadModal").addEventListener(
  "click",
  closeUploadDialog
);

$("#uploadModal").addEventListener("click", event => {
  if (event.target.dataset.closeUpload) {
    closeUploadDialog();
  }
});

// Pencarian
$("#searchInput").addEventListener("input", () => {
  clearTimeout(searchTimer);

  searchTimer = setTimeout(() => {
    loadFiles();
  }, 300);
});

// Filter kategori
$("#categoryFilter").addEventListener(
  "change",
  loadFiles
);

// Navigasi
document.querySelectorAll(".nav").forEach(button => {
  button.addEventListener("click", () => {
    navigate(button.dataset.page);
  });
});

// Preview
$("#closePreview").addEventListener(
  "click",
  closePreview
);

$("#previewModal").addEventListener("click", event => {
  if (event.target.dataset.closePreview) {
    closePreview();
  }
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

// Drag and Drop
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

// Tambah pengguna
$("#userForm").addEventListener("submit", async event => {
  event.preventDefault();

  const form = event.currentTarget;
  const body = Object.fromEntries(new FormData(form));

  try {
    await api("/api/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body)
    });

    $("#userMessage").textContent =
      "Pengguna berhasil dibuat.";

    form.reset();

    await loadUsers();

  } catch (error) {
    $("#userMessage").textContent = error.message;
  }
});

// Refresh penyimpanan
const refreshStorageButton = $("#refreshStorage");

if (refreshStorageButton) {
  refreshStorageButton.addEventListener(
    "click",
    loadStorage
  );
}

// =========================
// JALANKAN APLIKASI
// =========================

init();
