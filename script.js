// script.js - client-side encrypt/decrypt demo using Web Crypto API
// Updated: encrypted output is pretty JSON and there's a viewer + open/copy/download UI
// Added: background video reduced-motion handling

// Helpers: base64 <-> arraybuffer
const bufToBase64 = (buf) => {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
};
const base64ToBuf = (b64) => {
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
};

async function fileToArrayBuffer(file){
  return await file.arrayBuffer();
}

// Derive AES-GCM key from password and salt using PBKDF2
async function deriveKey(password, salt, iterations=150000){
  const pwUtf8 = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', pwUtf8, 'PBKDF2', false, ['deriveKey']);
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}

// Encrypt file -> JSON object with metadata (readable)
async function makeEncryptedPayload(file, password){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const data = await fileToArrayBuffer(file);
  const ciphertext = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, data);

  const payload = {
    format: "profile-pic-enc-v1",
    filename: file.name,
    type: file.type || 'application/octet-stream',
    created_at: new Date().toISOString(),
    salt: bufToBase64(salt.buffer),
    iv: bufToBase64(iv.buffer),
    ciphertext: bufToBase64(ciphertext)
  };
  return payload;
}

// Decrypt JSON blob back to original file Blob
async function decryptBlobToFile(encryptedBlob, password){
  const text = await encryptedBlob.text();
  let payload;
  try{
    payload = JSON.parse(text);
  } catch (err){
    throw new Error('Invalid encrypted file format (not JSON).');
  }
  if(!payload.salt || !payload.iv || !payload.ciphertext) throw new Error('Missing encryption metadata.');

  const salt = base64ToBuf(payload.salt);
  const iv = base64ToBuf(payload.iv);
  const ciphertext = base64ToBuf(payload.ciphertext);

  const key = await deriveKey(password, salt);
  let plain;
  try{
    plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ciphertext);
  } catch (err){
    throw new Error('Decryption failed (wrong passphrase or corrupted file).');
  }
  return new File([plain], payload.filename || 'restored', { type: payload.type || 'application/octet-stream' });
}

// UI wiring
document.addEventListener('DOMContentLoaded', () => {
  // Background video accessibility: respect prefers-reduced-motion and try to play/pause accordingly
  const bgVideo = document.getElementById('bg-video');
  if (bgVideo) {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const updateMotion = () => {
      if (mq.matches) {
        try { bgVideo.pause(); } catch (e) {}
        bgVideo.setAttribute('aria-hidden', 'true');
      } else {
        // Try to play video (muted videos usually autoplay)
        if (typeof bgVideo.play === 'function') bgVideo.play().catch(() => {});
        bgVideo.removeAttribute('aria-hidden');
      }
    };
    if (mq.addEventListener) mq.addEventListener('change', updateMotion);
    else mq.addListener(updateMotion);
    updateMotion();

    // hide if error loading
    bgVideo.addEventListener('error', () => { bgVideo.style.display = 'none'; });
  }

  // Tabs
  const tabEnc = document.getElementById('tab-encrypt');
  const tabDec = document.getElementById('tab-decrypt');
  const encPanel = document.getElementById('encrypt-panel');
  const decPanel = document.getElementById('decrypt-panel');

  tabEnc.addEventListener('click', () => {
    tabEnc.classList.add('active'); tabDec.classList.remove('active');
    encPanel.classList.remove('hidden'); decPanel.classList.add('hidden');
  });
  tabDec.addEventListener('click', () => {
    tabDec.classList.add('active'); tabEnc.classList.remove('active');
    decPanel.classList.remove('hidden'); encPanel.classList.add('hidden');
  });

  // Encrypt UI elements
  const imageInput = document.getElementById('image-input');
  const preview = document.getElementById('preview');
  const passwordEnc = document.getElementById('password-encrypt');
  const encryptBtn = document.getElementById('encrypt-btn');
  const encryptStatus = document.getElementById('encrypt-status');
  const clearEnc = document.getElementById('clear-encrypt');

  // JSON viewer elements (new)
  const jsonActions = document.getElementById('json-actions');
  const jsonViewer = document.getElementById('json-viewer');
  const openJsonBtn = document.getElementById('open-json');
  const copyJsonBtn = document.getElementById('copy-json');
  const downloadJsonLink = document.getElementById('download-json');

  let selectedFile = null;
  let lastJsonBlobUrl = null;
  let lastJsonString = '';

  imageInput.addEventListener('change', (e) => {
    const f = e.target.files[0];
    if(!f) return;
    selectedFile = f;
    showPreview(preview, f);
    checkEncryptEnabled();
  });

  function showPreview(imgEl, file){
    const url = URL.createObjectURL(file);
    imgEl.src = url;
    imgEl.classList.remove('hidden');
  }
  function hidePreview(imgEl){
    imgEl.src = '';
    imgEl.classList.add('hidden');
  }

  passwordEnc.addEventListener('input', checkEncryptEnabled);
  function checkEncryptEnabled(){
    encryptBtn.disabled = !(selectedFile && passwordEnc.value.length > 0);
  }

  encryptBtn.addEventListener('click', async () => {
    if(!selectedFile) return;
    const pass = passwordEnc.value;
    encryptStatus.textContent = 'Encrypting...';
    encryptBtn.disabled = true;
    // hide previous json viewer
    jsonActions.classList.add('hidden');
    jsonViewer.value = '';
    lastJsonString = '';
    if (lastJsonBlobUrl) { URL.revokeObjectURL(lastJsonBlobUrl); lastJsonBlobUrl = null; }
    try{
      const payload = await makeEncryptedPayload(selectedFile, pass);
      // produce pretty JSON string so the file is human-readable
      const json = JSON.stringify(payload, null, 2);
      lastJsonString = json;
      const blob = new Blob([json], { type: 'application/json' });

      // prepare download link (use .enc.json extension to emphasize encrypted JSON)
      const filename = (selectedFile.name || 'image') + '.enc.json';
      const url = URL.createObjectURL(blob);
      downloadJsonLink.href = url;
      downloadJsonLink.download = filename;

      // store blob url for "Open JSON"
      lastJsonBlobUrl = url;

      // show JSON in viewer
      jsonViewer.value = json;
      jsonActions.classList.remove('hidden');

      // also immediately trigger a download as before (still available)
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();

      encryptStatus.innerHTML = `Encrypted and downloaded as <strong>${filename}</strong>. You can view/copy/open the JSON below. Keep your passphrase safe.`;
      encryptStatus.style.color = '';
    } catch (err){
      encryptStatus.textContent = 'Error: ' + (err.message || err);
      encryptStatus.style.color = 'var(--danger)';
    } finally {
      encryptBtn.disabled = false;
    }
  });

  // Open JSON in new tab
  openJsonBtn.addEventListener('click', () => {
    if (!lastJsonBlobUrl) {
      // fallback: open a data URL
      const dataUrl = 'data:application/json;charset=utf-8,' + encodeURIComponent(lastJsonString || '');
      window.open(dataUrl, '_blank');
    } else {
      window.open(lastJsonBlobUrl, '_blank');
    }
  });

  // Copy JSON to clipboard
  copyJsonBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(lastJsonString || jsonViewer.value || '');
      copyJsonBtn.textContent = 'Copied ✓';
      setTimeout(() => { copyJsonBtn.textContent = 'Copy JSON'; }, 1500);
    } catch {
      // fallback: select text
      jsonViewer.select();
      document.execCommand('copy');
      copyJsonBtn.textContent = 'Copied ✓';
      setTimeout(() => { copyJsonBtn.textContent = 'Copy JSON'; }, 1500);
    }
  });

  clearEnc.addEventListener('click', () => {
    imageInput.value = '';
    selectedFile = null;
    hidePreview(preview);
    passwordEnc.value = '';
    encryptStatus.textContent = '';
    jsonActions.classList.add('hidden');
    jsonViewer.value = '';
    lastJsonString = '';
    if (lastJsonBlobUrl) { URL.revokeObjectURL(lastJsonBlobUrl); lastJsonBlobUrl = null; }
    checkEncryptEnabled();
  });

  // Decrypt UI elements
  const encryptedInput = document.getElementById('encrypted-input');
  const passwordDec = document.getElementById('password-decrypt');
  const decryptBtn = document.getElementById('decrypt-btn');
  const decryptStatus = document.getElementById('decrypt-status');
  const clearDec = document.getElementById('clear-decrypt');
  const decPreview = document.getElementById('decrypted-preview');
  const downloadDec = document.getElementById('download-decrypted');

  let encFile = null;
  encryptedInput.addEventListener('change', (e) => {
    const f = e.target.files[0];
    if(!f) return;
    encFile = f;
    decryptStatus.textContent = `Loaded file: ${f.name}`;
    checkDecryptEnabled();
  });

  passwordDec.addEventListener('input', checkDecryptEnabled);
  function checkDecryptEnabled(){
    decryptBtn.disabled = !(encFile && passwordDec.value.length > 0);
  }

  decryptBtn.addEventListener('click', async () => {
    if(!encFile) return;
    decryptStatus.textContent = 'Decrypting...';
    decryptBtn.disabled = true;
    try{
      const restoredFile = await decryptBlobToFile(encFile, passwordDec.value);
      const url = URL.createObjectURL(restoredFile);
      decPreview.src = url;
      decPreview.classList.remove('hidden');
      downloadDec.href = url;
      downloadDec.download = restoredFile.name;
      downloadDec.classList.remove('hidden');
      decryptStatus.innerHTML = `Decryption successful — restored <strong>${restoredFile.name}</strong>.`;
      decryptStatus.style.color = 'var(--success)';
    } catch (err){
      decryptStatus.textContent = 'Error: ' + (err.message || err);
      decryptStatus.style.color = 'var(--danger)';
      decPreview.classList.add('hidden');
      downloadDec.classList.add('hidden');
    } finally {
      decryptBtn.disabled = false;
    }
  });

  clearDec.addEventListener('click', () => {
    encryptedInput.value = '';
    encFile = null;
    passwordDec.value = '';
    decryptStatus.textContent = '';
    decPreview.src = '';
    decPreview.classList.add('hidden');
    downloadDec.href = '#';
    downloadDec.classList.add('hidden');
    checkDecryptEnabled();
  });

  // Small UX: support drag & drop onto preview area for encrypt
  const dropzone = document.getElementById('dropzone');
  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag');
    const f = e.dataTransfer.files[0];
    if(f && f.type.startsWith('image/')){
      imageInput.files = e.dataTransfer.files;
      imageInput.dispatchEvent(new Event('change'));
    }
  });

});