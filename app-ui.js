// =========================================================================
// AVVIOPC PRO - UI LAYER (strings, state, helpers, operators, scanner, OCR)
// -------------------------------------------------------------------------
// HOW TO APPLY: in the inline <script> of Index.html put this file FIRST and
// app-core.js right after it. Delete the old script entirely.
//
// SECTIONS
//   1. Configuration and state
//   2. UI strings (DICTIONARY)
//   3. DOM references and startup
//   4. Alerts and string initialization
//   5. Input formatters
//   6. Operators (store / operator dropdowns)
//   7. Operator modal and Microsoft creation buttons
//   8. Scanner (camera, barcode)
//   9. OCR capture and quota
// =========================================================================


// =========================================================================
// 1. CONFIGURATION AND STATE
// =========================================================================

const APP_API_KEY = 'REPLACE_WITH_NEW_APP_API_KEY';   // from Script Properties
const GOOGLE_SCRIPT_URL = 'https://script.google.com/macros/s/AKfycbwRw29rfoRjM5-_4F-G6YviGQtjFgM18xQ4doFVD23I_DICuzp4OeJLbTBMb2V-t98/exec';

let sessionToken = '';
let operatorDirectory = [];
let currentOperatorId = localStorage.getItem('operator_id') || '00000';
let customAlertCallback = null;
let serialCheckTimeout = null;
let isMsCreated = false;
let acquiredEmail = '';
let acquiredPassword = '';
let currentAuthSession = '';
let currentMode = null;
let currentInputId = null;
let streamTrack = null;
let barcodeInterval = null;
let isBarcodeDecoding = false;
let currentOcrRemaining = null;

// Scanner engines. ZXing is optional: the app still works if its script fails to load.
const zxingReader = window.ZXing ? new ZXing.BrowserMultiFormatReader() : null;
const nativeBarcodeDetector = ('BarcodeDetector' in window)
  ? new BarcodeDetector({ formats: ['code_128', 'qr_code', 'ean_13', 'code_39'] })
  : null;


// =========================================================================
// 2. UI STRINGS (DICTIONARY)
// =========================================================================
// Values containing HTML are static and trusted. Never put server data here.

const DICTIONARY = {
  appTitle: "AvvioPC <span class='pro-badge'>PRO</span>",
  operatorBadge: 'Operatore',
  serialPlaceholder: '...',
  localAccountPlaceholder: 'Nome di chi userà il PC',

  officeTitle: 'Suite da ufficio',
  officeOptMs: "<img src='logos/logo_office.png' class='option-icon'><span class='option-text'>Office 365</span>",
  officeOptLibre: "<img src='logos/logo_libreoffice.png' class='option-icon'><span class='option-text'>Libre Office</span>",
  officeKeyLabel: 'Product Key Office',
  officeKeyPlaceholder: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',

  avTitle: 'Protezione antivirus',
  avOptUnevdi: "<img src='logos/logo_unevdi.png' class='option-icon'><span class='option-text'>Unieuro Everyday Digital</span>",
  avOptNorton: "<img src='logos/logo_norton.png' class='option-icon'><span class='option-text'>Norton 360 Deluxe</span>",
  avOptMcafee: "<img src='logos/logo_mcafee.png' class='option-icon'><span class='option-text'>McAfee Total Protection</span>",
  avOptNone: "<img src='logos/logo_defender.png' class='option-icon'><span class='option-text'>Windows Defender</span>",
  avNortonKeyLabel: 'Product Key Norton',
  avMcafeeKeyLabel: 'Product Key McAfee',
  avKeyPlaceholderNorton: 'XXXXX XXXXX XXXXX XXXXX XXXXX',
  avKeyPlaceholderMcafee: 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',

  cyberTitle: 'Unieuro Cyber Protection',
  cyberCheck: "<img src='logos/logo_cyber.png' class='option-icon'><span class='option-text'>Installa icona servizio</span>",

  msTitle: 'Account Microsoft *',
  btnCreateMs: 'Crea nuovo account Microsoft',
  btnAuth: 'Importa account creato',
  msUserLabel: 'Email',
  msUserPlaceholder: 'nome.cognome@dominio',
  msPassLabel: 'Password',
  btnFeedbackCustom: '✅ Copiata negli appunti!',

  winUpdTitle: 'Windows Update',
  winUpdCheck: "<svg class='option-icon' viewBox='0 0 24 24' fill='currentColor'><path d='M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z'/></svg><span class='option-text'>Esegui a fine installazione</span>",

  btnSubmit: 'Caricamento dati',
  btnReprint: 'Ristampa report',

  opModalTitle: 'Impostazioni',
  storeModalDefault: '-- Seleziona Negozio --',
  opModalDefault: '-- Seleziona Operatore --',
  opModalLoading: 'Caricamento dati in corso...',
  opModalPinPlaceholder: 'PIN',
  btnCancel: 'Annulla',
  btnSave: 'Conferma',
  networkError: 'Errore di rete',

  scanTitleBarcode: 'Scansione Codice a Barre',
  scanTitleOcr: 'Scansione Product Key',
  btnCaptureOcr: 'CATTURA CODICE',
  statusBarcodeSearch: 'Ricerca del codice a barre in corso...',
  statusOcrAlign: 'Allinea il codice e premi CATTURA',
  statusOcrSending: "Invio dell'immagine al servizio OCR...",
  statusOcrSuccess: '✅ Product Key estratto con successo!',
  statusOcrFailed: '❌ Nessun codice rilevato. Riprova.',
  quotaNone: 'nessun riconoscimento disponibile',
  quotaAvailable: 'riconoscimenti disponibili',

  alertOauthSuccess: '✅ Account Microsoft acquisito: ',
  alertUploadSuccess: 'Dati inviati al server con successo!',
  alertUploadError: 'Impossibile trasmettere i dati: ',
  alertCameraError: 'Errore hardware fotocamera: ',
  alertFetchError: 'Impossibile scaricare la lista operatori. Riprova più tardi.',
  overlayLoadingText: 'Trasmissione dati<br>in corso...',
  ocrFormatOfficeExpected: '❌ Formato non valido: rilevato cartoncino Norton. Inquadrare cartoncino Office.',
  ocrFormatNortonExpected: '❌ Formato non valido: rilevato cartoncino Office. Inquadrare cartoncino Norton.'
};


// =========================================================================
// 3. DOM REFERENCES AND STARTUP
// =========================================================================

const elements = {
  pcSerial: document.getElementById('pc-serial'),
  localAccount: document.getElementById('local-account'),
  officeMs: document.getElementById('office-ms'),
  officeKey: document.getElementById('office-key'),
  msOfficeField: document.getElementById('ms-office-field'),
  avUnevdi: document.getElementById('av-unevdi'),
  avNorton: document.getElementById('av-norton'),
  avMcafee: document.getElementById('av-mcafee'),
  avNone: document.getElementById('av-none'),
  avKey: document.getElementById('av-key'),
  avField: document.getElementById('av-field'),
  avKeyLabel: document.getElementById('av-key-label'),
  runCyber: document.getElementById('run-cyber'),
  btnCreateMs: document.getElementById('btn-create-ms'),
  btnAuth: document.getElementById('btnAuth'),
  msUsername: document.getElementById('ms-username'),
  msPassword: document.getElementById('ms-password'),
  runUpdates: document.getElementById('run-updates'),
  submitBtn: document.getElementById('submit-btn'),
  reprintBtn: document.getElementById('reprint-btn'),
  operatorBadge: document.getElementById('header-operator-id'),
  operatorModal: document.getElementById('operator-modal'),
  storeDropdown: document.getElementById('store-dropdown'),
  operatorDropdown: document.getElementById('operator-dropdown'),
  operatorPin: document.getElementById('operator-pin'),
  scannerModal: document.getElementById('scanner-modal'),
  video: document.getElementById('scanner-video'),
  modalStatus: document.getElementById('modal-status'),
  scanAnimation: document.getElementById('scan-animation'),
  captureBtn: document.getElementById('capture-btn'),
  ocrControls: document.getElementById('ocr-controls'),
  overlay: document.getElementById('scanner-overlay'),
  canvas: document.getElementById('hidden-canvas'),
  loadingOverlay: document.getElementById('loading-overlay'),
  customAlertModal: document.getElementById('custom-alert-modal'),
  alertMessage: document.getElementById('alert-message'),
  pwdAlertModal: document.getElementById('pwd-alert-modal'),
  btnPwdAlertOk: document.getElementById('btn-pwd-alert-ok'),
  chkDontShowAgain: document.getElementById('chk-dont-show-again'),
  importAlertModal: document.getElementById('import-alert-modal'),
  btnImportAlertOk: document.getElementById('btn-import-alert-ok'),
  chkImportDontShowAgain: document.getElementById('chk-import-dont-show-again'),
  chkEnableAlerts: document.getElementById('chk-enable-alerts'),
  existingRecordBanner: document.getElementById('existing-record-banner'),
  existingRecordDetails: document.getElementById('existing-record-details')
};

window.addEventListener('load', () => {
  initializeUIStrings();
  updateOperatorUI();
  generateRandomPassword();
  restoreDraft();
  fetchOperatorsFromServer();
});


// =========================================================================
// 4. ALERTS AND STRING INITIALIZATION
// =========================================================================

function setText(id, text) {
  const element = document.getElementById(id);
  if (element) element.innerText = text;
}

function setHtml(id, html) {
  const element = document.getElementById(id);
  if (element) element.innerHTML = html;   // static, trusted DICTIONARY values only
}

function initializeUIStrings() {
  setHtml('lbl-app-title', DICTIONARY.appTitle);
  setText('lbl-operator', DICTIONARY.operatorBadge);
  elements.pcSerial.placeholder = DICTIONARY.serialPlaceholder;
  elements.localAccount.placeholder = DICTIONARY.localAccountPlaceholder;

  setText('lbl-office-suite', DICTIONARY.officeTitle);
  setHtml('lbl-opt-ms', DICTIONARY.officeOptMs);
  setHtml('lbl-opt-libre', DICTIONARY.officeOptLibre);
  setText('lbl-office-key', DICTIONARY.officeKeyLabel);
  elements.officeKey.placeholder = DICTIONARY.officeKeyPlaceholder;

  setText('lbl-av-protection', DICTIONARY.avTitle);
  setHtml('lbl-opt-unevdi', DICTIONARY.avOptUnevdi);
  setHtml('lbl-opt-norton', DICTIONARY.avOptNorton);
  setHtml('lbl-opt-mcafee', DICTIONARY.avOptMcafee);
  setHtml('lbl-opt-none', DICTIONARY.avOptNone);

  setText('lbl-cyber-title', DICTIONARY.cyberTitle);
  setHtml('lbl-cyber-check', DICTIONARY.cyberCheck);

  setText('lbl-ms-title', DICTIONARY.msTitle);
  setText('lbl-btn-create-ms', DICTIONARY.btnCreateMs);
  setText('lbl-btn-auth', DICTIONARY.btnAuth);
  setText('lbl-ms-username', DICTIONARY.msUserLabel);
  elements.msUsername.placeholder = DICTIONARY.msUserPlaceholder;
  setText('lbl-ms-password', DICTIONARY.msPassLabel);

  setText('lbl-winupd-title', DICTIONARY.winUpdTitle);
  setHtml('lbl-winupd-check', DICTIONARY.winUpdCheck);
  setText('lbl-btn-submit', DICTIONARY.btnSubmit);
  setText('lbl-btn-reprint', DICTIONARY.btnReprint);

  setText('lbl-modal-op-title', DICTIONARY.opModalTitle);
  setText('lbl-modal-store-default', DICTIONARY.storeModalDefault);
  setText('lbl-modal-op-default', DICTIONARY.opModalDefault);
  elements.operatorPin.placeholder = DICTIONARY.opModalPinPlaceholder;
  setText('btn-cancel', DICTIONARY.btnCancel);
  setText('btn-save', DICTIONARY.btnSave);
  elements.captureBtn.innerText = DICTIONARY.btnCaptureOcr;
  setHtml('lbl-loading-overlay', DICTIONARY.overlayLoadingText);

  updateAuthButtonVisuals();
  validateForm();
}

/** msg is plain text: "\n" becomes a line break, everything else is escaped. */
function showAlert(msg, callback = null) {
  elements.alertMessage.innerHTML = escapeHtml(msg).replace(/\n/g, '<br>');
  elements.customAlertModal.classList.add('active');
  customAlertCallback = callback;
}

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function closeCustomAlert() {
  elements.customAlertModal.classList.remove('active');
  if (customAlertCallback) {
    const callback = customAlertCallback;
    customAlertCallback = null;
    callback();
  }
}

function validateForm() {
  elements.submitBtn.classList.toggle('is-disabled', !isFormValidCheck());
  saveDraft();
}

function updateOperatorUI() {
  elements.operatorBadge.innerText = currentOperatorId;
  validateForm();
}


// =========================================================================
// 5. INPUT FORMATTERS
// =========================================================================

/** Formats a 25-character key in groups of 5 and keeps the cursor position. */
function formatProductKey(input, separator) {
  const cursorStart = input.selectionStart;
  const originalValue = input.value;
  const rawValue = originalValue.replace(/[^A-Za-z0-9]/g, '').toUpperCase().substring(0, 25);

  let formattedValue = '';
  for (let i = 0; i < rawValue.length; i++) {
    if (i > 0 && i % 5 === 0) formattedValue += separator;
    formattedValue += rawValue[i];
  }
  if (originalValue === formattedValue) return;
  input.value = formattedValue;

  let alnumBeforeCursor = 0;
  for (let i = 0; i < cursorStart && i < originalValue.length; i++) {
    if (/[A-Za-z0-9]/.test(originalValue[i])) alnumBeforeCursor++;
  }

  let newCursorPosition = 0;
  let alnumCount = 0;
  for (let i = 0; i < formattedValue.length; i++) {
    if (alnumCount === alnumBeforeCursor) {
      newCursorPosition = i;
      break;
    }
    if (/[A-Za-z0-9]/.test(formattedValue[i])) alnumCount++;
  }
  if (alnumCount < alnumBeforeCursor) newCursorPosition = formattedValue.length;

  input.setSelectionRange(newCursorPosition, newCursorPosition);
  validateForm();
}

function formatAvKey(input) {
  formatProductKey(input, elements.avNorton.checked ? ' ' : '-');
}

function formatLocalAccount(input) {
  input.value = input.value.split(' ').map((word) =>
    word.length > 0 ? word.charAt(0).toUpperCase() + word.slice(1).toLowerCase() : word
  ).join(' ');
  validateForm();
}


// =========================================================================
// 6. OPERATORS
// =========================================================================

function createOption(value, label) {
  const option = document.createElement('option');
  option.value = value;
  option.textContent = label;
  return option;
}

function setSingleOption(select, value, label) {
  select.textContent = '';
  select.appendChild(createOption(value, label));
}

async function fetchOperatorsFromServer() {
  try {
    setSingleOption(elements.storeDropdown, '000', DICTIONARY.opModalLoading);
    const result = await getFromServer({ action: 'get_operators', api_key: APP_API_KEY });
    if (result.status !== 'success') {
      throw new Error('Server error');
    }
    operatorDirectory = result.data;
    initializeStoreDropdown();
  } catch (error) {
    setSingleOption(elements.storeDropdown, '000', DICTIONARY.networkError);
  }
}

function initializeStoreDropdown() {
  const stores = [...new Set(operatorDirectory.map((op) => String(op.storeId).trim()))];
  stores.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

  setSingleOption(elements.storeDropdown, '000', DICTIONARY.storeModalDefault);
  stores.forEach((store) => {
    if (store) elements.storeDropdown.appendChild(createOption(store, 'Negozio ' + store));
  });

  const savedStoreId = localStorage.getItem('store_id');
  if (savedStoreId && stores.includes(savedStoreId)) {
    elements.storeDropdown.value = savedStoreId;
    onStoreSelectionChange();
    const savedOperatorId = localStorage.getItem('operator_id');
    if (savedOperatorId && operatorDirectory.find((op) => String(op.id) === String(savedOperatorId))) {
      elements.operatorDropdown.value = savedOperatorId;
      currentOperatorId = savedOperatorId;
    }
  }
}

function onStoreSelectionChange() {
  const selectedStore = elements.storeDropdown.value;
  setSingleOption(elements.operatorDropdown, '00000', DICTIONARY.opModalDefault);
  if (selectedStore === '000') {
    elements.operatorDropdown.disabled = true;
    return;
  }

  const fullName = (op) => op.lastName + ' ' + op.firstName;
  const storeOperators = operatorDirectory
    .filter((op) => String(op.storeId).trim() === selectedStore)
    .sort((a, b) => fullName(a).toLowerCase().localeCompare(fullName(b).toLowerCase()));

  const maxLength = storeOperators.reduce((max, op) => Math.max(max, fullName(op).length), 0);
  storeOperators.forEach((op) => {
    const name = fullName(op);
    const padding = '\xa0'.repeat(maxLength - name.length + 1);
    elements.operatorDropdown.appendChild(createOption(op.id, name + padding + '[' + op.id + ']'));
  });
  elements.operatorDropdown.disabled = false;
}


// =========================================================================
// 7. OPERATOR MODAL AND MICROSOFT CREATION BUTTONS
// =========================================================================

function openOperatorModal() {
  elements.operatorPin.value = '';
  const isPwdHidden = localStorage.getItem('hide_pwd_alert') === 'true';
  const isImportHidden = localStorage.getItem('hide_import_alert') === 'true';
  elements.chkEnableAlerts.checked = !(isPwdHidden && isImportHidden);
  elements.operatorModal.classList.add('active');
}

function closeOperatorModal() {
  elements.operatorModal.classList.remove('active');
}

function updateAuthButtonVisuals() {
  elements.btnAuth.classList.remove('is-disabled', 'is-import', 'is-success');
  if (!isMsCreated) {
    elements.btnAuth.disabled = true;
    elements.btnAuth.classList.add('is-disabled');
  } else if (!acquiredEmail) {
    elements.btnAuth.disabled = false;
    elements.btnAuth.classList.add('is-import');
  } else {
    const isSameEmail = elements.msUsername.value.trim().toLowerCase() === acquiredEmail.toLowerCase();
    const isSamePassword = elements.msPassword.value.trim() === acquiredPassword;
    elements.btnAuth.classList.add(isSameEmail && isSamePassword ? 'is-success' : 'is-disabled');
  }
}

function handleManualAccountEdits() {
  if (acquiredEmail) updateAuthButtonVisuals();
}

elements.msUsername.addEventListener('input', () => { handleManualAccountEdits(); validateForm(); });
elements.msPassword.addEventListener('input', () => { handleManualAccountEdits(); validateForm(); });

elements.btnCreateMs.onclick = () => {
  if ('vibrate' in navigator) navigator.vibrate([100, 50, 100]);
  if (!isMsCreated) {
    isMsCreated = true;
    updateAuthButtonVisuals();
  }
  if (localStorage.getItem('hide_pwd_alert') === 'true') {
    executeMsCreationFlow();
  } else {
    elements.chkDontShowAgain.checked = false;
    elements.pwdAlertModal.classList.add('active');
  }
};

elements.btnPwdAlertOk.onclick = () => {
  if (elements.chkDontShowAgain.checked) localStorage.setItem('hide_pwd_alert', 'true');
  elements.pwdAlertModal.classList.remove('active');
  executeMsCreationFlow();
};

function executeMsCreationFlow() {
  const passwordToCopy = elements.msPassword.value.trim();
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(passwordToCopy).catch(() => {});
  }
  window.open('https://signup.live.com/signup', '_blank', 'noopener,noreferrer');

  const label = document.getElementById('lbl-btn-create-ms');
  label.innerText = DICTIONARY.btnFeedbackCustom;
  elements.btnCreateMs.classList.replace('is-primary', 'is-success');
  setTimeout(() => {
    label.innerText = DICTIONARY.btnCreateMs;
    elements.btnCreateMs.classList.replace('is-success', 'is-primary');
  }, 3000);
}

function handleImportClick() {
  if (elements.btnAuth.disabled) return;
  if (localStorage.getItem('hide_import_alert') === 'true') {
    startMicrosoftAuth();
  } else {
    elements.chkImportDontShowAgain.checked = false;
    elements.importAlertModal.classList.add('active');
  }
}

elements.btnImportAlertOk.onclick = () => {
  if (elements.chkImportDontShowAgain.checked) localStorage.setItem('hide_import_alert', 'true');
  elements.importAlertModal.classList.remove('active');
  startMicrosoftAuth();
};


// =========================================================================
// 8. SCANNER (CAMERA, BARCODE)
// =========================================================================

async function openScanner(targetId, mode) {
  currentInputId = targetId;
  currentMode = mode;
  const isBarcode = (mode === 'barcode');

  setText('scanner-title', isBarcode ? DICTIONARY.scanTitleBarcode : DICTIONARY.scanTitleOcr);
  if (!isBarcode) {
    currentOcrRemaining = null;
    fetchOcrStatus();
  }

  elements.scannerModal.classList.add('active');
  elements.overlay.classList.toggle('barcode-mode', isBarcode);
  elements.captureBtn.style.display = isBarcode ? 'none' : 'block';
  elements.captureBtn.disabled = false;
  elements.scanAnimation.style.display = isBarcode ? 'block' : 'none';
  elements.ocrControls.style.display = 'none';
  elements.modalStatus.innerText = isBarcode ? DICTIONARY.statusBarcodeSearch : DICTIONARY.statusOcrAlign;

  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: 'environment', width: { ideal: 4096 }, height: { ideal: 2160 } }
    });
    elements.video.srcObject = stream;
    streamTrack = stream.getVideoTracks()[0];
    elements.video.onloadedmetadata = () => {
      const capabilities = streamTrack.getCapabilities ? streamTrack.getCapabilities() : {};
      if (capabilities.zoom) streamTrack.applyConstraints({ advanced: [{ zoom: 1.5 }] });
      if (isBarcode) startBarcodeAutoScan();
    };
  } catch (error) {
    elements.modalStatus.innerText = DICTIONARY.alertCameraError + error.message;
  }
}

function closeScanner() {
  currentMode = null;
  elements.scannerModal.classList.remove('active');
  if (streamTrack) streamTrack.stop();
  elements.video.srcObject = null;
  if (barcodeInterval) {
    clearInterval(barcodeInterval);
    barcodeInterval = null;
  }
}

/** Crops the video to the overlay rectangle into the hidden canvas. */
function drawOverlayCrop(verticalInset) {
  const video = elements.video;
  const overlayRect = elements.overlay.getBoundingClientRect();
  const wrapperRect = video.parentElement.getBoundingClientRect();
  const scaleX = video.videoWidth / wrapperRect.width;
  const scaleY = video.videoHeight / wrapperRect.height;

  const cropWidth = overlayRect.width * scaleX;
  const cropHeight = (overlayRect.height - verticalInset * 2) * scaleY;
  const cropX = (overlayRect.left - wrapperRect.left) * scaleX;
  const cropY = ((overlayRect.top + verticalInset) - wrapperRect.top) * scaleY;

  elements.canvas.width = cropWidth;
  elements.canvas.height = cropHeight;
  elements.canvas.getContext('2d', { willReadFrequently: true })
    .drawImage(video, cropX, cropY, cropWidth, cropHeight, 0, 0, cropWidth, cropHeight);
}

function decodeWithZxing(canvas) {
  if (!zxingReader) return Promise.resolve(null);
  return new Promise((resolve) => {
    const image = new Image();
    image.onload = async () => {
      try {
        resolve((await zxingReader.decodeFromImageElement(image)).text);
      } catch (error) {
        resolve(null);
      }
    };
    image.onerror = () => resolve(null);
    image.src = canvas.toDataURL('image/jpeg', 0.6);
  });
}

function startBarcodeAutoScan() {
  barcodeInterval = setInterval(async () => {
    if (currentMode !== 'barcode' || !elements.video.videoWidth || isBarcodeDecoding) return;
    isBarcodeDecoding = true;   // avoid overlapping decodes
    try {
      drawOverlayCrop(0);
      let detectedValue = null;
      if (nativeBarcodeDetector) {
        const barcodes = await nativeBarcodeDetector.detect(elements.canvas);
        if (barcodes.length > 0) detectedValue = barcodes[0].rawValue;
      }
      if (!detectedValue) detectedValue = await decodeWithZxing(elements.canvas);

      if (detectedValue && currentMode === 'barcode') {
        const target = document.getElementById(currentInputId);
        target.value = detectedValue;
        if ('vibrate' in navigator) navigator.vibrate([100, 50, 100]);
        closeScanner();
        // Triggers uppercase normalization and the serial lookup.
        target.dispatchEvent(new Event('input', { bubbles: true }));
      }
    } catch (error) {
      // A failed frame is ignored: the next tick tries again.
    } finally {
      isBarcodeDecoding = false;
    }
  }, 300);
}


// =========================================================================
// 9. OCR CAPTURE AND QUOTA
// =========================================================================

// Product key alphabet (24 symbols). Letters outside it are misreads.
const KEY_ALPHABET = 'BCDFGHJKMPQRTVWXY2346789Z';
const OCR_MISREAD_CORRECTIONS = {
  S: '6', 5: '6', O: 'Q', 0: 'Q', I: 'T', 1: 'T', L: 'T',
  A: '4', U: 'V', E: 'F', N: 'M', Z: '2'
};
const KEY_GROUP = '([' + KEY_ALPHABET + ']{5})';
const KEY_PATTERN = new RegExp(new Array(5).fill(KEY_GROUP).join('[\\s-]*'), 'g');

/** Re-encodes the crop with decreasing quality until it fits the server limit. */
function captureBase64Image() {
  for (const quality of [0.9, 0.7, 0.5]) {
    const base64 = elements.canvas.toDataURL('image/jpeg', quality).split(',')[1];
    if (base64.length < 3500000) return base64;
  }
  return elements.canvas.toDataURL('image/jpeg', 0.3).split(',')[1];
}

function resumeScanner(statusText) {
  elements.modalStatus.innerText = statusText;
  elements.captureBtn.disabled = false;
  elements.video.play();
}

/** Applies the format rules and returns the formatted key, or null. */
function extractProductKey(recognizedText) {
  let text = recognizedText.toUpperCase();
  const dashCount = (text.match(/-/g) || []).length;
  const spaceCount = (text.match(/ /g) || []).length;

  if (currentInputId === 'office-key') {
    if (dashCount === 0 && spaceCount >= 3) return { error: DICTIONARY.ocrFormatOfficeExpected };
    text = text.split('').map((char) => OCR_MISREAD_CORRECTIONS[char] || char).join('');
    text = text.replace(new RegExp('[^' + KEY_ALPHABET + '\\- ]', 'g'), '');
  } else if (currentInputId === 'av-key' && elements.avNorton.checked && dashCount >= 2) {
    return { error: DICTIONARY.ocrFormatNortonExpected };
  }

  const matches = [...text.matchAll(KEY_PATTERN)];
  if (matches.length === 0) return { error: DICTIONARY.statusOcrFailed };

  const best = matches[matches.length - 1];
  const chars = (best[1] + best[2] + best[3] + best[4] + best[5]).split('');
  const lastIndex = (currentInputId === 'office-key') ? 24 : 25;   // Office: final "Z" is real
  for (let i = 0; i < lastIndex; i++) {
    if (chars[i] === 'Z') chars[i] = '2';
  }
  if (currentInputId === 'office-key') chars[24] = 'Z';

  const key = chars.join('');
  return { key: [0, 5, 10, 15, 20].map((start) => key.substring(start, start + 5)).join('-') };
}

elements.captureBtn.onclick = async () => {
  if (!streamTrack || currentMode !== 'ocr') return;

  elements.video.pause();
  elements.captureBtn.disabled = true;
  elements.modalStatus.innerText = DICTIONARY.statusOcrSending;

  drawOverlayCrop(12);   // 12px inset on top and bottom of the overlay
  const base64Image = captureBase64Image();

  try {
    const data = await requestOcr(base64Image);   // defined in app-core.js
    if (typeof data.remaining === 'number') {
      currentOcrRemaining = data.remaining;
      updateScannerTitleWithQuota(data.remaining);
    }

    const outcome = extractProductKey(data.text || '');
    if (outcome.error) {
      resumeScanner(outcome.error);
      return;
    }

    const target = document.getElementById(currentInputId);
    target.value = outcome.key;
    target.dispatchEvent(new Event('input'));
    elements.modalStatus.innerText = DICTIONARY.statusOcrSuccess;
    setTimeout(closeScanner, 800);
  } catch (error) {
    resumeScanner(error.message);
  }
};

async function fetchOcrStatus() {
  try {
    const data = await getFromServer({ action: 'get_ocr_status', api_key: APP_API_KEY });
    if (data.status === 'success') {
      currentOcrRemaining = data.remaining;
      updateScannerTitleWithQuota(data.remaining);
    }
  } catch (error) {
    // The quota label is optional.
  }
}

function updateScannerTitleWithQuota(remaining) {
  const count = Number(remaining) || 0;
  let label;
  let color;
  if (count === 0) {
    label = DICTIONARY.quotaNone;
    color = '#ff6b6b';
  } else {
    label = count + ' ' + DICTIONARY.quotaAvailable;
    color = (count < 50) ? '#ffd93d' : '#90ee90';
  }

  const title = document.getElementById('scanner-title');
  const detail = document.createElement('span');
  detail.style.cssText = 'font-size:13px;font-weight:normal;color:' + color + ';';
  detail.textContent = '(' + label + ')';
  title.textContent = DICTIONARY.scanTitleOcr;
  title.append(document.createElement('br'), detail);
}
