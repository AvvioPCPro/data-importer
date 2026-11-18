// =========================================================================
// AVVIOPC PRO - FRONTEND CORE (drop-in for the inline <script> of Index.html)
// -------------------------------------------------------------------------
// HOW TO APPLY
//   1. Paste this whole file at the END of the existing inline <script>,
//      just before </script>. Function declarations placed later override
//      the old ones with the same name; delete the old copies afterwards.
//   2. Keep GOOGLE_SCRIPT_URL, update APP_API_KEY with the NEW key.
//   3. Apply the manual patches listed in the reply (HTML/CSS one-liners).
//
// SECTIONS
//   1. Configuration and state
//   2. UI strings added or overridden
//   3. Network layer
//   4. Session handling
//   5. Operator login
//   6. Serial lookup and record locking
//   7. Form rules (antivirus / cyber, validation)
//   8. Microsoft account flow
//   9. OCR request
//  10. Submit, delete, reprint
//  11. Draft storage
// =========================================================================


// =========================================================================
// 1. CONFIGURATION AND STATE
// =========================================================================

const SESSION_STORAGE_KEY = 'avviopc_session_token';
const DRAFT_STORAGE_KEY = 'avviopc_draft';
const DRAFT_MAX_AGE_MS = 60 * 60 * 1000;     // drafts expire after 1 hour
const REQUEST_TIMEOUT_MS = 30000;
const PIN_MIN_LENGTH = 6;                    // must match Code.gs (menu tool)
const PIN_MAX_LENGTH = 12;
const SESSION_EXPIRED_MARKER = 'Sessione scaduta';  // text returned by Code.gs
const SERIAL_PATTERN = /^[A-Z0-9][A-Z0-9 ._\-\/]{2,63}$/;   // must match Code.gs
const ALLOWED_OFFICE_TYPES = ['ms_office', 'libre_office'];
const ALLOWED_ANTIVIRUS_TYPES = ['unevdi', 'norton', 'mcafee', 'none'];

let isRecordLocked = false;
let serialLookupCounter = 0;
let msPollingTimer = null;

// The session token now lives in sessionStorage (cleared when the tab closes).
localStorage.removeItem(SESSION_STORAGE_KEY);   // remove the legacy copy
sessionToken = sessionStorage.getItem(SESSION_STORAGE_KEY) || '';
if (sessionToken) {
  currentOperatorId = localStorage.getItem('operator_id') || '00000';
}


// =========================================================================
// 2. UI STRINGS ADDED OR OVERRIDDEN
// =========================================================================

Object.assign(DICTIONARY, {
  alertPinLength: 'Il PIN deve essere di ' + PIN_MIN_LENGTH + '-' + PIN_MAX_LENGTH + ' cifre.',
  alertPinInvalid: 'ID operatore o PIN non validi.',
  alertSelectOperator: 'Seleziona prima un negozio e un operatore.',
  alertLoginError: "Errore durante l'autenticazione: ",
  alertSessionExpired: 'La tua sessione è scaduta.\n\nClicca sul tuo ID Operatore in alto a destra, ' +
    'seleziona il tuo nome, inserisci il PIN e premi Conferma.',
  alertOauthConnectionError: "Impossibile avviare l'accesso Microsoft. Riprova.",
  alertOauthEmptyUrl: "Impossibile ottenere l'indirizzo di accesso Microsoft.",
  alertPopupBlocked: 'Il browser ha bloccato la finestra di accesso. Consenti i popup per questo sito e riprova.',
  alertMissingFields: 'Campi obbligatori mancanti.',
  alertSerialInvalid: 'Il numero seriale contiene caratteri non validi.',
  alertSerialMissing: 'Numero seriale mancante.',
  alertLoginRequired: 'Autenticazione operatore richiesta.',
  alertDeleteSuccess: 'Record eliminato con successo.',
  promptDeleteSerial: 'Inserisci il numero seriale di cui cancellare i dati registrati:',
  alertReprintSent: 'Ristampa inviata.',
  alertNetworkDelete: 'Errore di rete. Impossibile eliminare il record.',
  alertNetworkReprint: 'Errore di rete. Richiesta fallita.',
  alertNetworkArm: 'Errore di rete. Impossibile preparare il ripristino.',
  armingActive: 'Pronto per il provisioning fino alle ',
  armingInactive: 'Non pronto: premi "Prepara ripristino" prima di avviare il PC.',
  errorUnexpectedResponse: 'Risposta del server non valida. Riprova più tardi.',
  errorTimeout: 'Il server non risponde. Riprova tra qualche istante.',
  btnVerifying: 'Verifica...',
  btnAuthInitializing: 'Inizializzazione...',
  btnAuthWaiting: 'In attesa...',
  btnAuthImported: 'Account importato',
  btnAuthTimeout: 'Timeout. Riprova.',
  bannerLocked: 'Impossibile sovrascrivere i dati. Eliminare il record per procedere.',
  bannerRestricted: 'Il record appartiene a un altro negozio: i dati non sono consultabili.'
});


// =========================================================================
// 3. NETWORK LAYER
// =========================================================================

async function fetchWithTimeout(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, Object.assign({}, options, { signal: controller.signal }));
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (parseError) {
      console.error('Unexpected server response:', text.slice(0, 200));
      throw new Error(DICTIONARY.errorUnexpectedResponse);
    }
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error(DICTIONARY.errorTimeout);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** Public GET routes only (get_operators, get_ocr_status, get_uuid, getAuthUrl). */
function getFromServer(params) {
  const query = new URLSearchParams(Object.assign({}, params, { t: Date.now() }));
  return fetchWithTimeout(GOOGLE_SCRIPT_URL + '?' + query.toString(), {});
}

/** Plain POST (used for login/logout). "text/plain" avoids a CORS preflight. */
function postToServer(payload) {
  return fetchWithTimeout(GOOGLE_SCRIPT_URL, {
    method: 'POST',
    body: JSON.stringify(payload),
    headers: { 'Content-Type': 'text/plain;charset=utf-8' }
  });
}

/**
 * POST with the session token. Throws on server errors; when the session has
 * expired the user is already notified and error.isAuthError is true.
 */
async function postAuthenticated(action, data) {
  const result = await postToServer(Object.assign({ action: action, token: sessionToken }, data));
  if (result.status === 'error') {
    const error = new Error(result.message);
    error.isAuthError = handleAuthError(result.message);
    throw error;
  }
  return result;
}


// =========================================================================
// 4. SESSION HANDLING
// =========================================================================

function clearSession() {
  sessionToken = '';
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
  currentOperatorId = '00000';
  localStorage.removeItem('operator_id');
  updateOperatorUI();
}

function handleAuthError(message) {
  if (!String(message).includes(SESSION_EXPIRED_MARKER)) {
    return false;
  }
  clearSession();
  showAlert(DICTIONARY.alertSessionExpired);   // plain text: "\n" becomes <br>
  return true;
}

function applyAlertPreferences() {
  if (elements.chkEnableAlerts.checked) {
    localStorage.removeItem('hide_pwd_alert');
    localStorage.removeItem('hide_import_alert');
  } else {
    localStorage.setItem('hide_pwd_alert', 'true');
    localStorage.setItem('hide_import_alert', 'true');
  }
}


// =========================================================================
// 5. OPERATOR LOGIN
// =========================================================================

async function saveOperatorSelection() {
  const storeId = elements.storeDropdown.value;
  const operatorId = elements.operatorDropdown.value;
  const pin = elements.operatorPin.value.replace(/\D/g, '');

  if (storeId === '000' || operatorId === '00000') {
    showAlert(DICTIONARY.alertSelectOperator);
    return;
  }
  if (pin.length < PIN_MIN_LENGTH || pin.length > PIN_MAX_LENGTH) {
    showAlert(DICTIONARY.alertPinLength);
    return;
  }

  const saveButton = document.getElementById('btn-save');
  const originalLabel = saveButton.innerText;
  const previousToken = sessionToken;
  saveButton.innerText = DICTIONARY.btnVerifying;
  saveButton.disabled = true;

  try {
    const result = await postToServer({
      action: 'login',
      operator_id: operatorId,
      pin: pin,
      api_key: APP_API_KEY
    });

    if (result.status !== 'success' || !result.token) {
      showAlert(result.message || DICTIONARY.alertPinInvalid);
      elements.operatorPin.value = '';
      return;
    }

    // Invalidate the previous operator's session on shared devices.
    if (previousToken) {
      postToServer({ action: 'logout', token: previousToken }).catch(() => {});
    }

    sessionToken = result.token;
    sessionStorage.setItem(SESSION_STORAGE_KEY, sessionToken);
    applyAlertPreferences();

    currentOperatorId = operatorId;
    localStorage.setItem('operator_id', operatorId);
    localStorage.setItem('store_id', storeId);   // UI convenience only
    elements.operatorPin.value = '';

    updateOperatorUI();
    closeOperatorModal();

    // The serial lookup requires a session: run it now if a serial is present.
    if (elements.pcSerial.value.trim().length >= 5) {
      handleSerialInput();
    }
  } catch (error) {
    showAlert(DICTIONARY.alertLoginError + error.message);
  } finally {
    saveButton.innerText = originalLabel;
    saveButton.disabled = false;
  }
}


// =========================================================================
// 6. SERIAL LOOKUP AND RECORD LOCKING
// =========================================================================

function handleSerialInput() {
  const serial = elements.pcSerial.value.trim().toUpperCase();
  if (elements.pcSerial.value !== serial) {
    elements.pcSerial.value = serial;
  }
  validateForm();

  elements.reprintBtn.style.background = '';
  elements.reprintBtn.classList.remove('is-success');
  clearTimeout(serialCheckTimeout);
  const lookupId = ++serialLookupCounter;

  if (serial.length < 5 || !SERIAL_PATTERN.test(serial)) {
    if (isRecordLocked) unlockForm();
    return;
  }
  if (!sessionToken) {
    return;   // the lookup needs a valid session
  }

  serialCheckTimeout = setTimeout(async () => {
    try {
      const result = await postAuthenticated('check_serial_post', { serial: serial });
      if (lookupId !== serialLookupCounter) {
        return;   // stale response: the serial changed in the meantime
      }
      if (result.exists && result.record) {
        elements.reprintBtn.classList.add('is-success');
        if ('vibrate' in navigator) navigator.vibrate([50]);
        lockFormAndPopulate(result.record, Boolean(result.restricted));
      } else if (isRecordLocked) {
        unlockForm();
      }
    } catch (error) {
      console.warn('Serial check failed:', error.message);
    }
  }, 800);
}

function createBoldNode(value) {
  const node = document.createElement('b');
  node.textContent = String(value === undefined || value === null ? '' : value);
  return node;
}

function lockFormAndPopulate(record, isRestricted) {
  isRecordLocked = true;
  const recordDate = record.timestamp ? new Date(record.timestamp) : null;
  const dateLabel = (recordDate && !isNaN(recordDate.getTime()))
    ? recordDate.toLocaleDateString('it-IT')
    : 'N/D';

  // Built with DOM nodes (textContent): server values are never parsed as HTML.
  const details = elements.existingRecordDetails;
  details.textContent = '';
  details.append(
    'Registrato il ', createBoldNode(dateLabel),
    " dall'operatore ", createBoldNode(record.operator_id),
    ' (Negozio: ', String(record.store_id), ').',
    document.createElement('br'),
    isRestricted ? DICTIONARY.bannerRestricted : DICTIONARY.bannerLocked
  );
  elements.existingRecordBanner.style.display = 'block';

  if (!isRestricted) {
    populateFormFromRecord(record);
  }

  // The serial field stays editable so the operator can scan another PC.
  document.querySelectorAll('main.form-container input, main.form-container select')
    .forEach((element) => { element.disabled = (element !== elements.pcSerial); });

  document.getElementById('btn-delete-record').disabled = isRestricted;
  document.getElementById('btn-arm-restore').disabled = isRestricted;
  document.getElementById('btn-arm-restore').style.display = isRestricted ? 'none' : '';
  showArmingStatus(isRestricted ? null : record.armed_until);
  elements.reprintBtn.disabled = isRestricted;
  elements.submitBtn.disabled = true;
  elements.submitBtn.classList.add('is-disabled');
}

function showArmingStatus(armedUntilIso) {
  const label = document.getElementById('arming-status');
  if (armedUntilIso === null) {
    label.textContent = '';   // restricted record: nothing to show
    return;
  }
  const expiry = armedUntilIso ? new Date(armedUntilIso) : null;
  if (expiry && !isNaN(expiry.getTime())) {
    label.textContent = DICTIONARY.armingActive +
      expiry.toLocaleString('it-IT', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) + '.';
  } else {
    label.textContent = DICTIONARY.armingInactive;
  }
}

function populateFormFromRecord(record) {
  try {
    elements.localAccount.value = record.local_account || '';
    if (record.office_suite === 'ms_office') {
      elements.officeMs.checked = true;
      elements.officeKey.value = record.office_key || '';
    } else {
      document.getElementById('office-libre').checked = true;
    }

    const antivirusType = String(record.antivirus || 'none').toLowerCase();
    const antivirusRadio = ALLOWED_ANTIVIRUS_TYPES.includes(antivirusType)
      ? document.querySelector('input[name="av_type"][value="' + antivirusType + '"]')
      : null;
    if (antivirusRadio) {
      antivirusRadio.checked = true;
      elements.avKey.value = record.antivirus_key || '';
    } else {
      elements.avNone.checked = true;
    }

    elements.runCyber.checked = (record.cyber === 'Yes');
    elements.runUpdates.checked = (record.windows_update === 'Yes');
    elements.msUsername.value = record.microsoft_account || '';
    elements.msPassword.value = record.microsoft_password || '';
    toggleFields();
  } catch (error) {
    showAlert('Errore critico durante il caricamento dei dati.');
  }
}

function unlockForm() {
  const wasLocked = isRecordLocked;
  isRecordLocked = false;
  elements.existingRecordBanner.style.display = 'none';
  document.getElementById('btn-delete-record').disabled = false;
  document.getElementById('btn-arm-restore').disabled = false;
  document.getElementById('btn-arm-restore').style.display = '';
  elements.reprintBtn.disabled = false;
  document.querySelectorAll('main.form-container input, main.form-container select')
    .forEach((element) => { element.disabled = false; });

  // Never keep the previous record's credentials in a form for a new serial.
  if (wasLocked) resetRecordFields();
  validateForm();
}

function resetRecordFields() {
  elements.localAccount.value = '';
  elements.officeKey.value = '';
  elements.avKey.value = '';
  elements.msUsername.value = '';
  document.getElementById('office-libre').checked = true;
  elements.avNone.checked = true;
  elements.runCyber.checked = false;
  elements.runUpdates.checked = false;
  acquiredEmail = '';
  acquiredPassword = '';
  isMsCreated = false;
  updateAuthButtonVisuals();
  generateRandomPassword();
  toggleFields();
}


// =========================================================================
// 7. FORM RULES
// =========================================================================

/**
 * Toggles conditional fields only. The cyber rule was removed from here: it
 * used to reset the Cyber checkbox on every call (office change, draft
 * restore, record display).
 */
function toggleFields() {
  if (elements.officeMs.checked) {
    document.getElementById('lbl-opt-ms').after(elements.msOfficeField);
  }
  elements.msOfficeField.classList.toggle('visible', elements.officeMs.checked);

  const showAvKey = elements.avNorton.checked || elements.avMcafee.checked;
  if (elements.avNorton.checked) {
    document.getElementById('lbl-opt-norton').after(elements.avField);
  } else if (elements.avMcafee.checked) {
    document.getElementById('lbl-opt-mcafee').after(elements.avField);
  }

  if (showAvKey) {
    elements.avKeyLabel.innerText = elements.avNorton.checked
      ? DICTIONARY.avNortonKeyLabel
      : DICTIONARY.avMcafeeKeyLabel;
    elements.avKey.placeholder = elements.avNorton.checked
      ? DICTIONARY.avKeyPlaceholderNorton
      : DICTIONARY.avKeyPlaceholderMcafee;
    if (elements.avKey.value !== '') formatAvKey(elements.avKey);
  }
  elements.avField.classList.toggle('visible', showAvKey);
  validateForm();
}

/** Use as onchange of the four antivirus radios (replaces toggleFields(); validateForm();). */
function handleAntivirusChange() {
  toggleFields();
  // Unieuro Everyday Digital already includes Cyber Protection.
  elements.runCyber.checked = elements.avUnevdi.checked;
  validateForm();
}

function isFormValidCheck() {
  const hasPassword = elements.msPassword.value.trim() !== '';
  let isValid = sessionToken !== '' &&
    currentOperatorId !== '00000' &&
    elements.pcSerial.value.trim() !== '' &&
    elements.localAccount.value.trim() !== '' &&
    elements.msUsername.value.trim() !== '' &&
    hasPassword;

  if (elements.officeMs.checked && elements.officeKey.value.length < 29) isValid = false;
  const requiresAvKey = elements.avNorton.checked || elements.avMcafee.checked;
  if (requiresAvKey && elements.avKey.value.length < 29) isValid = false;
  return isValid;
}


// =========================================================================
// 8. MICROSOFT ACCOUNT FLOW
// =========================================================================

function resetAuthButton() {
  document.getElementById('lbl-btn-auth').innerText = DICTIONARY.btnAuth;
  elements.btnAuth.disabled = false;
}

async function startMicrosoftAuth() {
  const authLabel = document.getElementById('lbl-btn-auth');
  clearInterval(msPollingTimer);

  // Open the popup synchronously: browsers block popups opened after an await.
  const popup = window.open('', '_blank');
  if (!popup) {
    showAlert(DICTIONARY.alertPopupBlocked);
    return;
  }
  popup.opener = null;   // the Microsoft page must not control this tab

  authLabel.innerText = DICTIONARY.btnAuthInitializing;
  elements.btnAuth.disabled = true;

  try {
    const uuidData = await getFromServer({ action: 'get_uuid' });
    currentAuthSession = uuidData.uuid;
    const authData = await getFromServer({ action: 'getAuthUrl', session_id: currentAuthSession });
    if (!authData.url) {
      throw new Error(DICTIONARY.alertOauthEmptyUrl);
    }
    popup.location.href = authData.url;
    authLabel.innerText = DICTIONARY.btnAuthWaiting;
    pollForEmail();
  } catch (error) {
    popup.close();
    showAlert(DICTIONARY.alertOauthConnectionError);
    resetAuthButton();
  }
}

function applyAcquiredAccount(email) {
  acquiredEmail = email;
  acquiredPassword = elements.msPassword.value.trim();
  elements.msUsername.value = email;
  document.getElementById('lbl-btn-auth').innerText = DICTIONARY.btnAuthImported;
  updateAuthButtonVisuals();
  showAlert(DICTIONARY.alertOauthSuccess + email);
  validateForm();
}

function pollForEmail() {
  let attempts = 0;
  msPollingTimer = setInterval(async () => {
    attempts++;
    try {
      const result = await postAuthenticated('get_microsoft_email', { session_id: currentAuthSession });
      if (result.email) {
        clearInterval(msPollingTimer);
        applyAcquiredAccount(result.email);
        return;
      }
    } catch (error) {
      if (error.isAuthError) {
        clearInterval(msPollingTimer);
        resetAuthButton();
        return;
      }
    }
    if (attempts > 40) {
      clearInterval(msPollingTimer);
      document.getElementById('lbl-btn-auth').innerText = DICTIONARY.btnAuthTimeout;
      elements.btnAuth.disabled = false;
      updateAuthButtonVisuals();
    }
  }, 3000);
}

/** Cryptographically secure integer in [0, maxExclusive), without modulo bias. */
function secureRandomInt(maxExclusive) {
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buffer = new Uint32Array(1);
  do {
    crypto.getRandomValues(buffer);
  } while (buffer[0] >= limit);
  return buffer[0] % maxExclusive;
}

function generateRandomPassword() {
  const uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowers = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*';
  const allChars = uppers + lowers + numbers + symbols;
  const pick = (set) => set[secureRandomInt(set.length)];

  const chars = [pick(uppers), pick(lowers), pick(numbers), pick(symbols)];
  for (let i = 0; i < 8; i++) {
    chars.push(pick(allChars));
  }

  // Fisher-Yates shuffle with the secure generator.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    const swap = chars[i];
    chars[i] = chars[j];
    chars[j] = swap;
  }

  elements.msPassword.value = chars.join('');
  handleManualAccountEdits();
  validateForm();
}


// =========================================================================
// 9. OCR REQUEST
// =========================================================================
// In elements.captureBtn.onclick, replace the block that builds the payload,
// calls fetch and checks data.status / data.reason (4 lines) with:
//
//   const data = await requestOcr(base64Image);
//   if (typeof data.remaining === 'number') {
//     currentOcrRemaining = data.remaining;
//     updateScannerTitleWithQuota(data.remaining);
//   }

async function requestOcr(base64Image) {
  try {
    return await postAuthenticated('ocr', { image_data: base64Image });
  } catch (error) {
    fetchOcrStatus();   // refresh the remaining quota shown in the title
    throw error;
  }
}


// =========================================================================
// 10. SUBMIT, DELETE, REPRINT
// =========================================================================
// Operator and store are NOT sent: the server takes them from the session.

elements.submitBtn.onclick = async () => {
  if (!isFormValidCheck()) {
    showAlert(DICTIONARY.alertMissingFields);
    return;
  }
  const serial = elements.pcSerial.value.trim().toUpperCase();
  if (!SERIAL_PATTERN.test(serial)) {
    showAlert(DICTIONARY.alertSerialInvalid);
    return;
  }

  elements.submitBtn.disabled = true;
  elements.loadingOverlay.classList.add('active');

  const record = {
    pc_serial: serial,
    local_account: elements.localAccount.value.trim(),
    office_suite: document.querySelector('input[name="office_type"]:checked').value,
    office_key: elements.officeKey.value,
    antivirus: document.querySelector('input[name="av_type"]:checked').value,
    antivirus_key: elements.avKey.value,
    cyber: elements.runCyber.checked ? 'Yes' : 'No',
    microsoft_account: elements.msUsername.value.trim(),
    microsoft_password: elements.msPassword.value.trim(),
    windows_update: elements.runUpdates.checked ? 'Yes' : 'No'
  };

  try {
    await postAuthenticated('insert_record', record);
    sessionStorage.removeItem(DRAFT_STORAGE_KEY);
    elements.loadingOverlay.classList.remove('active');
    showAlert(DICTIONARY.alertUploadSuccess, () => { location.reload(); });
  } catch (error) {
    elements.loadingOverlay.classList.remove('active');
    elements.submitBtn.disabled = false;
    if (!error.isAuthError) {
      showAlert(DICTIONARY.alertUploadError + error.message);
    }
    validateForm();
  }
};

function handleDeleteRecord() {
  const serial = elements.pcSerial.value.trim().toUpperCase();
  if (!serial) return;
  deleteRecordBySerial(serial);
}

// Deletes any record of the operator's store by serial, without needing the form to be filled in.
function handleDeleteBySerial() {
  const typed = window.prompt(DICTIONARY.promptDeleteSerial, elements.pcSerial.value.trim());
  if (typed === null) return;
  const serial = typed.trim().toUpperCase();
  if (!serial) {
    showAlert(DICTIONARY.alertSerialMissing);
    return;
  }
  deleteRecordBySerial(serial);
}

async function deleteRecordBySerial(serial) {
  if (!confirm('⚠️ ATTENZIONE!\n\nStai per eliminare PERMANENTEMENTE il record di ' +
      serial + '.\nProcedere?')) {
    return;
  }

  elements.loadingOverlay.classList.add('active');
  try {
    await postAuthenticated('delete_record', { pc_serial: serial });
    elements.loadingOverlay.classList.remove('active');
    showAlert(DICTIONARY.alertDeleteSuccess, () => {
      // Resets the form only when the deleted record is the one currently shown
      if (elements.pcSerial.value.trim().toUpperCase() === serial) unlockForm();
    });
  } catch (error) {
    elements.loadingOverlay.classList.remove('active');
    if (error.isAuthError) return;
    showAlert(error.message || DICTIONARY.alertNetworkDelete);
  }
}

async function handleArmRestore() {
  const serial = elements.pcSerial.value.trim().toUpperCase();
  if (!serial) {
    showAlert(DICTIONARY.alertSerialMissing);
    return;
  }

  const button = document.getElementById('btn-arm-restore');
  button.disabled = true;
  elements.loadingOverlay.classList.add('active');
  try {
    const result = await postAuthenticated('arm_restore', { pc_serial: serial });
    elements.loadingOverlay.classList.remove('active');
    showArmingStatus(result.armed_until);
    showAlert(result.message);
  } catch (error) {
    elements.loadingOverlay.classList.remove('active');
    if (!error.isAuthError) {
      showAlert(error.message || DICTIONARY.alertNetworkArm);
    }
  }
  button.disabled = false;
}

async function handleReprint() {
  const serial = elements.pcSerial.value.trim().toUpperCase();
  if (!serial) {
    showAlert(DICTIONARY.alertSerialMissing);
    return;
  }
  if (currentOperatorId === '00000' || !sessionToken) {
    showAlert(DICTIONARY.alertLoginRequired);
    return;
  }

  elements.reprintBtn.disabled = true;
  elements.loadingOverlay.classList.add('active');
  try {
    const result = await postAuthenticated('reprint', { pc_serial: serial });
    elements.loadingOverlay.classList.remove('active');
    showAlert(result.message || DICTIONARY.alertReprintSent);
  } catch (error) {
    elements.loadingOverlay.classList.remove('active');
    if (!error.isAuthError) {
      showAlert(error.message || DICTIONARY.alertNetworkReprint);
    }
  }
  elements.reprintBtn.disabled = false;
}


// =========================================================================
// 11. DRAFT STORAGE
// =========================================================================
// The draft holds product keys, so it lives in sessionStorage, expires after
// DRAFT_MAX_AGE_MS and is never written while a registered record is shown.

function saveDraft() {
  if (isRecordLocked) return;
  const draft = {
    savedAt: Date.now(),
    pcSerial: elements.pcSerial.value,
    localAccount: elements.localAccount.value,
    officeType: document.querySelector('input[name="office_type"]:checked')?.value,
    officeKey: elements.officeKey.value,
    avType: document.querySelector('input[name="av_type"]:checked')?.value,
    avKey: elements.avKey.value,
    runCyber: elements.runCyber.checked,
    runUpdates: elements.runUpdates.checked
  };
  sessionStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
}

function restoreDraft() {
  localStorage.removeItem(DRAFT_STORAGE_KEY);   // legacy plain-text draft
  const saved = sessionStorage.getItem(DRAFT_STORAGE_KEY);
  if (!saved) return;

  try {
    const draft = JSON.parse(saved);
    if (!draft.savedAt || Date.now() - draft.savedAt > DRAFT_MAX_AGE_MS) {
      sessionStorage.removeItem(DRAFT_STORAGE_KEY);
      return;
    }

    if (draft.pcSerial) elements.pcSerial.value = String(draft.pcSerial);
    if (draft.localAccount) elements.localAccount.value = String(draft.localAccount);
    if (ALLOWED_OFFICE_TYPES.includes(draft.officeType)) {
      document.querySelector('input[name="office_type"][value="' + draft.officeType + '"]').checked = true;
    }
    if (draft.officeKey) elements.officeKey.value = String(draft.officeKey);
    if (ALLOWED_ANTIVIRUS_TYPES.includes(draft.avType)) {
      document.querySelector('input[name="av_type"][value="' + draft.avType + '"]').checked = true;
    }
    if (draft.avKey) elements.avKey.value = String(draft.avKey);
    elements.runCyber.checked = draft.runCyber === true;
    elements.runUpdates.checked = draft.runUpdates === true;
    toggleFields();
  } catch (error) {
    sessionStorage.removeItem(DRAFT_STORAGE_KEY);
  }
}
