// =========================================================================
// AVVIOPC 3.0 - SECURE BACKEND (Google Apps Script)
// -------------------------------------------------------------------------
// Server-side field encryption (AES + HMAC), session authentication,
// operator login, print queue, Microsoft OAuth and OCR.
//
// Requirements:
//   - Apps Script library "cCryptoGS" (AES) added to the project.
//   - HTML file "print_template" in the project.
//   - Sheets: AVVIOPC_DATA, OPERATORS, CONFIG_SOFTWARE
//     (AUDIT_LOG is created automatically).
//
// SECTIONS
//    1. Configuration
//    2. Secrets management
//    3. Errors and responses
//    4. Security utilities
//    5. Field encryption
//    6. Sessions
//    7. Request routing (doGet / doPost)
//    8. Handlers: authentication
//    9. Handlers: records
//   10. Handlers: PowerShell provisioning
//   11. Handlers: print queue
//   12. Handlers: Microsoft OAuth
//   13. Handlers: OCR
//   14. Spreadsheet admin tools (custom menu)
// =========================================================================


// =========================================================================
// 1. CONFIGURATION
// =========================================================================

const SHEET_DATA = 'AVVIOPC_DATA';
const SHEET_OPERATORS = 'OPERATORS';
const SHEET_SOFTWARE_CONFIG = 'CONFIG_SOFTWARE';
const SHEET_AUDIT_LOG = 'AUDIT_LOG';
const PRINT_TEMPLATE_FILE = 'print_template';

const TIMEZONE = 'Europe/Rome';
const LOGO_BASE_URL = 'https://avviopcpro.github.io/data-importer/logos/';

// Column indexes (0-based) of the AVVIOPC_DATA sheet.
const DATA_COL = {
  TIMESTAMP: 0,
  OPERATOR_ID: 1,
  STORE_ID: 2,
  PC_SERIAL: 3,
  LOCAL_ACCOUNT: 4,      // encrypted
  OFFICE_SUITE: 5,
  OFFICE_KEY: 6,         // encrypted
  ANTIVIRUS: 7,
  ANTIVIRUS_KEY: 8,      // encrypted
  CYBER: 9,
  MS_ACCOUNT: 10,        // encrypted
  MS_PASSWORD: 11,       // encrypted
  WINDOWS_UPDATE: 12,
  PRINT_STATUS: 13
};
const DATA_COLUMN_COUNT = 14;
const ENCRYPTED_DATA_COLUMNS = [
  DATA_COL.LOCAL_ACCOUNT,
  DATA_COL.OFFICE_KEY,
  DATA_COL.ANTIVIRUS_KEY,
  DATA_COL.MS_ACCOUNT,
  DATA_COL.MS_PASSWORD
];

// Column indexes (0-based) of the OPERATORS sheet.
const OPERATOR_COL = {
  ID: 0,
  FIRST_NAME: 1,
  LAST_NAME: 2,
  PIN_HASH: 3,
  STORE_ID: 4,
  STATUS: 5
};

const PRINT_STATUS = {
  PENDING: 'TO PRINT',
  IN_PROGRESS: 'PRINTING',
  DONE: 'PRINTED'
};

// If true, the daemon must call "confirm_print_jobs" after printing.
// Jobs not confirmed within PRINT_CLAIM_SECONDS are delivered again.
// If false (legacy behaviour), jobs are marked PRINTED as soon as delivered.
const PRINT_REQUIRES_CONFIRMATION = false;
const PRINT_CLAIM_SECONDS = 300;

const SESSION_TTL_SECONDS = 21600;      // CacheService hard limit: 6 hours
// Customer records are kept this long (re-provisioning, license recovery),
// then deleted by purgeExpiredRecords().
const RETENTION_MONTHS = 24;
const LOGIN_MAX_FAILURES = 5;
const LOGIN_LOCKOUT_SECONDS = 900;      // 15 minutes
const LOCK_TIMEOUT_MS = 10000;
const MAX_REQUEST_BODY_LENGTH = 5000000;

const ENCRYPTION_PREFIX = 'v2:';        // format: v2:<ciphertext>:<hmac>

const OCR_MONTHLY_SAFE_LIMIT = 900;
const OCR_MAX_IMAGE_LENGTH = 4000000;

const SERIAL_PATTERN = /^[A-Z0-9][A-Z0-9 ._\-\/]{2,63}$/;
const STORE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_\-]{0,31}$/;
const OPERATOR_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,31}$/;
const UUID_PATTERN = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const FORMULA_PREFIX_PATTERN = /^[=+\-@\t\r]/;

const ANTIVIRUS_PROFILES = {
  unevdi: { slot: '10A', logo: 'logo_unevdi.png', showKey: false },
  norton: { slot: '10B', logo: 'logo_norton.png', showKey: true },
  mcafee: { slot: '10C', logo: 'logo_mcafee.png', showKey: true }
};
const DEFAULT_ANTIVIRUS_SLOT = '10D';
const DEFAULT_ANTIVIRUS_LOGO = 'logo_defender.png';

// User-facing messages (Italian).
const MSG = {
  UNAUTHORIZED: 'Accesso non autorizzato.',
  INVALID_CREDENTIALS: 'ID operatore o PIN non validi.',
  SESSION_EXPIRED: 'Sessione scaduta. Effettua di nuovo il login.',
  INVALID_REQUEST: 'Richiesta non valida.',
  INVALID_ACTION: 'Azione non valida.',
  TOO_MANY_REQUESTS: 'Troppe richieste. Riprova tra qualche istante.',
  SERVER_BUSY: 'Server occupato. Riprova tra qualche secondo.',
  GENERIC_ERROR: 'Si è verificato un errore di sistema. Riprova più tardi.'
};


// =========================================================================
// 2. SECRETS MANAGEMENT
// =========================================================================
// Secrets live ONLY in Script Properties (Project Settings), never in code.

const AUTO_GENERATED_SECRETS = [
  'APP_API_KEY',          // web client (GitHub Pages)
  'POWERSHELL_API_KEY',   // PowerShell provisioning
  'PRINT_DAEMON_KEY',     // print daemon
  'ENCRYPTION_KEY',       // AES key for sheet fields
  'MAC_KEY',              // HMAC key for ciphertext integrity
  'PIN_PEPPER'            // secret pepper for PIN hashes
];

const MANUAL_SECRETS = [
  'MS_CLIENT_ID',
  'MS_CLIENT_SECRET',
  'VISION_API_KEY',
  'APP_URL'
];

/**
 * Run ONCE from the editor. Creates any missing random secret and reports
 * which manual secrets are still missing. Never overwrites existing values
 * and never prints secret values to the log.
 */
function initializeSecrets() {
  const props = PropertiesService.getScriptProperties();
  const generated = [];

  AUTO_GENERATED_SECRETS.forEach(function (name) {
    if (!props.getProperty(name)) {
      props.setProperty(name, generateRandomSecret());
      generated.push(name);
    }
  });

  const missing = MANUAL_SECRETS.filter(function (name) {
    return !props.getProperty(name);
  });

  console.log('Generated secrets: ' + (generated.join(', ') || 'none'));
  console.log('Missing manual secrets (set them in Project Settings): ' +
    (missing.join(', ') || 'none'));
}

function generateRandomSecret() {
  return (Utilities.getUuid() + Utilities.getUuid() + Utilities.getUuid())
    .replace(/-/g, '');
}

function getSecret(name) {
  return PropertiesService.getScriptProperties().getProperty(name);
}

function getRequiredSecret(name) {
  const value = getSecret(name);
  if (!value) {
    throw new Error('Missing required secret: ' + name);
  }
  return value;
}


// =========================================================================
// 3. ERRORS AND RESPONSES
// =========================================================================

/** Error whose message is safe to show to the end user. */
class AppError extends Error {}

function successResponse(data) {
  return ContentService
    .createTextOutput(JSON.stringify(Object.assign({ status: 'success' }, data)))
    .setMimeType(ContentService.MimeType.JSON);
}

function errorResponse(error) {
  const isUserError = error instanceof AppError;
  if (!isUserError) {
    console.error('SERVER ERROR: ' + (error && error.stack ? error.stack : error));
  }
  return ContentService
    .createTextOutput(JSON.stringify({
      status: 'error',
      message: isUserError ? error.message : MSG.GENERIC_ERROR
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

function buildHtmlMessage(message, isSuccess) {
  const color = isSuccess ? 'green' : 'red';
  return HtmlService.createHtmlOutput(
    '<h3 style="color:' + color + ';text-align:center;margin-top:50px;">' +
    message + '</h3>'
  );
}


// =========================================================================
// 4. SECURITY UTILITIES
// =========================================================================

/** Constant-time string comparison. */
function constantTimeEquals(a, b) {
  const left = String(a);
  const right = String(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    diff |= (left.charCodeAt(i) || 0) ^ (right.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/** Checks a client-supplied key against a stored secret. Fails if secret is unset. */
function isValidKey(candidate, secretName) {
  const secret = getSecret(secretName);
  if (!secret || typeof candidate !== 'string' || candidate === '') {
    return false;
  }
  return constantTimeEquals(candidate, secret);
}

function bytesToHex(bytes) {
  return bytes.map(function (b) {
    return ('0' + (b & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function computeHmacHex(message, key) {
  return bytesToHex(Utilities.computeHmacSha256Signature(message, key));
}

function escapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---- Input validation ---------------------------------------------------

function normalizeSerial(value) {
  const serial = String(value === undefined || value === null ? '' : value)
    .trim()
    .toUpperCase();
  if (!SERIAL_PATTERN.test(serial)) {
    throw new AppError('Numero seriale non valido.');
  }
  return serial;
}

function normalizeStoreId(value) {
  const storeId = String(value === undefined || value === null ? '' : value).trim();
  if (!STORE_ID_PATTERN.test(storeId)) {
    throw new AppError('ID negozio non valido.');
  }
  return storeId;
}

/** Returns null (instead of throwing) so login can answer with a generic error. */
function normalizeOperatorId(value) {
  const operatorId = String(value === undefined || value === null ? '' : value).trim();
  return OPERATOR_ID_PATTERN.test(operatorId) ? operatorId : null;
}

/** Plain text stored unencrypted in the sheet: rejects formula-injection prefixes. */
function normalizeText(value, label, maxLength) {
  const text = String(value === undefined || value === null ? '' : value).trim();
  if (text.length > maxLength) {
    throw new AppError('Il campo "' + label + '" è troppo lungo.');
  }
  if (FORMULA_PREFIX_PATTERN.test(text)) {
    throw new AppError('Il campo "' + label + '" contiene caratteri non validi.');
  }
  return text;
}

/** Secret text (stored encrypted): preserved as typed, only length-checked. */
function normalizeSecretText(value, label, maxLength) {
  const text = String(value === undefined || value === null ? '' : value);
  if (text.length > maxLength) {
    throw new AppError('Il campo "' + label + '" è troppo lungo.');
  }
  return text;
}

// ---- Rate limiting ------------------------------------------------------
// Apps Script exposes no client IP, so buckets are keyed by server-trusted
// values only (action name or authenticated operator ID), never by
// attacker-controlled input. Counters are approximate (no locking).

function enforceRateLimit(bucket, maxRequests, windowSeconds) {
  const cache = CacheService.getScriptCache();
  const key = 'rl_' + bucket;
  const now = Date.now();

  let entry = null;
  try {
    entry = JSON.parse(cache.get(key));
  } catch (error) {
    entry = null;
  }

  if (!entry || now - entry.start >= windowSeconds * 1000) {
    entry = { start: now, count: 0 };
  }
  if (entry.count >= maxRequests) {
    throw new AppError(MSG.TOO_MANY_REQUESTS);
  }

  entry.count++;
  cache.put(key, JSON.stringify(entry), windowSeconds);
}

// ---- Locking ------------------------------------------------------------

function withScriptLock(callback) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(LOCK_TIMEOUT_MS)) {
    throw new AppError(MSG.SERVER_BUSY);
  }
  try {
    return callback();
  } finally {
    lock.releaseLock();
  }
}

// ---- Sheets and audit ---------------------------------------------------

function getSheetOrThrow(name) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
  if (!sheet) {
    throw new Error('Sheet not found: ' + name);
  }
  return sheet;
}

/** Appends one audit line. Never logs secrets. Never breaks the request. */
function writeAuditLog(actor, action, target, outcome) {
  try {
    const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = spreadsheet.getSheetByName(SHEET_AUDIT_LOG);
    if (!sheet) {
      sheet = spreadsheet.insertSheet(SHEET_AUDIT_LOG);
      sheet.appendRow(['TIMESTAMP', 'ACTOR', 'ACTION', 'TARGET', 'OUTCOME']);
    }
    sheet.appendRow([new Date(), String(actor), String(action), String(target), String(outcome)]);
  } catch (error) {
    console.error('Audit log failure: ' + error);
  }
}

function hashPin(pin, operatorId) {
  return computeHmacHex(operatorId + ':' + pin, getRequiredSecret('PIN_PEPPER'));
}

function findRecordRow(data, normalizedSerial) {
  for (let i = data.length - 1; i > 0; i--) {
    if (String(data[i][DATA_COL.PC_SERIAL]).trim().toUpperCase() === normalizedSerial) {
      return i;
    }
  }
  return -1;
}


// =========================================================================
// 5. FIELD ENCRYPTION
// =========================================================================
// Stored format: "v2:<AES ciphertext>:<HMAC-SHA256 of ciphertext>".
// Values without the prefix are legacy data and are read in compatibility
// mode until upgradeEncryptionFormat() is run.

let cachedCryptoKeys = null;

function loadCryptoKeys() {
  if (!cachedCryptoKeys) {
    cachedCryptoKeys = {
      encryptionKey: getRequiredSecret('ENCRYPTION_KEY'),
      macKey: getRequiredSecret('MAC_KEY')
    };
  }
  return cachedCryptoKeys;
}

function createCipher(encryptionKey) {
  return new cCryptoGS.Cipher(encryptionKey, 'AES');
}

function computeMac(cipherText, macKey) {
  return computeHmacHex(cipherText, macKey);
}

function encryptField(plainText, keys) {
  if (!plainText) {
    return '';
  }
  const activeKeys = keys || loadCryptoKeys();
  const cipherText = createCipher(activeKeys.encryptionKey).encrypt(String(plainText));
  return ENCRYPTION_PREFIX + cipherText + ':' + computeMac(cipherText, activeKeys.macKey);
}

function decryptField(storedValue, keys) {
  if (!storedValue) {
    return '';
  }
  const activeKeys = keys || loadCryptoKeys();
  const value = String(storedValue);

  if (value.indexOf(ENCRYPTION_PREFIX) === 0) {
    const parts = value.slice(ENCRYPTION_PREFIX.length).split(':');
    const isIntact = parts.length === 2 &&
      constantTimeEquals(parts[1], computeMac(parts[0], activeKeys.macKey));
    if (!isIntact) {
      throw new Error('Integrity check failed for an encrypted field.');
    }
    return createCipher(activeKeys.encryptionKey).decrypt(parts[0]);
  }

  // Legacy value (no prefix): try to decrypt, otherwise treat as plain text.
  try {
    const decrypted = createCipher(activeKeys.encryptionKey).decrypt(value);
    if (decrypted) {
      return decrypted;
    }
  } catch (error) {
    // Fall through to the legacy plain-text case.
  }
  console.warn('Legacy non-encrypted value detected. Run upgradeEncryptionFormat().');
  return value;
}

/**
 * Re-encrypts every encrypted column of AVVIOPC_DATA.
 * rotateKeys = false: upgrades legacy values to the v2 format (same keys).
 * rotateKeys = true:  also generates NEW encryption and MAC keys.
 * Properties are updated only after all columns have been written.
 * MAKE A COPY OF THE SPREADSHEET BEFORE RUNNING.
 */
function reencryptAllRecords(rotateKeys) {
  return withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const lastRow = sheet.getLastRow();
    if (lastRow < 2) {
      return 0;
    }

    const currentKeys = loadCryptoKeys();
    const targetKeys = rotateKeys
      ? { encryptionKey: generateRandomSecret(), macKey: generateRandomSecret() }
      : currentKeys;
    const rowCount = lastRow - 1;

    // Compute everything in memory first, then write.
    const newColumns = ENCRYPTED_DATA_COLUMNS.map(function (columnIndex) {
      const range = sheet.getRange(2, columnIndex + 1, rowCount, 1);
      const converted = range.getValues().map(function (row) {
        return [encryptField(decryptField(row[0], currentKeys), targetKeys)];
      });
      return { range: range, values: converted };
    });

    newColumns.forEach(function (column) {
      column.range.setValues(column.values);
    });

    if (rotateKeys) {
      PropertiesService.getScriptProperties().setProperties({
        ENCRYPTION_KEY: targetKeys.encryptionKey,
        MAC_KEY: targetKeys.macKey
      });
      cachedCryptoKeys = null;
    }
    return rowCount;
  });
}

function upgradeEncryptionFormat() {
  return reencryptAllRecords(false);
}

function rotateEncryptionKeys() {
  return reencryptAllRecords(true);
}


// =========================================================================
// 6. SESSIONS
// =========================================================================

function createSession(operatorId, storeId) {
  const token = Utilities.getUuid();
  CacheService.getScriptCache().put(
    'session_' + token,
    JSON.stringify({ operatorId: operatorId, storeId: storeId }),
    SESSION_TTL_SECONDS
  );
  return token;
}

/** Returns { operatorId, storeId } or null. */
function getSession(token) {
  if (typeof token !== 'string' || !UUID_PATTERN.test(token)) {
    return null;
  }
  const raw = CacheService.getScriptCache().get('session_' + token);
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw);
  } catch (error) {
    return null;
  }
}

function requireSession(token) {
  const session = getSession(token);
  if (!session) {
    throw new AppError(MSG.SESSION_EXPIRED);
  }
  return session;
}

function destroySession(token) {
  if (typeof token === 'string' && UUID_PATTERN.test(token)) {
    CacheService.getScriptCache().remove('session_' + token);
  }
}


// =========================================================================
// 7. REQUEST ROUTING
// =========================================================================

function parseRequestBody(e) {
  if (!e || !e.postData || !e.postData.contents) {
    throw new AppError(MSG.INVALID_REQUEST);
  }
  if (e.postData.contents.length > MAX_REQUEST_BODY_LENGTH) {
    throw new AppError('Richiesta troppo grande.');
  }
  let payload;
  try {
    payload = JSON.parse(e.postData.contents);
  } catch (error) {
    throw new AppError(MSG.INVALID_REQUEST);
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new AppError(MSG.INVALID_REQUEST);
  }
  return payload;
}

/**
 * GET routes (no session, only API keys):
 *   - Microsoft OAuth callback and URL builder
 *   - get_uuid
 *   - get_operators, get_ocr_status          (APP_API_KEY)
 * Sensitive record access is POST-only: API keys never travel in the URL.
 */
function doGet(e) {
  try {
    const params = (e && e.parameter) || {};
    const action = params.action;

    // OAuth callback (the "state" nonce is verified inside the handler).
    if (params.state && (params.code || params.error)) {
      enforceRateLimit('oauth_callback', 60, 60);
      return handleMicrosoftCallback(params.code, params.error, params.state);
    }

    if (action === 'getAuthUrl') {
      enforceRateLimit('oauth_url', 60, 60);
      return successResponse(buildMicrosoftAuthUrl(params.session_id));
    }

    if (action === 'get_uuid') {
      enforceRateLimit('get_uuid', 120, 60);
      return successResponse({ uuid: Utilities.getUuid() });
    }

    // Web app public data routes.
    if (isValidKey(params.api_key, 'APP_API_KEY')) {
      enforceRateLimit('app_get', 300, 60);
      if (action === 'get_operators') {
        return successResponse(handleGetOperators());
      }
      if (action === 'get_ocr_status') {
        return successResponse(getOcrStatus());
      }
      throw new AppError(MSG.INVALID_REQUEST);
    }

    throw new AppError(MSG.UNAUTHORIZED);
  } catch (error) {
    return errorResponse(error);
  }
}

/**
 * POST routes:
 *   - login                              (APP_API_KEY + PIN)
 *   - get_print_jobs, confirm_print_jobs (PRINT_DAEMON_KEY)
 *   - provision_serial                   (POWERSHELL_API_KEY)
 *   - everything else                    (valid session token required)
 * A request without "action" is treated as insert_record (legacy clients).
 */
function doPost(e) {
  try {
    const payload = parseRequestBody(e);
    const action = payload.action || 'insert_record';

    // Public routes.
    if (action === 'login') {
      enforceRateLimit('login', 120, 60);
      return successResponse(handleLogin(payload));
    }
    if (action === 'get_print_jobs') {
      enforceRateLimit('print_daemon', 120, 60);
      return successResponse(handleGetPrintJobs(payload));
    }
    if (action === 'confirm_print_jobs') {
      enforceRateLimit('print_daemon', 120, 60);
      return successResponse(handleConfirmPrintJobs(payload));
    }
    if (action === 'provision_serial') {
      enforceRateLimit('provisioning', 120, 60);
      if (!isValidKey(payload.api_key, 'POWERSHELL_API_KEY')) {
        writeAuditLog('powershell', 'provisioning', '-', 'DENIED');
        throw new AppError(MSG.UNAUTHORIZED);
      }
      return successResponse(handleProvisioningRequest(payload.serial));
    }

    // Authenticated routes: the identity comes from the server-side session.
    const session = requireSession(payload.token);
    enforceRateLimit('op_' + session.operatorId, 60, 60);

    switch (action) {
      case 'check_serial_post':
        return successResponse(handleCheckSerial(payload, session));
      case 'insert_record':
        return successResponse(handleInsertRecord(payload, session));
      case 'delete_record':
        return successResponse(handleDeleteRecord(payload, session));
      case 'reprint':
        return successResponse(handleReprint(payload, session));
      case 'ocr':
        return successResponse(handleOcrRequest(payload, session));
      case 'get_microsoft_email':
        return successResponse(handleGetMicrosoftEmail(payload));
      case 'logout':
        destroySession(payload.token);
        return successResponse({ message: 'Disconnesso.' });
      default:
        throw new AppError(MSG.INVALID_ACTION);
    }
  } catch (error) {
    return errorResponse(error);
  }
}


// =========================================================================
// 8. HANDLERS: AUTHENTICATION
// =========================================================================

function handleLogin(payload) {
  if (!isValidKey(payload.api_key, 'APP_API_KEY')) {
    throw new AppError(MSG.UNAUTHORIZED);
  }

  const operatorId = normalizeOperatorId(payload.operator_id);
  const pin = String(payload.pin === undefined || payload.pin === null ? '' : payload.pin)
    .slice(0, 64);
  if (!operatorId) {
    throw new AppError(MSG.INVALID_CREDENTIALS);
  }

  const cache = CacheService.getScriptCache();
  const failKey = 'login_fail_' + operatorId;
  const failCount = parseInt(cache.get(failKey) || '0', 10);
  if (failCount >= LOGIN_MAX_FAILURES) {
    writeAuditLog(operatorId, 'login', '-', 'LOCKED_OUT');
    throw new AppError('Troppi tentativi falliti. Account bloccato per 15 minuti.');
  }

  const rows = getSheetOrThrow(SHEET_OPERATORS).getDataRange().getValues();
  let operatorRow = null;
  for (let i = 1; i < rows.length; i++) {
    const isSameOperator = String(rows[i][OPERATOR_COL.ID]).trim() === operatorId;
    const isActive = String(rows[i][OPERATOR_COL.STATUS]).trim().toUpperCase() === 'ACTIVE';
    if (isSameOperator && isActive) {
      operatorRow = rows[i];
      break;
    }
  }

  // The hash is always computed so response time does not reveal whether
  // the operator exists.
  const storedHash = operatorRow ? String(operatorRow[OPERATOR_COL.PIN_HASH]).trim() : '';
  const inputHash = hashPin(pin, operatorId);
  const isValid = constantTimeEquals(inputHash, storedHash) && operatorRow !== null;

  if (!isValid) {
    cache.put(failKey, String(failCount + 1), LOGIN_LOCKOUT_SECONDS);
    writeAuditLog(operatorId, 'login', '-', 'FAILED');
    throw new AppError(MSG.INVALID_CREDENTIALS);
  }

  cache.remove(failKey);
  const storeId = String(operatorRow[OPERATOR_COL.STORE_ID]).trim();
  const token = createSession(operatorId, storeId);
  writeAuditLog(operatorId, 'login', storeId, 'SUCCESS');
  return { token: token, message: 'Accesso effettuato.' };
}

function handleGetOperators() {
  const rows = getSheetOrThrow(SHEET_OPERATORS).getDataRange().getValues();
  const operators = [];
  for (let i = 1; i < rows.length; i++) {
    const isActive = String(rows[i][OPERATOR_COL.STATUS]).trim().toUpperCase() === 'ACTIVE';
    if (isActive && rows[i][OPERATOR_COL.ID] !== '') {
      // The PIN hash is never returned.
      operators.push({
        id: rows[i][OPERATOR_COL.ID],
        firstName: rows[i][OPERATOR_COL.FIRST_NAME],
        lastName: rows[i][OPERATOR_COL.LAST_NAME],
        storeId: rows[i][OPERATOR_COL.STORE_ID]
      });
    }
  }
  return { data: operators };
}


// =========================================================================
// 9. HANDLERS: RECORDS
// =========================================================================

function handleCheckSerial(payload, session) {
  const serial = normalizeSerial(payload.serial);
  const data = getSheetOrThrow(SHEET_DATA).getDataRange().getValues();
  const rowIndex = findRecordRow(data, serial);

  if (rowIndex === -1) {
    return { exists: false };
  }

  const row = data[rowIndex];
  const isOwnStore = String(row[DATA_COL.STORE_ID]).trim() === session.storeId;

  // Records from other stores are returned WITHOUT any credential.
  if (!isOwnStore) {
    return {
      exists: true,
      restricted: true,
      record: {
        timestamp: row[DATA_COL.TIMESTAMP],
        operator_id: row[DATA_COL.OPERATOR_ID],
        store_id: row[DATA_COL.STORE_ID],
        pc_serial: row[DATA_COL.PC_SERIAL],
        local_account: '',
        office_suite: row[DATA_COL.OFFICE_SUITE],
        office_key: '',
        antivirus: row[DATA_COL.ANTIVIRUS],
        antivirus_key: '',
        cyber: row[DATA_COL.CYBER],
        microsoft_account: '',
        microsoft_password: '',
        windows_update: row[DATA_COL.WINDOWS_UPDATE]
      }
    };
  }

  const keys = loadCryptoKeys();
  return {
    exists: true,
    record: {
      timestamp: row[DATA_COL.TIMESTAMP],
      operator_id: row[DATA_COL.OPERATOR_ID],
      store_id: row[DATA_COL.STORE_ID],
      pc_serial: row[DATA_COL.PC_SERIAL],
      local_account: decryptField(row[DATA_COL.LOCAL_ACCOUNT], keys),
      office_suite: row[DATA_COL.OFFICE_SUITE],
      office_key: decryptField(row[DATA_COL.OFFICE_KEY], keys),
      antivirus: row[DATA_COL.ANTIVIRUS],
      antivirus_key: decryptField(row[DATA_COL.ANTIVIRUS_KEY], keys),
      cyber: row[DATA_COL.CYBER],
      microsoft_account: decryptField(row[DATA_COL.MS_ACCOUNT], keys),
      microsoft_password: decryptField(row[DATA_COL.MS_PASSWORD], keys),
      windows_update: row[DATA_COL.WINDOWS_UPDATE]
    }
  };
}

function validateRecordPayload(payload) {
  return {
    pcSerial: normalizeSerial(payload.pc_serial),
    localAccount: normalizeSecretText(payload.local_account, 'Account locale', 256),
    officeSuite: normalizeText(payload.office_suite, 'Suite Office', 100),
    officeKey: normalizeSecretText(payload.office_key, 'Chiave Office', 256).trim(),
    antivirus: normalizeText(payload.antivirus, 'Antivirus', 100),
    antivirusKey: normalizeSecretText(payload.antivirus_key, 'Chiave antivirus', 256).trim(),
    cyber: normalizeText(payload.cyber, 'Cyber', 100),
    msAccount: normalizeSecretText(payload.microsoft_account, 'Account Microsoft', 256).trim(),
    msPassword: normalizeSecretText(payload.microsoft_password, 'Password Microsoft', 256),
    windowsUpdate: normalizeText(payload.windows_update, 'Windows Update', 100)
  };
}

function handleInsertRecord(payload, session) {
  const record = validateRecordPayload(payload);

  return withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const data = sheet.getDataRange().getValues();

    if (findRecordRow(data, record.pcSerial) !== -1) {
      throw new AppError('Il seriale esiste già. Impossibile procedere.');
    }

    // Operator and store come from the session, never from the request.
    sheet.appendRow([
      new Date().toISOString(),
      session.operatorId,
      session.storeId,
      record.pcSerial,
      encryptField(record.localAccount),
      record.officeSuite,
      encryptField(record.officeKey),
      record.antivirus,
      encryptField(record.antivirusKey),
      record.cyber,
      encryptField(record.msAccount),
      encryptField(record.msPassword),
      record.windowsUpdate,
      PRINT_STATUS.PENDING
    ]);

    writeAuditLog(session.operatorId, 'insert_record', record.pcSerial, 'SUCCESS');
    return { message: 'Dati salvati.' };
  });
}

function handleDeleteRecord(payload, session) {
  const serial = normalizeSerial(payload.pc_serial);

  return withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const data = sheet.getDataRange().getValues();
    const rowIndex = findRecordRow(data, serial);

    if (rowIndex === -1) {
      throw new AppError('Record non trovato.');
    }
    if (String(data[rowIndex][DATA_COL.STORE_ID]).trim() !== session.storeId) {
      writeAuditLog(session.operatorId, 'delete_record', serial, 'DENIED');
      throw new AppError('Non hai i permessi per eliminare record di altri negozi.');
    }

    sheet.deleteRow(rowIndex + 1);
    writeAuditLog(session.operatorId, 'delete_record', serial, 'SUCCESS');
    return { message: 'Record eliminato.' };
  });
}

function handleReprint(payload, session) {
  const serial = normalizeSerial(payload.pc_serial);

  return withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const data = sheet.getDataRange().getValues();
    const rowIndex = findRecordRow(data, serial);

    if (rowIndex === -1) {
      throw new AppError('Seriale non trovato.');
    }
    if (String(data[rowIndex][DATA_COL.STORE_ID]).trim() !== session.storeId) {
      writeAuditLog(session.operatorId, 'reprint', serial, 'DENIED');
      throw new AppError('Non hai i permessi per ristampare record di altri negozi.');
    }

    sheet.getRange(rowIndex + 1, DATA_COL.PRINT_STATUS + 1).setValue(PRINT_STATUS.PENDING);
    writeAuditLog(session.operatorId, 'reprint', serial, 'SUCCESS');
    return { message: 'Ristampa messa in coda.' };
  });
}


// =========================================================================
// 10. HANDLERS: POWERSHELL PROVISIONING
// =========================================================================
// Exact serial match only: partial matches could hand the credentials of
// one PC to a different machine.

function handleProvisioningRequest(rawSerial) {
  const serial = normalizeSerial(rawSerial);
  const data = getSheetOrThrow(SHEET_DATA).getDataRange().getValues();
  const rowIndex = findRecordRow(data, serial);

  if (rowIndex === -1) {
    writeAuditLog('powershell', 'provisioning', serial, 'NOT_FOUND');
    // Keeps the legacy response shape: { status: "not_found" }.
    return { status: 'not_found' };
  }

  writeAuditLog('powershell', 'provisioning', serial, 'SUCCESS');
  return buildProvisioningResponse(data[rowIndex]);
}

function buildProvisioningResponse(row) {
  const keys = loadCryptoKeys();
  return {
    match_type: 'exact_match',
    db_serial: String(row[DATA_COL.PC_SERIAL]).trim(),
    operator: row[DATA_COL.OPERATOR_ID],
    store_id: row[DATA_COL.STORE_ID],
    pc_serial: row[DATA_COL.PC_SERIAL],
    local_account: decryptField(row[DATA_COL.LOCAL_ACCOUNT], keys),
    office_suite: row[DATA_COL.OFFICE_SUITE],
    office_key: decryptField(row[DATA_COL.OFFICE_KEY], keys),
    antivirus: row[DATA_COL.ANTIVIRUS],
    antivirus_key: decryptField(row[DATA_COL.ANTIVIRUS_KEY], keys),
    cyber: row[DATA_COL.CYBER],
    msa_email: decryptField(row[DATA_COL.MS_ACCOUNT], keys),
    msa_password: decryptField(row[DATA_COL.MS_PASSWORD], keys),
    windows_update: row[DATA_COL.WINDOWS_UPDATE]
  };
}


// =========================================================================
// 11. HANDLERS: PRINT QUEUE
// =========================================================================

function printClaimKey(serial) {
  return 'print_claim_' + String(serial).trim().toUpperCase();
}

function isJobPrintable(status, serial, cache) {
  if (status === PRINT_STATUS.PENDING) {
    return true;
  }
  return PRINT_REQUIRES_CONFIRMATION &&
    status === PRINT_STATUS.IN_PROGRESS &&
    !cache.get(printClaimKey(serial));
}

function handleGetPrintJobs(payload) {
  if (!isValidKey(payload.daemon_key, 'PRINT_DAEMON_KEY')) {
    writeAuditLog('print_daemon', 'get_print_jobs', '-', 'DENIED');
    throw new AppError(MSG.UNAUTHORIZED);
  }
  const storeId = normalizeStoreId(payload.store_id);

  return withScriptLock(function () {
    const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = getSheetOrThrow(SHEET_DATA);
    const template = loadPrintTemplate();
    const catalog = loadSoftwareCatalog(spreadsheet);
    const keys = loadCryptoKeys();
    const cache = CacheService.getScriptCache();
    const data = sheet.getDataRange().getValues();
    const jobs = [];

    for (let i = 1; i < data.length; i++) {
      const row = data[i];
      if (String(row[DATA_COL.STORE_ID]).trim() !== storeId) {
        continue;
      }
      const serial = String(row[DATA_COL.PC_SERIAL]).trim();
      const status = String(row[DATA_COL.PRINT_STATUS]).trim();
      if (!isJobPrintable(status, serial, cache)) {
        continue;
      }

      const job = {
        timestamp: row[DATA_COL.TIMESTAMP],
        operator_id: row[DATA_COL.OPERATOR_ID],
        store_id: row[DATA_COL.STORE_ID],
        pc_serial: row[DATA_COL.PC_SERIAL],
        local_account: decryptField(row[DATA_COL.LOCAL_ACCOUNT], keys),
        office_suite: row[DATA_COL.OFFICE_SUITE],
        office_key: decryptField(row[DATA_COL.OFFICE_KEY], keys),
        antivirus: row[DATA_COL.ANTIVIRUS],
        antivirus_key: decryptField(row[DATA_COL.ANTIVIRUS_KEY], keys),
        cyber: row[DATA_COL.CYBER],
        microsoft_account: decryptField(row[DATA_COL.MS_ACCOUNT], keys),
        microsoft_password: decryptField(row[DATA_COL.MS_PASSWORD], keys),
        windows_update: row[DATA_COL.WINDOWS_UPDATE]
      };
      job.compiled_html = renderPrintTemplate(template, buildPrintValues(job, catalog));
      jobs.push(job);

      const statusCell = sheet.getRange(i + 1, DATA_COL.PRINT_STATUS + 1);
      if (PRINT_REQUIRES_CONFIRMATION) {
        statusCell.setValue(PRINT_STATUS.IN_PROGRESS);
        cache.put(printClaimKey(serial), '1', PRINT_CLAIM_SECONDS);
      } else {
        statusCell.setValue(PRINT_STATUS.DONE);
      }
    }

    writeAuditLog('print_daemon', 'get_print_jobs', storeId, 'DELIVERED:' + jobs.length);
    return { data: jobs };
  });
}

/** Used only when PRINT_REQUIRES_CONFIRMATION is true. */
function handleConfirmPrintJobs(payload) {
  if (!isValidKey(payload.daemon_key, 'PRINT_DAEMON_KEY')) {
    writeAuditLog('print_daemon', 'confirm_print_jobs', '-', 'DENIED');
    throw new AppError(MSG.UNAUTHORIZED);
  }
  const storeId = normalizeStoreId(payload.store_id);
  const serials = Array.isArray(payload.serials) ? payload.serials.slice(0, 200) : [];
  const serialSet = {};
  serials.forEach(function (serial) {
    serialSet[String(serial).trim().toUpperCase()] = true;
  });

  return withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const cache = CacheService.getScriptCache();
    const data = sheet.getDataRange().getValues();
    let confirmed = 0;

    for (let i = 1; i < data.length; i++) {
      const serial = String(data[i][DATA_COL.PC_SERIAL]).trim().toUpperCase();
      const isSameStore = String(data[i][DATA_COL.STORE_ID]).trim() === storeId;
      const isInProgress = String(data[i][DATA_COL.PRINT_STATUS]).trim() === PRINT_STATUS.IN_PROGRESS;
      if (isSameStore && isInProgress && serialSet[serial]) {
        sheet.getRange(i + 1, DATA_COL.PRINT_STATUS + 1).setValue(PRINT_STATUS.DONE);
        cache.remove(printClaimKey(serial));
        confirmed++;
      }
    }

    writeAuditLog('print_daemon', 'confirm_print_jobs', storeId, 'CONFIRMED:' + confirmed);
    return { message: 'Conferma registrata.', confirmed: confirmed };
  });
}

// ---- Print template rendering -------------------------------------------

function loadPrintTemplate() {
  try {
    return HtmlService.createHtmlOutputFromFile(PRINT_TEMPLATE_FILE).getContent();
  } catch (error) {
    throw new Error('Print template "' + PRINT_TEMPLATE_FILE + '" is missing or unreadable.');
  }
}

/** Returns { "01A": { name, desc }, ... } from the CONFIG_SOFTWARE sheet. */
function loadSoftwareCatalog(spreadsheet) {
  const catalog = {};
  const configSheet = spreadsheet.getSheetByName(SHEET_SOFTWARE_CONFIG);
  if (!configSheet) {
    return catalog;
  }
  const rows = configSheet.getDataRange().getValues();
  for (let i = 1; i < rows.length; i++) {
    const slotKey = String(rows[i][0]).trim().toUpperCase();
    if (slotKey !== '') {
      catalog[slotKey] = {
        name: String(rows[i][1]).trim(),
        desc: String(rows[i][2]).trim()
      };
    }
  }
  return catalog;
}

function formatTimestamp(value) {
  if (!value) {
    return 'N/D';
  }
  try {
    const date = value instanceof Date ? value : new Date(value);
    return Utilities.formatDate(date, TIMEZONE, 'dd/MM/yyyy HH:mm');
  } catch (error) {
    return String(value);
  }
}

function buildPrintValues(job, catalog) {
  const values = {
    PC_SERIAL: job.pc_serial || 'N/D',
    LOCAL_ACCOUNT: job.local_account || 'N/D',
    DATA_STAMPA: formatTimestamp(job.timestamp),
    MS_EMAIL: job.microsoft_account || 'N/D',
    MS_PASSWORD: job.microsoft_password || 'N/D',
    OPERATOR_ID: job.operator_id || 'N/D',
    STORE_ID: job.store_id || 'N/D'
  };

  // Generic software slots 01..07.
  for (let n = 1; n <= 7; n++) {
    const slot = ('0' + n).slice(-2);
    const entry = catalog[slot + 'A'];
    values['APPLICATION_' + slot] = entry ? entry.name : '';
    values['DESCRIPTION_' + slot] = entry ? entry.desc : '';
  }

  // Slot 08: cyber security.
  const cyberEntry = catalog['08A'];
  values.APPLICATION_08 = cyberEntry ? cyberEntry.name : 'Cyber Security';
  values.DESCRIPTION_08 = cyberEntry ? cyberEntry.desc : 'Protezione avanzata integrata.';
  values.CYBER_STATUS =
    String(job.cyber).trim().toLowerCase() === 'no' ? 'Non richiesto' : 'Installato';

  Object.assign(values, buildOfficeValues(job, catalog), buildAntivirusValues(job, catalog));
  return values;
}

function buildOfficeValues(job, catalog) {
  const isMsOffice = String(job.office_suite).toLowerCase() === 'ms_office';
  const entry = catalog[isMsOffice ? '09A' : '09B'];
  const values = {
    APPLICATION_09: entry ? entry.name : '',
    DESCRIPTION_09: entry ? entry.desc : '',
    SHOW_OFFICE: 'none',
    OFFICE_KEY: '',
    OFFICE_KEY_DISPLAY: 'none',
    OFFICE_LOGO_URL: ''
  };

  if (isMsOffice) {
    const key = String(job.office_key || '').trim();
    values.SHOW_OFFICE = 'flex';
    values.OFFICE_KEY = key;
    values.OFFICE_KEY_DISPLAY = key !== '' ? 'flex' : 'none';
    values.OFFICE_LOGO_URL = LOGO_BASE_URL + 'logo_office.png';
  } else if (entry && entry.name !== '') {
    values.SHOW_OFFICE = 'flex';
    values.OFFICE_LOGO_URL = LOGO_BASE_URL + 'logo_libreoffice.png';
  }
  return values;
}

function buildAntivirusValues(job, catalog) {
  const type = String(job.antivirus).toLowerCase();
  const profile = Object.prototype.hasOwnProperty.call(ANTIVIRUS_PROFILES, type)
    ? ANTIVIRUS_PROFILES[type]
    : null;
  const entry = catalog[profile ? profile.slot : DEFAULT_ANTIVIRUS_SLOT];
  const values = {
    APPLICATION_10: entry ? entry.name : '',
    DESCRIPTION_10: entry ? entry.desc : '',
    SHOW_AV: 'none',
    AV_KEY: '',
    AV_KEY_DISPLAY: 'none',
    AV_LOGO_URL: ''
  };

  if (profile) {
    const key = String(job.antivirus_key || '').trim();
    values.SHOW_AV = 'flex';
    values.AV_LOGO_URL = LOGO_BASE_URL + profile.logo;
    if (profile.showKey) {
      values.AV_KEY = key;
      values.AV_KEY_DISPLAY = key !== '' ? 'flex' : 'none';
    }
  } else if (entry && entry.name !== '') {
    values.SHOW_AV = 'flex';
    values.AV_LOGO_URL = LOGO_BASE_URL + DEFAULT_ANTIVIRUS_LOGO;
  }
  return values;
}

/**
 * Single-pass placeholder replacement. Values are HTML-escaped and are never
 * re-scanned, so a value containing "{{X}}" or "$&" cannot alter the output.
 */
function renderPrintTemplate(template, values) {
  return template.replace(/\{\{([A-Z0-9_]+)\}\}/g, function (match, name) {
    return Object.prototype.hasOwnProperty.call(values, name)
      ? escapeHtml(values[name])
      : '';
  });
}


// =========================================================================
// 12. HANDLERS: MICROSOFT OAUTH
// =========================================================================
// Flow:
//   1. Client gets a UUID via get_uuid and calls getAuthUrl?session_id=<uuid>.
//   2. Server creates a random one-time "state" bound to that session_id.
//   3. Microsoft redirects to the callback; state is verified and consumed.
//   4. The e-mail is cached for 5 minutes under the session_id.
//   5. Logged-in client calls POST get_microsoft_email { session_id }.

function buildMicrosoftAuthUrl(sessionId) {
  if (typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId)) {
    throw new AppError('Sessione di autenticazione non valida.');
  }

  const state = Utilities.getUuid();
  CacheService.getScriptCache().put('oauth_state_' + state, sessionId, 600);

  const url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize' +
    '?client_id=' + encodeURIComponent(getRequiredSecret('MS_CLIENT_ID')) +
    '&response_type=code' +
    '&redirect_uri=' + encodeURIComponent(getRequiredSecret('APP_URL')) +
    '&state=' + encodeURIComponent(state) +
    '&scope=' + encodeURIComponent('User.Read') +
    '&prompt=login';
  return { url: url };
}

function handleMicrosoftCallback(authCode, errorCode, state) {
  const failure = buildHtmlMessage('Autenticazione non riuscita. Riprova.', false);

  if (typeof state !== 'string' || !UUID_PATTERN.test(state)) {
    return failure;
  }

  // The state is one-time: read it, then remove it immediately.
  const cache = CacheService.getScriptCache();
  const stateKey = 'oauth_state_' + state;
  const sessionId = cache.get(stateKey);
  cache.remove(stateKey);

  if (!sessionId || errorCode || !authCode) {
    return failure;
  }

  const tokenResponse = UrlFetchApp.fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'post',
    muteHttpExceptions: true,
    payload: {
      client_id: getRequiredSecret('MS_CLIENT_ID'),
      client_secret: getRequiredSecret('MS_CLIENT_SECRET'),
      grant_type: 'authorization_code',
      code: authCode,
      redirect_uri: getRequiredSecret('APP_URL')
    }
  });
  const tokenData = JSON.parse(tokenResponse.getContentText());
  if (!tokenData.access_token) {
    return failure;
  }

  const graphResponse = UrlFetchApp.fetch('https://graph.microsoft.com/v1.0/me', {
    headers: { Authorization: 'Bearer ' + tokenData.access_token },
    muteHttpExceptions: true
  });
  if (graphResponse.getResponseCode() !== 200) {
    return failure;
  }

  const profile = JSON.parse(graphResponse.getContentText());
  const email = profile.userPrincipalName || profile.mail;
  if (!email) {
    return failure;
  }

  cache.put('msa_email_' + sessionId, email, 300);
  return buildHtmlMessage('Autenticazione completata. Puoi chiudere questa finestra.', true);
}

function handleGetMicrosoftEmail(payload) {
  const sessionId = payload.session_id;
  if (typeof sessionId !== 'string' || !UUID_PATTERN.test(sessionId)) {
    throw new AppError('Sessione di autenticazione non valida.');
  }
  const cache = CacheService.getScriptCache();
  const key = 'msa_email_' + sessionId;
  const email = cache.get(key);
  if (email) {
    cache.remove(key);   // single use
  }
  return { email: email || null };
}


// =========================================================================
// 13. HANDLERS: OCR (Google Cloud Vision)
// =========================================================================
// NOTE: handleOcrRequest was not present in the uploaded file. This is a
// minimal implementation. If you have your own version, keep it, but make
// sure it requires a session and uses the quota logic below.

function getOcrMonthKey() {
  return 'ocr_usage_' + Utilities.formatDate(new Date(), TIMEZONE, 'yyyy-MM');
}

function getOcrStatus() {
  const used = parseInt(PropertiesService.getScriptProperties().getProperty(getOcrMonthKey()) || '0', 10);
  return {
    used: used,
    limit: OCR_MONTHLY_SAFE_LIMIT,
    remaining: Math.max(0, OCR_MONTHLY_SAFE_LIMIT - used)
  };
}

/** Atomically reserves one OCR call from the monthly quota. */
function reserveOcrQuota() {
  return withScriptLock(function () {
    const props = PropertiesService.getScriptProperties();
    const usageKey = getOcrMonthKey();
    const used = parseInt(props.getProperty(usageKey) || '0', 10);
    if (used >= OCR_MONTHLY_SAFE_LIMIT) {
      throw new AppError('Limite mensile OCR raggiunto.');
    }
    props.setProperty(usageKey, String(used + 1));
    return used + 1;
  });
}

function handleOcrRequest(payload, session) {
  const imageData = String(payload.image_data || '')
    .replace(/^data:image\/[a-zA-Z0-9.+\-]+;base64,/, '');

  if (!imageData || imageData.length > OCR_MAX_IMAGE_LENGTH) {
    throw new AppError('Immagine mancante o troppo grande.');
  }
  if (!/^[A-Za-z0-9+\/=\s]+$/.test(imageData)) {
    throw new AppError('Formato immagine non valido.');
  }

  const used = reserveOcrQuota();   // reserved before the call (conservative)

  const response = UrlFetchApp.fetch('https://vision.googleapis.com/v1/images:annotate', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-Goog-Api-Key': getRequiredSecret('VISION_API_KEY') },
    muteHttpExceptions: true,
    payload: JSON.stringify({
      requests: [{
        image: { content: imageData },
        features: [{ type: 'DOCUMENT_TEXT_DETECTION' }]
      }]
    })
  });
  if (response.getResponseCode() !== 200) {
    throw new Error('Vision API returned HTTP ' + response.getResponseCode());
  }

  const result = JSON.parse(response.getContentText());
  const annotation = result.responses && result.responses[0] && result.responses[0].fullTextAnnotation;
  writeAuditLog(session.operatorId, 'ocr', '-', 'SUCCESS');
  return {
    text: annotation ? annotation.text : '',
    used: used,
    limit: OCR_MONTHLY_SAFE_LIMIT,
    remaining: Math.max(0, OCR_MONTHLY_SAFE_LIMIT - used)
  };
}


// =========================================================================
// 14. DATA RETENTION & ERASURE
// =========================================================================

/**
 * Deletes every record older than RETENTION_MONTHS. Meant to run from a daily
 * time trigger (see installRetentionTrigger). The audit log only stores the
 * number of deleted rows, never customer data.
 */
function purgeExpiredRecords() {
  const cutoff = new Date();
  cutoff.setMonth(cutoff.getMonth() - RETENTION_MONTHS);

  const deletedCount = withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const data = sheet.getDataRange().getValues();
    let deleted = 0;

    // Bottom-up so that deleting a row does not shift the rows still to check.
    for (let i = data.length - 1; i > 0; i--) {
      const recordDate = new Date(data[i][DATA_COL.TIMESTAMP]);
      if (!isNaN(recordDate.getTime()) && recordDate < cutoff) {
        sheet.deleteRow(i + 1);
        deleted++;
      }
    }
    return deleted;
  });

  writeAuditLog('system', 'retention_purge', '-', 'DELETED:' + deletedCount);
  return deletedCount;
}

/** Run once from the menu: schedules purgeExpiredRecords every day at 03:00. */
function installRetentionTrigger() {
  const ui = SpreadsheetApp.getUi();

  ScriptApp.getProjectTriggers().forEach(function (trigger) {
    if (trigger.getHandlerFunction() === 'purgeExpiredRecords') {
      ScriptApp.deleteTrigger(trigger);
    }
  });
  ScriptApp.newTrigger('purgeExpiredRecords')
    .timeBased()
    .everyDays(1)
    .atHour(3)
    .create();

  writeAuditLog('admin', 'retention_trigger', '-', 'INSTALLED');
  ui.alert('Pulizia automatica attiva',
    'Ogni notte vengono eliminati i record piu\' vecchi di ' + RETENTION_MONTHS + ' mesi.',
    ui.ButtonSet.OK);
}

/**
 * Erasure on customer request: removes every record of a PC serial,
 * whichever store registered it.
 */
function eraseCustomerDataFromMenu() {
  const ui = SpreadsheetApp.getUi();
  const answer = ui.prompt('Elimina dati cliente', 'Numero seriale del PC:', ui.ButtonSet.OK_CANCEL);
  if (answer.getSelectedButton() !== ui.Button.OK) {
    return;
  }

  let serial;
  try {
    serial = normalizeSerial(answer.getResponseText());
  } catch (error) {
    ui.alert('Seriale non valido.');
    return;
  }

  const confirmation = ui.alert('Conferma eliminazione',
    'Eliminare definitivamente tutti i dati registrati per il seriale ' + serial + '?',
    ui.ButtonSet.YES_NO);
  if (confirmation !== ui.Button.YES) {
    return;
  }

  const deleted = withScriptLock(function () {
    const sheet = getSheetOrThrow(SHEET_DATA);
    const data = sheet.getDataRange().getValues();
    let count = 0;
    for (let i = data.length - 1; i > 0; i--) {
      if (String(data[i][DATA_COL.PC_SERIAL]).trim().toUpperCase() === serial) {
        sheet.deleteRow(i + 1);
        count++;
      }
    }
    return count;
  });

  writeAuditLog('admin', 'erase_customer_data', serial, 'DELETED:' + deleted);
  ui.alert(deleted > 0 ? 'Eliminati ' + deleted + ' record.' : 'Nessun record trovato per questo seriale.');
}


// =========================================================================
// 15. SPREADSHEET ADMIN TOOLS (custom menu)
// =========================================================================

function onOpen() {
  SpreadsheetApp.getUi()
    .createMenu('AvvioPC Tools')
    .addItem('Genera Hash PIN', 'generatePinHashFromPrompt')
    .addSeparator()
    .addItem('Aggiorna formato cifratura', 'runEncryptionUpgradeFromMenu')
    .addItem('Ruota chiavi di cifratura', 'runKeyRotationFromMenu')
    .addSeparator()
    .addItem('Elimina dati cliente (per seriale)', 'eraseCustomerDataFromMenu')
    .addItem('Attiva pulizia automatica dati', 'installRetentionTrigger')
    .addToUi();
}

function generatePinHashFromPrompt() {
  const ui = SpreadsheetApp.getUi();

  const idResult = ui.prompt(
    'Genera Hash PIN',
    'Inserisci l\'ID dell\'operatore (colonna A del foglio OPERATORS):',
    ui.ButtonSet.OK_CANCEL
  );
  if (idResult.getSelectedButton() !== ui.Button.OK) {
    return;
  }
  const operatorId = normalizeOperatorId(idResult.getResponseText());
  if (!operatorId) {
    ui.alert('Errore', 'ID operatore non valido.', ui.ButtonSet.OK);
    return;
  }

  const pinResult = ui.prompt(
    'Genera Hash PIN',
    'Inserisci il PIN numerico (da 6 a 12 cifre):',
    ui.ButtonSet.OK_CANCEL
  );
  if (pinResult.getSelectedButton() !== ui.Button.OK) {
    return;
  }
  const pin = pinResult.getResponseText().trim();
  if (!/^\d{6,12}$/.test(pin)) {
    ui.alert('Errore', 'Il PIN deve contenere da 6 a 12 cifre.', ui.ButtonSet.OK);
    return;
  }

  ui.alert(
    'Hash generato',
    'Copia questo codice nella colonna del PIN per l\'operatore ' + operatorId + ':\n\n' +
    hashPin(pin, operatorId) +
    '\n\n(L\'hash è valido solo per questo operatore. Il PIN in chiaro non viene salvato.)',
    ui.ButtonSet.OK
  );
}

function runEncryptionUpgradeFromMenu() {
  const ui = SpreadsheetApp.getUi();
  const answer = ui.alert(
    'Aggiorna formato cifratura',
    'Tutti i campi cifrati verranno convertiti al nuovo formato autenticato.\n' +
    'Crea prima una copia del foglio. Continuare?',
    ui.ButtonSet.YES_NO
  );
  if (answer !== ui.Button.YES) {
    return;
  }
  const count = upgradeEncryptionFormat();
  ui.alert('Operazione completata', 'Record aggiornati: ' + count, ui.ButtonSet.OK);
}

function runKeyRotationFromMenu() {
  const ui = SpreadsheetApp.getUi();
  const answer = ui.alert(
    'Ruota chiavi di cifratura',
    'Verranno generate nuove chiavi e tutti i dati cifrati verranno ricifrati.\n' +
    'Crea prima una copia del foglio. Continuare?',
    ui.ButtonSet.YES_NO
  );
  if (answer !== ui.Button.YES) {
    return;
  }
  const count = rotateEncryptionKeys();
  ui.alert('Operazione completata', 'Record ricifrati: ' + count, ui.ButtonSet.OK);
}