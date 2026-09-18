// QR payload format for safety-number verification, and the comparison that
// decides whether two people are talking to each other or to an attacker.
//
// Extracted as a standalone, dependency-free module (mirrors pinEntryPolicy.js
// and phraseBackup.js) so the comparison is unit-tested against the SHIPPED
// logic rather than a copy of it.
//
// ── WHY QR AT ALL ───────────────────────────────────────────────────────────
// The safety number already existed and was already reachable, but verifying
// meant reading sixty digits aloud and comparing them by eye. Almost nobody
// does that, which means in practice the verification step that backs the
// entire E2EE claim went unused. Scanning is the same check with the friction
// removed — and it removes human error in the direction that matters, since a
// bored person comparing 60 digits will glance at the first group and say
// "yeah, matches".
//
// ── WHY THE PAYLOAD IS NAMESPACED AND VERSIONED ─────────────────────────────
// The prefix is not decoration. Without it, any QR code containing the right
// digits would verify, and — worse — the app's OTHER QR codes (contact share,
// invite links) could be waved at this scanner and produce an ambiguous
// result. An unrecognised payload must be reported as unrecognised, never as
// a match and never as a scary mismatch: it is a user error, not an attack.
// The version lets the format change later without an old build silently
// misreading a new payload.
//
// ── PRIVACY ─────────────────────────────────────────────────────────────────
// The payload carries the safety number only, which is a hash of both parties'
// PUBLIC keys and user ids. It contains no private key material, no username,
// and no message content. Comparison happens entirely on-device; nothing is
// sent anywhere, and this module makes no network calls.

const SAFETY_QR_PREFIX = 'shft-sn-v1:';
const SAFETY_NUMBER_DIGITS = 60; // computeSafetyNumber: 12 groups of 5

/** Strip formatting and accept only a full-length safety number. */
function normalizeSafetyDigits(safetyNumber) {
  if (typeof safetyNumber !== 'string') return '';
  const digits = safetyNumber.replace(/\D/g, '');
  return digits.length === SAFETY_NUMBER_DIGITS ? digits : '';
}

/**
 * Build the QR payload for our locally computed safety number.
 * @return {string|null} null when the number is absent or malformed, so the
 *   caller renders nothing rather than a QR that cannot possibly verify.
 */
function toSafetyQrPayload(safetyNumber) {
  const digits = normalizeSafetyDigits(safetyNumber);
  return digits ? SAFETY_QR_PREFIX + digits : null;
}

/**
 * Compare a scanned payload against our own safety number.
 *
 * Three outcomes, deliberately distinct:
 *   'match'        — same number on both devices. Safe to mark verified.
 *   'mismatch'     — a well-formed safety code that DIFFERS. This is the
 *                    signal of an interception; it must never be soft-pedalled
 *                    into "try again".
 *   'unrecognized' — not one of our safety codes at all (wrong QR scanned, or
 *                    a future/older format). Not an attack indicator.
 *
 * Plain equality is used rather than a constant-time compare: both values are
 * derived from public keys and are displayed on screen, so there is no secret
 * for a timing side channel to leak.
 */
function compareScannedSafetyPayload(scanned, mySafetyNumber) {
  if (typeof scanned !== 'string') return 'unrecognized';
  const trimmed = scanned.trim();
  if (!trimmed.startsWith(SAFETY_QR_PREFIX)) return 'unrecognized';

  const theirDigits = trimmed.slice(SAFETY_QR_PREFIX.length).replace(/\D/g, '');
  if (theirDigits.length !== SAFETY_NUMBER_DIGITS) return 'unrecognized';

  const mine = normalizeSafetyDigits(mySafetyNumber);
  // No local number to compare against: refuse rather than guess. Returning
  // 'match' here would let a screen that failed to compute its own number
  // verify anything at all.
  if (!mine) return 'unrecognized';

  return theirDigits === mine ? 'match' : 'mismatch';
}

module.exports = {
  SAFETY_QR_PREFIX,
  SAFETY_NUMBER_DIGITS,
  normalizeSafetyDigits,
  toSafetyQrPayload,
  compareScannedSafetyPayload,
};
