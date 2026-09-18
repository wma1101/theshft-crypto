/**
 * Shared PIN validation utility.
 * Used by create-pin, change-pin, duress-pin, setup-decoy, and restore screens.
 * Centralized to ensure consistent validation across all PIN entry points.
 */

/**
 * Check if a PIN is weak (easily guessable).
 * Detects: repeated digits, sequential ascending/descending, common patterns.
 *
 * @param {string} pin - The PIN to validate
 * @returns {{ weak: boolean, reason: string|null }}
 */
export const isWeakPin = (pin) => {
  if (!pin || typeof pin !== 'string' || pin.length < 4) {
    return { weak: true, reason: 'PIN must be at least 4 digits' };
  }

  // All same digit (0000, 1111, 222222, etc.)
  if (/^(\d)\1+$/.test(pin)) {
    return { weak: true, reason: 'PIN cannot be all the same digit' };
  }

  // Sequential ascending (1234, 23456, 012345, etc.)
  let isAscending = true;
  for (let i = 1; i < pin.length; i++) {
    if (parseInt(pin[i]) !== parseInt(pin[i - 1]) + 1) {
      isAscending = false;
      break;
    }
  }
  if (isAscending) {
    return { weak: true, reason: 'PIN cannot be sequential digits' };
  }

  // Sequential descending (4321, 98765, etc.)
  let isDescending = true;
  for (let i = 1; i < pin.length; i++) {
    if (parseInt(pin[i]) !== parseInt(pin[i - 1]) - 1) {
      isDescending = false;
      break;
    }
  }
  if (isDescending) {
    return { weak: true, reason: 'PIN cannot be sequential digits' };
  }

  // Common patterns
  const commonPins = [
    '1234', '0000', '1111', '2222', '3333', '4444', '5555',
    '6666', '7777', '8888', '9999', '1212', '1122', '2233',
    '1010', '2020', '6969', '4321', '0852', '2580',
    '12345', '123456', '654321', '111111', '000000',
  ];
  if (commonPins.includes(pin)) {
    return { weak: true, reason: 'PIN is too common' };
  }

  // Alternating digits (1212, 3434, 121212)
  if (pin.length >= 4) {
    const pattern = pin.substring(0, 2);
    let isAlternating = true;
    for (let i = 0; i < pin.length; i += 2) {
      if (pin.substring(i, i + 2) !== pattern.substring(0, Math.min(2, pin.length - i))) {
        isAlternating = false;
        break;
      }
    }
    if (isAlternating) {
      return { weak: true, reason: 'PIN cannot be a repeating pattern' };
    }
  }

  return { weak: false, reason: null };
};

/**
 * Validate that two PINs don't conflict (e.g., duress PIN != main PIN).
 *
 * @param {string} newPin - The new PIN being set
 * @param {string} existingPin - An existing PIN to check against
 * @param {string} existingLabel - Label for the existing PIN (e.g., "main PIN", "decoy PIN")
 * @returns {{ conflict: boolean, reason: string|null }}
 */
export const checkPinConflict = (newPin, existingPin, existingLabel) => {
  if (!newPin || !existingPin) return { conflict: false, reason: null };
  if (newPin === existingPin) {
    return { conflict: true, reason: `This PIN is already your ${existingLabel}` };
  }
  return { conflict: false, reason: null };
};
