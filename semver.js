// Semver-Vergleich für Version-Checking

/**
 * Vergleicht aktuelle Version mit minimaler Version
 * @param {string} current - Aktuelle Version (z.B. "1.0.0")
 * @param {string} minimum - Minimale Version (z.B. "1.0.0")
 * @returns {boolean} - true wenn current >= minimum
 */
export function semverSatisfies(current, minimum) {
  if (!minimum) return true;
  
  const parse = (v) => v.split('.').map(Number);
  const [cMajor, cMinor, cPatch] = parse(current);
  const [mMajor, mMinor, mPatch] = parse(minimum);
  
  if (cMajor !== mMajor) return cMajor > mMajor;
  if (cMinor !== mMinor) return cMinor > mMinor;
  return cPatch >= mPatch;
}

export default semverSatisfies;