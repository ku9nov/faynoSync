export type KeyAlgorithm = 'ed25519' | 'rsa' | 'ecdsa';

export const normalizeKeyAlgorithm = (value?: string): KeyAlgorithm => {
  const normalized = value?.trim().toLowerCase();
  if (normalized === 'ed25519' || normalized === 'rsa' || normalized === 'ecdsa') {
    return normalized;
  }

  throw new Error(`Unsupported key type "${value ?? ''}". Allowed values: ed25519, rsa, ecdsa.`);
};
