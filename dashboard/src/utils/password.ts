const CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
// Largest multiple of the charset size that fits in a byte: bytes above it are
// dropped so every character is equally likely.
const MAX_UNBIASED_BYTE = 256 - (256 % CHARSET.length);

export const generateRandomPassword = (length = 32): string => {
  let password = '';
  const bytes = new Uint8Array(length * 2);
  while (password.length < length) {
    crypto.getRandomValues(bytes);
    for (const byte of bytes) {
      if (byte < MAX_UNBIASED_BYTE && password.length < length) {
        password += CHARSET[byte % CHARSET.length];
      }
    }
  }
  return password;
};
