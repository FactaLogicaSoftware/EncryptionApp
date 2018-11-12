using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Algorithms
{
    /// <summary>
    /// A class used for encrypting data for a user without a password
    /// </summary>
    public static class NativeKeyEncryptor
    {
        // Just some random data, make non
        private static readonly byte[] Entropy =
        {
            0xc2, 0x2e, 0x42, 0xdc, 0x37, 0xe5, 0x95, 0x6d,
            0x9e, 0x4f, 0x34, 0xab, 0x98, 0x53, 0xcb, 0x5f,
            0x54, 0xee, 0xab, 0x4a, 0x39, 0x01, 0x6f, 0xef,
            0xeb, 0xd6, 0x28, 0x8b, 0x24, 0xed, 0xfb, 0xe8,
            0xe8, 0xde, 0x64, 0x54, 0x1f, 0x23, 0x6a, 0x9a,
            0x00, 0x9c, 0xf1, 0xf2, 0xac, 0xb5, 0xac, 0x2e,
            0x96, 0xd0, 0xb5, 0xd9, 0x4d, 0xef, 0x08, 0xbb,
            0xf6, 0x6c, 0x02, 0xc7, 0x8a, 0x5e, 0x4d, 0x81
        };

        /// <summary>
        /// Generate a secure 64 byte random byte array
        /// </summary>
        /// <returns>A 64 byte array of cryptographically secure values</returns>
        public static byte[] GenerateEntropy()
        {
            var entropy = new byte[64];
            new RNGCryptoServiceProvider().GetBytes(entropy);

            return entropy;
        }

        /// <summary>
        /// Generate a secure random byte array
        /// </summary>
        /// <param name="length">Number of bytes to generate</param>
        /// <returns>A byte array of cryptographically secure values</returns>
        public static byte[] GenerateEntropy(int length)
        {
            var entropy = new byte[length];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(entropy);

            return entropy;
        }

        /// <summary>
        /// Encrypt a key for storage by a user
        /// </summary>
        /// <param name="key">The plaintext bytes</param>
        /// <returns>The encrypted data</returns>
        public static byte[] EncryptKey(byte[] key)
        {
            return ProtectedData.Protect(key, Entropy, DataProtectionScope.CurrentUser);
        }

        /// <summary>
        /// Decrypt a key encrypted for storage by a user
        /// </summary>
        /// <param name="encryptedKey">The encrypted bytes</param>
        /// <returns>The plaintext bytes</returns>
        public static byte[] DecryptKey(byte[] encryptedKey)
        {
            return ProtectedData.Unprotect(encryptedKey, Entropy, DataProtectionScope.CurrentUser);
        }
    }
}