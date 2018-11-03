namespace FactaLogicaSoftware.CryptoTools.HMAC
{
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;

    /// <summary>
    /// Used for signing and verifying HMACs
    /// </summary>
    public static class MessageAuthenticator
    {
        /// <summary>
        /// Creates a byte[] hashcode that represents the file and key hashed with SHA384. Do not try and verify this yourself, use the VerifyHMAC() func
        /// </summary>
        /// <param name="data">A byte[] of the encrypted message data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <returns>A byte[] hash that is the file and key hashed</returns>
        public static byte[] CreateHmac(byte[] data, byte[] key)
        {
            byte[] hashKey;

            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hashKey;
        }

        /// <summary>
        /// Signs a encrypted file and key with a hash algorithm of your choosing. Do not try and verify this yourself, use the VerifyHMAC() func
        /// </summary>
        /// <param name="data">A byte[] of the encrypted message data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hmac">The HMAC algorithm to use</param>
        /// <returns>A byte[] hash that is the file and key hashed</returns>
        public static byte[] CreateHmac(byte[] data, byte[] key, HMAC hmac)
        {
            byte[] hashKey;
            hmac.Key = key;

            using (hmac)
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hashKey;
        }

        /// <summary>
        /// Creates a byte[] hashcode that represents the file and key hashed with SHA384. Do not try and verify this yourself, use the VerifyHMAC() func
        /// </summary>
        /// <param name="path">A path to the file with the encrypted data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <returns>A byte[] hash that is the file and key hashed</returns>
        public static byte[] CreateHmac(string path, byte[] key)
        {
            byte[] hashKey;

            using (var fHandle = new FileStream(path, FileMode.Open))
            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(fHandle);
            }

            return hashKey;
        }

        /// <summary>
        /// Signs a encrypted file and key with a hash algorithm of your choosing. Do not try and verify this yourself, use the VerifyHMAC() func
        /// </summary>
        /// <param name="path">A path to the file with the encrypted data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hmac">The HMAC algorithm to use</param>
        /// <returns>A byte[] hash that is the file and key hashed</returns>
        public static byte[] CreateHmac(string path, byte[] key, HMAC hmac)
        {
            byte[] hashKey;
            hmac.Key = key;

            using (var fHandle = new FileStream(path, FileMode.Open))
            using (hmac)
            {
                hashKey = hmac.ComputeHash(fHandle);
            }

            return hashKey;
        }

        /// <summary>
        /// A function that verifies a HMAC file with SHA384
        /// </summary>
        /// <param name="data">A byte[] of encrypted message data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hash">The hash in the header file/the hash provided, that's been hashed with SHA384</param>
        /// <returns>True if they match, otherwise false</returns>
        public static bool VerifyHmac(byte[] data, byte[] key, byte[] hash)
        {
            byte[] hashKey;

            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hash.SequenceEqual(hashKey);
        }

        /// <summary>
        /// A function that verifies a HMAC file with a hash algorithm of your choice
        /// </summary>
        /// <param name="data">A byte[] of encrypted message data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hash">The hash in the header file/the hash provided, that's been hashed with typeOfHash</param>
        /// <param name="hmac">The HMAC algorithm to use</param>
        /// <returns>True if they match, otherwise false</returns>
        public static bool VerifyHmac(byte[] data, byte[] key, byte[] hash, HMAC hmac)
        {
            byte[] hashKey;
            hmac.Key = key;

            using (hmac)
            {
                hashKey = hmac.ComputeHash(data);
            }

            return hash.SequenceEqual(hashKey);
        }

        /// <summary>
        /// A function that verifies a HMAC file with SHA384
        /// </summary>
        /// <param name="path">A path to the file with the encrypted data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hash">The hash in the header file/the hash provided, that's been hashed with SHA384</param>
        /// <returns>True if they match, otherwise false</returns>
        public static bool VerifyHmac(string path, byte[] key, byte[] hash)
        {
            byte[] hashKey;

            using (var fHandle = new FileStream(path, FileMode.Open))
            using (var hmac = new HMACSHA384(key))
            {
                hashKey = hmac.ComputeHash(fHandle);
            }

            return hash.SequenceEqual(hashKey);
        }

        /// <summary>
        /// A function that verifies a HMAC file with a hash algorithm of your choice
        /// </summary>
        /// <param name="path">A path to the file with the encrypted data</param>
        /// <param name="key">A byte[] of the key</param>
        /// <param name="hash">The hash in the header file/the hash provided, that's been hashed with typeOfHash</param>
        /// <param name="hmac">The HMAC algorithm to use</param>
        /// <returns>True if they match, otherwise false</returns>
        public static bool VerifyHmac(string path, byte[] key, byte[] hash, HMAC hmac)
        {
            byte[] hashKey;
            hmac.Key = key;

            using (var fHandle = new FileStream(path, FileMode.Open))
            using (hmac)
            {
                hashKey = hmac.ComputeHash(fHandle);
            }

            return hash.SequenceEqual(hashKey);
        }
    }
}