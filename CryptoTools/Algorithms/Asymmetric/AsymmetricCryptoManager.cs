namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    /// <summary>
    /// An interface that defines the contract of any asymmetric encryption algorithm
    /// that uses a public-private key system
    /// </summary>
    public abstract class AsymmetricCryptoManager
    {
        /// <summary>
        /// Whether the current aes object is FIPS 140-2 compliant
        /// </summary>
        public bool IsFipsCompliant { get; private protected set; }

        /// <summary>
        /// If overriden in a derived class, encrypts bytes using the public key
        /// </summary>
        /// <param name="data">The bytes to encrypt</param>
        /// <param name="key">The public key to encrypt with</param>
        /// <returns></returns>
        public abstract byte[] EncryptBytesWithPubKey(byte[] data, byte[] key);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes using the public key
        /// </summary>
        /// <param name="data">The bytes to decrypt</param>
        /// <param name="key">The public key to decrypt
        /// the private-key encrypted data</param>
        /// <returns></returns>
        public abstract byte[] DecryptBytesWithPubKey(byte[] data, byte[] key);

        /// <summary>
        /// If overriden in a derived class, encrypts bytes using the public key
        /// </summary>
        /// <param name="data">The bytes to encrypt</param>
        /// <param name="key">The private key to encrypt with</param>
        /// <returns></returns>
        public abstract byte[] EncryptBytesWithPrivKey(byte[] data, byte[] key);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes using the private key
        /// </summary>
        /// <param name="data">The bytes to decrypt</param>
        /// <param name="key">The private key to decrypt
        /// the public-key encrypted data</param>
        /// <returns></returns>
        public abstract byte[] DecryptBytesWithPrivKey(byte[] data, byte[] key);
    }
}