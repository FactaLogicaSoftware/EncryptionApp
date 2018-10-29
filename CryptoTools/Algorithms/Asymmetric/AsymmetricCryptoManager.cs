namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    /// <summary>
    /// An interface that defines the contract of any asymmetric encryption algorithm
    /// that uses a public-private key system
    /// </summary>
    public abstract class AsymmetricCryptoManager
    {
        /// <summary>
        /// Whether the current curves are compliant with pre-defined NIST curves.
        /// </summary>
        public bool IsNISTCompliant { get; private protected set; }

        /// <summary>
        /// If overriden in a derived class, encrypts bytes using the public key
        /// </summary>
        /// <param name="data">The bytes to encrypt</param>
        /// <param name="key">The public key to encrypt with</param>
        /// <returns>Encrypted byte Array</returns>
        public abstract byte[] EncryptBytes(byte[] data, byte[] PublicKey);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes using the public key
        /// </summary>
        /// <param name="data">The bytes to decrypt</param>
        /// <param name="key">The public key to decrypt
        /// the private-key encrypted data</param>
        /// <returns>Decrypted byte array</returns>
        public abstract byte[] DecryptBytes(byte[] data, byte[] PrivateKey);
    }
}