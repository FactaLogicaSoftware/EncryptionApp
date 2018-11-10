using System;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// The contract for transforming data
    /// including an optional HMAC and key derivation
    /// contract
    /// </summary>
    public class TransformationContract
    {
        /// <summary>
        /// The CryptoManager used for transformation
        /// </summary>
        public Type CryptoManager;

        /// <summary>
        /// The size, in bytes, to use for the
        /// initialization vector
        /// </summary>
        public uint InitializationVectorSizeBytes;

        /// <summary>
        /// The CipherMode used for encryption
        /// </summary>
        public CipherMode Mode;

        /// <summary>
        /// The key size, in bits, used
        /// </summary>
        public uint KeySize;

        /// <summary>
        /// The block size, in bits, used
        /// </summary>
        public uint BlockSize;

    }
}