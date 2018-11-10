using System;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <summary>
    /// The information representing a piece
    /// of encrypted data
    /// </summary>
    public class TransformationRepresentative
    {
        /// <summary>
        /// The CryptoManager used for transformation
        /// </summary>
        public Type CryptoManager;

        /// <summary>
        /// The initialization vector
        /// </summary>
        public byte[] InitializationVector;

        /// <summary>
        /// The CipherMode used
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
