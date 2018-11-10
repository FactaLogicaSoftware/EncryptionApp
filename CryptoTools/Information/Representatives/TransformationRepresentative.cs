using System;
using System.Security.Cryptography;
using JetBrains.Annotations;

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
        [NotNull]
        public Type CryptoManager { get; }

        /// <summary>
        /// The initialization vector
        /// </summary>
        [NotNull]
        public byte[] InitializationVector { get; }

        /// <summary>
        /// The CipherMode used
        /// </summary>
        public CipherMode CipherMode { get; }

        /// <summary>
        /// The key size, in bits, used
        /// </summary>
        public uint KeySize { get; }

        /// <summary>
        /// The block size, in bits, used
        /// </summary>
        public uint BlockSize { get; }

        /// <summary>
        /// 
        /// </summary>
        public PaddingMode PaddingMode { get; }

        /// <summary>
        /// The constructor for this
        /// immutable class
        /// </summary>
        /// <param name="cryptoManager">The CryptoManager used for transformation</param>
        /// <param name="initializationVector">The initialization vector</param>
        /// <param name="cipherMode">The CipherMode used</param>
        /// <param name="keySize">The key size, in bits, used</param>
        /// <param name="blockSize">The block size, in bits, used</param>
        /// <param name="paddingMode"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public TransformationRepresentative([NotNull] Type cryptoManager, [CanBeNull] byte[] initializationVector, CipherMode cipherMode, PaddingMode paddingMode, uint keySize, uint blockSize)
        {
            CryptoManager = cryptoManager ?? throw new ArgumentNullException(nameof(cryptoManager));
            InitializationVector = initializationVector ?? new byte[blockSize / 8];
            this.CipherMode = cipherMode;
            KeySize = keySize;
            BlockSize = blockSize;
            this.PaddingMode = paddingMode;
        }
    }
}