using System;
using System.Security.Cryptography;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using JetBrains.Annotations;

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
        /// 
        /// </summary>
        /// <param name="cryptoManager"></param>
        /// <param name="initializationVectorSizeBytes"></param>
        /// <param name="cipherMode"></param>
        /// <param name="paddingMode"></param>
        /// <param name="keySize"></param>
        /// <param name="blockSize"></param>
        public TransformationContract(Type cryptoManager, uint initializationVectorSizeBytes, CipherMode cipherMode, PaddingMode paddingMode, uint keySize, uint blockSize)
        {
            if (!cryptoManager.IsSubclassOf(typeof(SymmetricCryptoManager)))
                throw new ArgumentException(nameof(CryptoManager) + "must be derived from" + typeof(SymmetricCryptoManager).FullName);

            CryptoManager = cryptoManager;
            InitializationVectorSizeBytes = initializationVectorSizeBytes;
            CipherMode = cipherMode;
            PaddingMode = paddingMode;
            KeySize = keySize;
            BlockSize = blockSize;
        }

        /// <summary>
        /// The CryptoManager used for transformation
        /// </summary>
        [NotNull]
        public Type CryptoManager { get; }

        /// <summary>
        /// The size, in bytes, to use for the
        /// initialization vector
        /// </summary>
        public uint InitializationVectorSizeBytes { get; }

        /// <summary>
        /// The CipherMode used for encryption
        /// </summary>
        public CipherMode CipherMode { get; }

        /// <summary>
        /// The PaddingMode used for encryption
        /// </summary>
        public PaddingMode PaddingMode { get; }

        /// <summary>
        /// The key size, in bits, used
        /// </summary>
        public uint KeySize { get; }

        /// <summary>
        /// The block size, in bits, used
        /// </summary>
        public uint BlockSize { get; }
    }
}