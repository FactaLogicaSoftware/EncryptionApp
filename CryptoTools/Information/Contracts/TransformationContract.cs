using System;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    public class TransformationContract
    {
        public Type CryptoManager;

        // The byte array used as an initialization vector
        public uint InitializationVectorSizeBytes;

        // The CipherMode used
        public CipherMode Mode;

        // The key size used
        public uint KeySize;

        // The block size used
        public uint BlockSize;

    }
}