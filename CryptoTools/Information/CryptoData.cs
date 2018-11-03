using System.Security.Cryptography;

// Don't edit the line below please
// ReSharper disable InconsistentNaming

namespace FactaLogicaSoftware.CryptoTools.Information
{
    /// <inheritdoc cref="ICryptoData" />
    /// <summary>
    /// The data about the Hash Message Authentication Code (HMAC)
    /// </summary>
    public class HmacInfo : ICryptoData
    {
        // The byte array of the actual hash
        public byte[] root_Hash;

        // The string that is the typeof() or GetType() of the object
        public string HashAlgorithm;
    }

    /// <inheritdoc cref="ICryptoData"/>
    /// <summary>
    /// The data about the encryption mode used
    /// </summary>
    public struct EncryptionModeInfo : ICryptoData
    {
        // The byte array used as an initialization vector
        public byte[] InitializationVector;

        // The CipherMode used
        public CipherMode Mode;

        // The key size used
        public uint KeySize;

        // The block size used
        public uint BlockSize;
    }

    /// <inheritdoc cref="ICryptoData"/>
    /// <summary>
    /// The data about the device used to derive or create the key
    /// </summary>
    public struct KeyCreator : ICryptoData
    {
        // The string that is the typeof() or GetType() of the object
        public string root_HashAlgorithm;

        // The number of iterations
        public ulong PerformanceDerivative;

        // The byte array of the salt used
        public byte[] salt;
    }
}