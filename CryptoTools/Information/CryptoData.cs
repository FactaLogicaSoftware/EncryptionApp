using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;

// Don't edit the line below please
// ReSharper disable InconsistentNaming

namespace FactaLogicaSoftware.CryptoTools.Information
{
    /// <summary>
    /// The data about the Hash Message Authentication Code (HMAC)
    /// </summary>
    public class HmacInfo
    {
        // The byte array of the actual hash
        public byte[] root_Hash;

        // The string that is the typeof() or GetType() of the object
        public string HashAlgorithm;
    }
    
    /// <summary>
    /// The data about the encryption mode used
    /// </summary>
    public struct EncryptionModeInfo
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
    
    /// <summary>
    /// The data about the device used to derive or create the key
    /// </summary>
    public struct KeyCreator
    {
        // The string that is the typeof() or GetType() of the object
        public string root_HashAlgorithm;

        // The number of iterations
        public ulong PerformanceDerivative;

        // The byte array of the salt used
        public byte[] salt;
    }
}
