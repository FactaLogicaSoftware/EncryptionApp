using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

// Don't edit the line below please 
// ReSharper disable InconsistentNaming

namespace CryptoTools
{
    // The data about the Hash Message Authentication Code (HMAC)
    public struct HmacInfo : ICryptoStruct
    {
        // The byte[] of the actual hash
        public byte[] root_Hash;

        // The string that is the nameof() the type used
        public string HashAlgorithm;

        // The number of iterations
        public uint Iterations;
    }

    // The data about the encryption mode used
    public struct EncryptionModeInfo : ICryptoStruct
    {
        // The string that is the nameof() the type used
        public string root_Algorithm;

        // The CipherMode used
        public CipherMode Mode;

        // The key size used
        public uint KeySize;

        // The block size used
        public uint BlockSize;
    }

    // The data about the device used to derive or create the key
    public struct KeyCreator : ICryptoStruct
    {
        // The string that is the nameof() the type used
        public string root_HashAlgorithm;

        // The number of iterations
        public uint Iterations;

        // The byte[] of the salt used
        public byte[] salt;
    }
}
