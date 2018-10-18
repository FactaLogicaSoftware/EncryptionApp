using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace CryptoTools
{
    public struct Hmac : ICryptoStruct
    {
        public byte[] _hash_root;
        public string _hashAlgorithm;
        public uint _iterations;
    }

    public struct EncryptionModeInfo : ICryptoStruct
    {
        public string _algorithm_root;
        public CipherMode _mode;
        public uint _keySize;
        public uint _blockSize;
    }

    public struct PasswordCreator : ICryptoStruct
    {
        public uint iterations;
        public string hashAlgorithm;
    }
}
