using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    public class TransformationRepresentative
    {
        public Type CryptoManager;

        // The byte array used as an initialization vector
        public byte[] InitializationVector;

        // The CipherMode used
        public CipherMode Mode;

        // The key size used
        public uint KeySize;

        // The block size used
        public uint BlockSize;

    }
}
