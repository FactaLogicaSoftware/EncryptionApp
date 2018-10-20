using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTools
{
    public interface ISymmetricCryptoManager
    {
        void EncryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);

        void DecryptFileBytes(string inputFile, string outputFile, byte[] key, byte[] iv);
    }
}
