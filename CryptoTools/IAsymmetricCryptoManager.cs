using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTools
{
    public interface IAsymmetricCryptoManager
    {
        IEnumerable<byte> EncryptBytes(IEnumerable<byte> data, IEnumerable<byte> key);
        IEnumerable<byte> DecryptBytes(IEnumerable<byte> data, IEnumerable<byte> key);
    }
}
