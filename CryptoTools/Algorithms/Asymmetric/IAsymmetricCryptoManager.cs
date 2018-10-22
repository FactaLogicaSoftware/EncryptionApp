using System.Collections.Generic;

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Asymmetric
{
    public interface IAsymmetricCryptoManager
    {
        IEnumerable<byte> EncryptBytes(IEnumerable<byte> data, IEnumerable<byte> key);
        IEnumerable<byte> DecryptBytes(IEnumerable<byte> data, IEnumerable<byte> key);
    }
}
