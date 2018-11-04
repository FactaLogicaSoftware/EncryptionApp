using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    public class KeyContract
    {
        // The string that is the typeof() or GetType() of the object
        public Type KeyAlgorithm;

        // The number of iterations
        public ulong PerformanceDerivative;

        // The byte array of the salt used
        public uint SaltLengthBytes;
    }
}
