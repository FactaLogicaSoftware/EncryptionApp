using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    public class KeyRepresentative
    {
        public Type KeyAlgorithm;

        // The number of iterations
        public ulong PerformanceDerivative;

        // The byte array of the salt used
        public byte[] Salt;
    }
}
