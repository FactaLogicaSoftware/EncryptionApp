using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <summary>
    /// The representation of how the key
    /// was derived for a specific transformation
    /// </summary>
    public class KeyRepresentative
    {
        /// <summary>
        /// The type used to derive the key
        /// </summary>
        public Type KeyAlgorithm;

        /// <summary>
        /// The performance derivative used to generate it
        /// (See FactaLogicaSoftware.CryptoTools.PerformanceInterop)
        /// </summary>
        /// <see cref="FactaLogicaSoftware.CryptoTools.PerformanceInterop"/>
        public ulong PerformanceDerivative;

        /// <summary>
        /// The bytes of the salt used
        /// </summary>
        public byte[] Salt;
    }
}
