using System;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// The contract for deriving a key
    /// in a specific way
    /// </summary>
    public class KeyContract
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
        /// The number of bytes of salt used
        /// </summary>
        public uint SaltLengthBytes;
    }
}