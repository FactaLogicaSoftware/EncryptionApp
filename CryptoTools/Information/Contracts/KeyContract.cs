using System;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// The contract for deriving a key
    /// in a specific way
    /// </summary>
    public class KeyContract
    {
        /// <summary>
        /// The constructor for this immutable
        /// object
        /// </summary>
        /// <param name="keyAlgorithm">The algorithm used for deriving the key</param>
        /// <param name="performanceDerivative">The performance derivative used</param>
        /// <param name="saltLengthBytes">The length of the salt, in bytes</param>
        public KeyContract([NotNull] Type keyAlgorithm, ulong performanceDerivative, uint saltLengthBytes)
        {
            if (!keyAlgorithm.IsSubclassOf(typeof(KeyDerive)))
                throw new ArgumentException(nameof(KeyDerive) + "must derive from" + typeof(KeyDerive).FullName);

            this.KeyAlgorithm = keyAlgorithm;
            this.PerformanceDerivative = performanceDerivative;
            this.SaltLengthBytes = saltLengthBytes;
        }

        /// <summary>
        /// The type used to derive the key
        /// </summary>
        [NotNull]
        public Type KeyAlgorithm { get;  }

        /// <summary>
        /// The performance derivative used to generate it
        /// (See FactaLogicaSoftware.CryptoTools.PerformanceInterop)
        /// </summary>
        /// <see cref="FactaLogicaSoftware.CryptoTools.PerformanceInterop"/>
        public ulong PerformanceDerivative { get; }

        /// <summary>
        /// The number of bytes of salt used
        /// </summary>
        public uint SaltLengthBytes { get; }
    }
}