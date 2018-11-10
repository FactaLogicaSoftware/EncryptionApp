using System;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// The contract for creation of an HMAC
    /// message authenticator
    /// </summary>
    public class HmacContract
    {
        /// <summary>
        /// The constructor for this immutable
        /// class
        /// </summary>
        /// <param name="hashAlgorithm">The type of the HMAC algorithm to use</param>
        public HmacContract([NotNull] Type hashAlgorithm)
        {
            if (!hashAlgorithm.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
                throw new ArgumentException(nameof(HashAlgorithm) + "must be derived from" + typeof(System.Security.Cryptography.HMAC).FullName);

            this.HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// The type used to generate the HMAC
        /// </summary>
        [NotNull]
        public Type HashAlgorithm { get; }
    }
}