using System;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <summary>
    /// The representation of a specific HMAC
    /// verification
    /// </summary>
    public class HmacRepresentative
    {
        /// <summary>
        /// The default constructor for this immutable object
        /// </summary>
        /// <param name="hashBytes"></param>
        /// <param name="hashAlgorithm"></param>
        public HmacRepresentative([NotNull] Type hashAlgorithm, [NotNull] byte[] hashBytes)
        {
            if (!hashAlgorithm.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
                throw new ArgumentException(nameof(HashAlgorithm) + "must be derived from" + typeof(System.Security.Cryptography.HMAC).FullName);

            HashBytes = hashBytes ?? throw new ArgumentNullException(nameof(hashBytes));
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// The byte array of the hash
        /// </summary>
        [NotNull]
        public byte[] HashBytes { get; }

        /// <summary>
        /// The type used to verify the bytes
        /// </summary>
        [NotNull]
        public Type HashAlgorithm { get; }
    }
}