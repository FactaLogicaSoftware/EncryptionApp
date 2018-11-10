using System;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <summary>
    /// The representation of a specific HMAC
    /// verification
    /// </summary>
    public class HmacRepresentative
    {
        /// <summary>
        /// The byte array of the hash
        /// </summary>
        public byte[] HashBytes;

        /// <summary>
        /// The type used to verify the bytes
        /// </summary>
        public Type HashAlgorithm;
    }
}