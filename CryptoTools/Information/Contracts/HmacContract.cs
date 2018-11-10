using System;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// The contract for creation of an HMAC
    /// message authenticator
    /// </summary>
    public class HmacContract
    {
        /// <summary>
        /// The type used to generate the HMAC
        /// </summary>
        public Type HashAlgorithm;
    }
}