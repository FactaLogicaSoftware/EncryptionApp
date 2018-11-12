using JetBrains.Annotations;
using System;

namespace FactaLogicaSoftware.CryptoTools.Information.Contracts
{
    /// <summary>
    /// Represents the contract used to transform data
    /// with a symmetric algorithm
    /// </summary>
    public class SymmetricCryptographicContract
    {
        /// <summary>
        /// The class containing the information
        /// defining how to transform the data
        /// </summary>
        [NotNull]
        public TransformationContract TransformationContract { get; }

        /// <summary>
        /// The class containing the information on
        /// how to derive the key from the password,
        /// or null to represent that the password is the key
        /// </summary>
        [CanBeNull]
        public KeyContract InstanceKeyContract { get; }

        /// <summary>
        /// The class containing the information on
        /// how to verify the data using an HMAC process,
        /// or null to represent the data cannot be verified
        /// </summary>
        [CanBeNull]
        public HmacContract HmacContract { get; }

        /// <summary>
        /// Creates a new instance of the SymmetricCryptographicContract
        /// from the relevant contracts
        /// </summary>
        /// <param name="transformationContract"></param>
        /// <param name="instanceKeyContract"></param>
        /// <param name="hmacContract"></param>
        public SymmetricCryptographicContract([NotNull] TransformationContract transformationContract, [CanBeNull] KeyContract instanceKeyContract = null, [CanBeNull] HmacContract hmacContract = null)
        {
            this.TransformationContract = transformationContract ??
                                          throw new ArgumentNullException(nameof(transformationContract));
            this.InstanceKeyContract = instanceKeyContract ??
                                       throw new ArgumentNullException(nameof(instanceKeyContract));
            this.HmacContract = hmacContract;
        }
    }
}