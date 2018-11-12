namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    /// <summary>
    /// A base class that represents the contract of any key derivation function
    /// </summary>
    public abstract class KeyDerive
    {
        /// <summary>
        /// The salt used with the KDF
        /// </summary>
        public byte[] Salt { get; private protected set; }

        private protected byte[] BackEncryptedArray;

        /// <summary>
        /// If overriden in a derived class, the universal performance derivative that can be
        /// transformed with the PerformanceDerivative class
        /// </summary>
        public abstract dynamic PerformanceValues { get; private protected set; }

        /// <summary>
        /// The bytes of the password that is stored encrypted
        /// </summary>
        public abstract byte[] Password { get; private protected set; }

        /// <summary>
        /// If overriden in a derived class, fills the array with
        /// secure random values
        /// </summary>
        /// <param name="toFill">The byte array to fill</param>
        public abstract byte[] GetBytes(int toFill);

        /// <summary>
        /// If overriden in a derived class, resets the base object
        /// </summary>
        public abstract void Reset();
    }
}