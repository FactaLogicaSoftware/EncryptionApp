namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    using System;
    using System.Security.Cryptography;

    /// <inheritdoc />
    /// <summary>
    /// An exception which represents an invalid call or operation on
    /// certain cryptographic objects
    /// </summary>
    [Serializable]
    public class InvalidCryptographicOperationException : CryptographicException
    {
        /// <inheritdoc />
        /// <summary>
        /// The default constructor
        /// </summary>
        public InvalidCryptographicOperationException()
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception
        /// </summary>
        /// <param name="message">The string to be the message</param>
        public InvalidCryptographicOperationException(string message)
            : base(message)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception and the inner exception to base it off
        /// </summary>
        /// <param name="message">The string to be the message</param>
        /// <param name="inner">The inner exception</param>
        public InvalidCryptographicOperationException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}