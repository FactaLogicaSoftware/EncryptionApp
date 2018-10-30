using System;
using System.Security.Cryptography;

namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    /// <inheritdoc />
    /// <summary>
    /// An exception which represents an invalid transformation key being
    /// passed to a method or constructor
    /// </summary>
    [Serializable]
    public class BadKeyException : CryptographicException
    {
        /// <inheritdoc />
        /// <summary>
        /// The default constructor
        /// </summary>
        public BadKeyException() : base("Key is not valid")
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception
        /// </summary>
        /// <param name="message">The string to be the message</param>
        public BadKeyException(string message) : base(message)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception and the inner exception to base it off
        /// </summary>
        /// <param name="message">The string to be the message</param>
        /// <param name="inner">The inner exception</param>
        public BadKeyException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}