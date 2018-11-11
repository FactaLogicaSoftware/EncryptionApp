using System;

namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    /// <inheritdoc />
    /// <summary>
    /// Indicates a key used in a cryptographic context
    /// is weak
    /// </summary>
    [Serializable]
    public class WeakKeyException : Exception
    {
        /// <inheritdoc />
        /// <summary>
        /// The default constructor
        /// </summary>
        public WeakKeyException() : base("Key is weak")
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception
        /// </summary>
        /// <param name="message">The string to be the message</param>
        public WeakKeyException(string message) : base(message)
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception and the inner exception to base it off
        /// </summary>
        /// <param name="message">The string to be the message</param>
        /// <param name="inner">The inner exception</param>
        public WeakKeyException(string message, Exception inner) : base(message, inner)
        {
        }
    }
}