namespace FactaLogicaSoftware.CryptoTools.Exceptions
{
    using System;

    /// <inheritdoc />
    /// <summary>
    ///
    /// </summary>
    [Serializable]
    public class DataTooLargeException : InvalidCryptographicOperationException
    {
        /// <inheritdoc />
        /// <summary>
        /// The default constructor
        /// </summary>
        public DataTooLargeException()
            : base("Data is too large")
        {
        }

        /// <inheritdoc />
        /// <summary>
        /// The constructor which defines a message to be carried by the
        /// exception
        /// </summary>
        /// <param name="message">The string to be the message</param>
        public DataTooLargeException(string message)
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
        public DataTooLargeException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }
}