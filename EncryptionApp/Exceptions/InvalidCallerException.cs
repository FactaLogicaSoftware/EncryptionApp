using System;

namespace Encryption_App.Exceptions
{
    internal class InvalidCallerException : Exception
    {
        public InvalidCallerException()
        {
        }

        public InvalidCallerException(string message) : base(message)
        {
        }

        public InvalidCallerException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}