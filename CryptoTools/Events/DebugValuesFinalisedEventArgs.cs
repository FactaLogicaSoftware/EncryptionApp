#if DEBUG

namespace FactaLogicaSoftware.CryptoTools.Events
{
    using System;

    /// <inheritdoc />
    /// <summary>
    /// The event args representing the finalisation of
    /// debug values, to allow them to be stored by the
    /// subscriber
    /// </summary>
    public class DebugValuesFinalisedEventArgs : EventArgs
    {
        /// <summary>
        /// The string array of the debug values
        /// </summary>
        public readonly string[] FinalisedStrings;

        /// <summary>
        /// The object that raised the event
        /// </summary>
        public readonly object Sender;

        /// <inheritdoc />
        /// <summary>
        /// Creates a new instance of DebugValuesFinalisedEventArgs
        /// with the specified values and sender
        /// </summary>
        /// <param name="values">The debug data in string form</param>
        /// <param name="sender">The raiser of the event (usually this)</param>
        public DebugValuesFinalisedEventArgs(string[] values, object sender)
        {
            this.FinalisedStrings = values;
            this.Sender = sender;
        }
    }
}

#endif