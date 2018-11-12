namespace FactaLogicaSoftware.CryptoTools.Events
{
    using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
    using System;

    /// <inheritdoc />
    /// <summary>
    /// Event args representing a change in the memory chunk
    /// value for
    /// </summary>
    public class MemoryChunkValueChangedEventArgs : EventArgs
    {
        /// <summary>
        /// The new value used for chunking
        /// </summary>
        public int NewValue;

        /// <summary>
        /// The object which raised the event
        /// </summary>
        public SymmetricCryptoManager Sender;

        /// <inheritdoc />
        /// <summary>
        /// Creates a new instance with of
        /// MemoryChunkValueChangedEventArgs
        /// </summary>
        /// <param name="newValue">The new chunk value</param>
        /// <param name="sender">The sending object</param>
        public MemoryChunkValueChangedEventArgs(int newValue, SymmetricCryptoManager sender)
        {
            this.NewValue = newValue;
            this.Sender = sender;
        }
    }
}