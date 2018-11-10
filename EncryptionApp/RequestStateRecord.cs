using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Information.Contracts;

namespace Encryption_App
{
    internal class RequestStateRecord
    {
        public MainWindow.ProcessType ProcessType;
        public readonly string FilePath;
        public readonly SymmetricCryptographicContract Contract;

        public RequestStateRecord(MainWindow.ProcessType processType, string filePath)
        {
            this.ProcessType = processType;
            this.FilePath = filePath;
        }

        public RequestStateRecord(MainWindow.ProcessType processType, string filePath, SymmetricCryptographicContract contract)
        {
            this.ProcessType = processType;
            this.FilePath = filePath;
            this.Contract = contract;
        }
    }
}