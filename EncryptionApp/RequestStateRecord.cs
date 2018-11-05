using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Information;
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
