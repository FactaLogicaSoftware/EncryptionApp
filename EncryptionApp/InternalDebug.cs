#if DEBUG

using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Encryption_App.UI;

namespace Encryption_App
{
    internal class InternalDebug
    {
        internal static void WriteToDiagnosticsFile(params string[] items)
        {
            MainWindow refToMainWindow = (MainWindow)System.Windows.Application.Current.MainWindow ?? throw new NoNullAllowedException("No main window found");

            string tempFilePath = refToMainWindow.TempFilePath;

            if (!Directory.Exists(tempFilePath + @"EncryptionApp\"))
            {
                Directory.CreateDirectory(tempFilePath + @"EncryptionApp\");
            }

            if (!File.Exists(tempFilePath + @"EncryptionApp\" + "DiagnosticsAndDebug.data"))
            {
                File.Create(tempFilePath + @"EncryptionApp\" + "DiagnosticsAndDebug.data");
            }

            using (var fHandle = new FileStream(refToMainWindow.TempFilePath + @"EncryptionApp\" + "DiagnosticsAndDebug.data", FileMode.Append))
            using (var fWriter = new StreamWriter(fHandle))
            {
                fWriter.WriteLine('\n' + DateTime.Now.ToString(CultureInfo.CurrentCulture));
                foreach (string item in items)
                {
                    fWriter.WriteLine(item);
                }
            }
        }
    }
}

#endif