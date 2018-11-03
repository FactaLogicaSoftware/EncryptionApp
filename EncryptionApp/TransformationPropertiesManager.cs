using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;

namespace Encryption_App
{
    internal class TransformationPropertiesManager
    {
        internal KeyDerive SecureStringToKeyDerive(SecureString password, IEnumerable salt, PerformanceDerivative performanceDerivative, Type keyDeriveAlgorithm)
        {
            // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
            IntPtr valuePtr = IntPtr.Zero;

            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(password);

                // Create an object array of parameters
                var parametersForInstance = new object[] { Marshal.PtrToStringUni(valuePtr), salt, null };

                // Parameters for static function call
                var parametersForStatic = new object[] { performanceDerivative, 2000UL };

                // TODO i forgot but something
                object val = keyDeriveAlgorithm.GetMethod("TransformPerformance")?.Invoke(null, parametersForStatic);

                parametersForInstance[2] = val;

                return (KeyDerive)Activator.CreateInstance(keyDeriveAlgorithm, parametersForInstance);
            }
            catch (NotSupportedException e)
            {
                password.Dispose();
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Fatal error while managing password. Check log file for details");
                throw;
            }
            catch (OutOfMemoryException e)
            {
                password.Dispose();
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Fatal error while managing password. Check log file for details");
                throw;
            }
            finally
            {
                // Destroy the managed string
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }
    }
}
