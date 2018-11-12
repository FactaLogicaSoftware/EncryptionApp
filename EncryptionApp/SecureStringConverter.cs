using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Security;
using System.Windows;

namespace Encryption_App
{
    internal static class SecureStringConverter
    {
        public static GCHandle SecureStringToKeyDerive(SecureString password, IEnumerable salt, PerformanceDerivative performanceDerivative, Type keyDeriveAlgorithm, out KeyDerive keyDerive)
        {
            // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
            IntPtr ptrSecureString = IntPtr.Zero;

            try
            {
                ptrSecureString = Marshal.SecureStringToGlobalAllocUnicode(password);

                var dataInsecureBytes = new byte[password.Length * sizeof(char)];

                GCHandle bytesHandle = GCHandle.Alloc(dataInsecureBytes, GCHandleType.Pinned);

                for (var i = 0; i < password.Length * sizeof(char); i++)
                    dataInsecureBytes[i] = Marshal.ReadByte(ptrSecureString, i);

                // Create an object array of parameters
                var parametersForInstance = new object[] { dataInsecureBytes, salt, null };

                // Parameters for static function call
                var parametersForStatic = new object[] { performanceDerivative, performanceDerivative.Milliseconds };

                object val = keyDeriveAlgorithm.GetMethod("TransformPerformance")?.Invoke(null, parametersForStatic);

                parametersForInstance[2] = val;

                keyDerive = (KeyDerive)Activator.CreateInstance(keyDeriveAlgorithm, parametersForInstance);

                password.Dispose();

                return bytesHandle;
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
                Marshal.ZeroFreeGlobalAllocUnicode(ptrSecureString);
            }
        }

        public static (IntPtr, int) SecureStringToKeyDeriveReturnPointer(SecureString password, IEnumerable salt, PerformanceDerivative performanceDerivative, Type keyDeriveAlgorithm, out KeyDerive keyDerive)
        {
            // Turn the secure string into a string to pass it into keyDevice for the shortest interval possible
            IntPtr ptrSecureString = IntPtr.Zero;

            try
            {
                ptrSecureString = Marshal.SecureStringToGlobalAllocUnicode(password);

                var dataInsecureBytes = new byte[password.Length * sizeof(char)];

                GCHandle bytesHandle = GCHandle.Alloc(dataInsecureBytes, GCHandleType.Pinned);

                for (var i = 0; i < password.Length * sizeof(char); i++)
                    dataInsecureBytes[i] = Marshal.ReadByte(ptrSecureString, i);

                // Create an object array of parameters
                var parametersForInstance = new object[] { dataInsecureBytes, salt, null };

                // Parameters for static function call
                var parametersForStatic = new object[] { performanceDerivative, performanceDerivative.Milliseconds };

                object val = keyDeriveAlgorithm.GetMethod("TransformPerformance")?.Invoke(null, parametersForStatic);

                parametersForInstance[2] = val;

                keyDerive = (KeyDerive)Activator.CreateInstance(keyDeriveAlgorithm, parametersForInstance);

                password.Dispose();

                return (bytesHandle.AddrOfPinnedObject(), dataInsecureBytes.Length);
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
                Marshal.ZeroFreeGlobalAllocUnicode(ptrSecureString);
            }
        }
    }
}