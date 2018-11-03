using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;

namespace Encryption_App.ManagedSlaves
{
    internal class TransformingFileManager : ManagedSlave
    {
        private readonly string _filePath;
        private readonly Progress<int> _encryptionProgress;
        private readonly Progress<int> _decryptionProgress;

        public TransformingFileManager(MainWindow owner, string filePath) : base(owner)
        {
            this.Owner = owner;
            this._filePath = filePath;
            this._encryptionProgress = null;
            this._decryptionProgress = null;
        }

        public TransformingFileManager(MainWindow owner, string filePath, Progress<int> encryptionProgress, Progress<int> decryptionProgress) : base(owner)
        {
            this.Owner = owner;
            this._filePath = filePath;
            this._encryptionProgress = encryptionProgress;
            this._decryptionProgress = decryptionProgress;
        }

        public bool FileContainsHeader()
        {
            var buff = new char[1024];
            string checkString;

            try
            {
                using (var fReader = new StreamReader(this._filePath))
                {
                    try
                    {
                        fReader.ReadBlock(buff, 0, buff.Length);
                    }
                    catch (IOException e)
                    {
                        FileStatics.WriteToLogFile(e);
                        MessageBox.Show("Unknown fatal IO exception occured - check log file for details");
                        throw;
                    }

                    checkString = new string(buff);
                }
            }
            catch (IOException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Unknown fatal IO exception occured - check log file for details");
                throw;
            }

            return checkString.IndexOf(CryptographicInfo.StartChars, StringComparison.Ordinal) != -1
                   &&
                   checkString.IndexOf(CryptographicInfo.EndChars, StringComparison.Ordinal) != -1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cryptographicInfo"></param>
        /// <param name="password"></param>
        /// <param name="filePath"></param>
        /// <param name="desiredKeyDerivationMilliseconds"></param>
        public void EncryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath, int desiredKeyDerivationMilliseconds)
        {
            ((IProgress<int>)this._encryptionProgress)?.Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

            #region ASSEMBLIES

            Dictionary<string, Assembly> assemblyDictionary = this.Owner._manager.GetAssemblies(this.Owner.EncryptProgressBar, "System.Security.dll", "System.Core.dll");

            Assembly securityAsm = assemblyDictionary["System.Security.dll"];
            Assembly coreAsm = assemblyDictionary["System.Core.dll"];

            #endregion

            var performanceDerivative = new PerformanceDerivative(cryptographicInfo.InstanceKeyCreator.PerformanceDerivative);

            ((IProgress<int>)this._encryptionProgress)?.Report(25);

            // Get the password

            if (password.Length == 0)
            {
                MessageBox.Show("You must enter a password");

                ((IProgress<int>)this._encryptionProgress)?.Report(0);
                return;
            }
#if TRACE
            if (password.Length < App.This.CurrentSettings.MinPasswordLength)
            {
                MessageBox.Show("Password too short");
                ((IProgress<int>)_encryptionProgress)?.Report(0);
                return;
            }
#endif

            Type typeOfKeyDerive = Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                   ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                   ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm);

            KeyDerive keyDevice = this.Owner._transformer.SecureStringToKeyDerive(password, cryptographicInfo.InstanceKeyCreator.salt,
                performanceDerivative, typeOfKeyDerive);

            ((IProgress<int>)this._encryptionProgress)?.Report(35);

            HMAC hmacAlg = null;

            if (cryptographicInfo.Hmac != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac?.HashAlgorithm)
                                                              ?? securityAsm.GetType(cryptographicInfo.Hmac?.HashAlgorithm)
                                                              ?? coreAsm.GetType(cryptographicInfo.Hmac?.HashAlgorithm));
            }

            var encryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager)
                                                     ?? securityAsm.GetType(cryptographicInfo.CryptoManager)
                                                     ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

            encryptor.DebugValuesFinalised += this.Owner.Encryptor_OnDebugValuesFinalised;

#if VERBOSE
            long offset = watch.ElapsedMilliseconds;
#endif
            byte[] key = keyDevice.GetBytes(this.Owner.KeySize / 8);
#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Actual_key_derivation_time__ + (watch.ElapsedMilliseconds - offset));
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Expected_key_derivation_time__ + desiredKeyDerivationMilliseconds);
#endif
            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Pre_encryption_time__ + watch.ElapsedMilliseconds);
#endif
            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(filePath, App.This.DataTempFile, key, cryptographicInfo.EncryptionModeInfo.InitializationVector);

            ((IProgress<int>)this._encryptionProgress)?.Report(90);
#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Post_encryption_time__ + watch.ElapsedMilliseconds);
#endif
            if (cryptographicInfo.Hmac != null)
            {

                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(App.This.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicInfo object
                cryptographicInfo.Hmac.root_Hash = signature;
            }

            // Delete the key from memory for security
            this.Owner.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();
#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Post_authenticate_time__ + watch.ElapsedMilliseconds);
#endif
            // Write the CryptographicInfo object to a file
            cryptographicInfo.WriteHeaderToFile(filePath);

            ((IProgress<int>)this._encryptionProgress)?.Report(98);
#if VERBOSE
            // We have to use Dispatcher.Invoke as the current thread can't access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Transferring the data to the file"; });
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Post_header_time__, watch.ElapsedMilliseconds);
#endif
            FileStatics.AppendToFile(filePath, App.This.DataTempFile);

            ((IProgress<int>)this._encryptionProgress)?.Report(100);
#if VERBOSE 
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_File_write_time__ + watch.ElapsedMilliseconds);
#endif
        }

        public void DecryptDataWithHeader(CryptographicInfo cryptographicInfo, SecureString password, string filePath)
        {
            ((IProgress<int>)this._decryptionProgress).Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Start_time__ + watch.ElapsedMilliseconds);
#endif
            #region ASSEMBLIES

            Dictionary<string, Assembly> assemblyDictionary = this.Owner._manager.GetAssemblies(this.Owner.DecryptProgressBar, "System.Security.dll", "System.Core.dll");

            Assembly securityAsm = assemblyDictionary["System.Security.dll"];
            Assembly coreAsm = assemblyDictionary["System.Core.dll"];

            #endregion

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Assembly_loaded_time__ + watch.ElapsedMilliseconds);
#endif
            var performanceDerivative = new PerformanceDerivative(cryptographicInfo.InstanceKeyCreator.PerformanceDerivative);

            Type typeOfKeyDerive = Type.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                   ?? securityAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm)
                                   ?? coreAsm.GetType(cryptographicInfo.InstanceKeyCreator.root_HashAlgorithm);

            KeyDerive keyDevice = this.Owner._transformer.SecureStringToKeyDerive(password, cryptographicInfo.InstanceKeyCreator.salt,
                performanceDerivative, typeOfKeyDerive);

            ((IProgress<int>)this._decryptionProgress).Report(10);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Password_managed_time__ + watch.ElapsedMilliseconds);
#endif
            HMAC hmacAlg = null;

            if (cryptographicInfo.Hmac != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(Type.GetType(cryptographicInfo.Hmac.HashAlgorithm)
                                                              ?? securityAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm)
                                                              ?? coreAsm.GetType(cryptographicInfo.Hmac.HashAlgorithm));
            }

            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicInfo.CryptoManager)
                                                                             ?? securityAsm.GetType(cryptographicInfo.CryptoManager)
                                                                             ?? coreAsm.GetType(cryptographicInfo.CryptoManager));

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Object_built_time__ + watch.ElapsedMilliseconds);
#endif
            FileStatics.RemovePrependData(filePath, App.This.HeaderLessTempFile, cryptographicInfo.HeaderLength);

            ((IProgress<int>)this._decryptionProgress).Report(20);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Header_removed_time__ + watch.ElapsedMilliseconds);
#endif
            byte[] key = keyDevice.GetBytes((int)cryptographicInfo.EncryptionModeInfo.KeySize / 8);

            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicInfo.Hmac != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(App.This.HeaderLessTempFile, key,
                    cryptographicInfo.Hmac.root_Hash, hmacAlg);
            }

            ((IProgress<int>)this._decryptionProgress).Report(35);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_HMAC_verified_time__ + watch.ElapsedMilliseconds);
#endif

            // If that didn't succeed, the file has been tampered with
            if (cryptographicInfo.Hmac != null && !isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
#if VERBOSE
                Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Pre_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                decryptor.DecryptFileBytes(App.This.HeaderLessTempFile, App.This.DataTempFile, key, cryptographicInfo.EncryptionModeInfo.InitializationVector);
#if VERBOSE
                ((IProgress<int>)this._decryptionProgress).Report(75);
                Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Post_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                // Move the file to the original file location
                File.Copy(App.This.DataTempFile, filePath, true);
                ((IProgress<int>)this._decryptionProgress).Report(100);
#if VERBOSE
                Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_File_copied_time__ + watch.ElapsedMilliseconds);
#endif
                MessageBox.Show("Successfully Decrypted");
            }
            catch (CryptographicException)
            {
                MessageBox.Show("Wrong password or corrupted file");
            }
            finally
            {
                // Delete the key from memory for security
                this.Owner.ZeroMemory(gch.AddrOfPinnedObject(), key.Length);
                gch.Free();
            }
        }
    }
}
