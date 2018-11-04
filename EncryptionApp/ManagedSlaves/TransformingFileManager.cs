using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Events;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;

namespace Encryption_App.ManagedSlaves
{
    internal class TransformingFileManager : ManagedSlave
    {
        private readonly string _filePath;
        private readonly Progress<int> _encryptionProgress;
        private readonly Progress<int> _decryptionProgress;
        private readonly ResourceManager _manager;
        private readonly TransformationPropertiesManager _transformer;

        public TransformingFileManager(MainWindow owner, string filePath) : base(owner)
        {
            this.Owner = owner;
            this._filePath = filePath;
            // BUG progress not working
            this._encryptionProgress = null;
            this._decryptionProgress = null;
            // TODO make owned by MainWindow, share assemblies
            this._manager = new ResourceManager(this);
            this._transformer = new TransformationPropertiesManager();
        }

        public TransformingFileManager(MainWindow owner, string filePath, Progress<int> encryptionProgress, Progress<int> decryptionProgress) : base(owner)
        {
            this.Owner = owner;
            this._filePath = filePath;
            this._encryptionProgress = encryptionProgress;
            this._decryptionProgress = decryptionProgress;
            this._manager = new ResourceManager(this);
            this._transformer = new TransformationPropertiesManager();
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

            return checkString.IndexOf(CryptographicRepresentative.StartChars, StringComparison.Ordinal) != -1
                   &&
                   checkString.IndexOf(CryptographicRepresentative.EndChars, StringComparison.Ordinal) != -1;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <param name="password"></param>
        /// <param name="filePath"></param>
        /// <param name="desiredKeyDerivationMilliseconds"></param>
        public void EncryptDataWithHeader(RequestStateRecord request, SecureString password, string filePath, int desiredKeyDerivationMilliseconds)
        {
            ((IProgress<int>)this._encryptionProgress)?.Report(0);
            password.MakeReadOnly();

#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

            #region ASSEMBLIES

            Dictionary<string, Assembly> assemblyDictionary = this._manager.GetAssemblies(this.Owner.EncryptProgressBar, "System.Security.dll", "System.Core.dll");

            Assembly securityAsm = assemblyDictionary["System.Security.dll"];
            Assembly coreAsm = assemblyDictionary["System.Core.dll"];

            #endregion

            // Create a random salt and iv
            var salt = new byte[request.contract.InstanceKeyContract.SaltLengthBytes];
            var iv = new byte[request.contract.TransformationContract.InitializationVectorSizeBytes];
            var rng = new RNGCryptoServiceProvider();
            try
            {
                rng.GetBytes(iv);
                rng.GetBytes(salt);
            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show("There was an error generating secure random numbers. Please try again - check log file for more details");
            }

            var performanceDerivative = new PerformanceDerivative(request.contract.InstanceKeyContract.PerformanceDerivative);

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

            KeyDerive keyDevice = this._transformer.SecureStringToKeyDerive(password, salt,
                performanceDerivative, request.contract.InstanceKeyContract.KeyAlgorithm);

            ((IProgress<int>)this._encryptionProgress)?.Report(35);

            HMAC hmacAlg = null;

            if (request.contract.HmacContract != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC)Activator.CreateInstance(request.contract.HmacContract.HashAlgorithm);
            }

            var encryptor = (SymmetricCryptoManager)Activator.CreateInstance(request.contract.TransformationContract.CryptoManager);

            encryptor.DebugValuesFinalised += Encryptor_OnDebugValuesFinalised;

#if VERBOSE
            long offset = watch.ElapsedMilliseconds;
#endif
            byte[] key = keyDevice.GetBytes((int)request.contract.TransformationContract.KeySize / 8);
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
            encryptor.EncryptFileBytes(filePath, App.This.DataTempFile, key, iv);

            ((IProgress<int>)this._encryptionProgress)?.Report(90);
#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Post_encryption_time__ + watch.ElapsedMilliseconds);
#endif

            byte[] hash = null;

            if (request.contract.HmacContract != null)
            {

                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(App.This.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicRepresentative object
                hash = signature;
            }

            // Delete the key from memory for security
            MainWindow.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();
#if VERBOSE
            Console.WriteLine(Resources.MainWindow_EncryptDataWithHeader_Post_authenticate_time__ + watch.ElapsedMilliseconds);
#endif
            var cryptographicInfo = new SymmetricCryptographicRepresentative
            {
                CryptoManager = request.contract.TransformationContract.CryptoManager.AssemblyQualifiedName,
                TransformationModeInfo = new TransformationRepresentative
                {
                    BlockSize = request.contract.TransformationContract.BlockSize,
                    CryptoManager = request.contract.TransformationContract.CryptoManager,
                    InitializationVector = iv,
                    KeySize = request.contract.TransformationContract.KeySize,
                    Mode = request.contract.TransformationContract.Mode
                },
                Hmac = new HmacRepresentative
                {
                    HashAlgorithm = request.contract.HmacContract?.HashAlgorithm,
                    HashBytes = hash
                },
                InstanceKeyCreator = new KeyRepresentative
                {
                    KeyAlgorithm = request.contract.InstanceKeyContract.KeyAlgorithm,
                    PerformanceDerivative = request.contract.InstanceKeyContract.PerformanceDerivative,
                    Salt = salt
                }
            };

            // Write the CryptographicRepresentative object to a file
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

        public void DecryptDataWithHeader(SymmetricCryptographicRepresentative cryptographicRepresentative, SecureString password, string filePath)
        {
            ((IProgress<int>)this._decryptionProgress)?.Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Start_time__ + watch.ElapsedMilliseconds);
#endif
            #region ASSEMBLIES

            Dictionary<string, Assembly> assemblyDictionary = this._manager.GetAssemblies(this.Owner.DecryptProgressBar, "System.Security.dll", "System.Core.dll");

            Assembly securityAsm = assemblyDictionary["System.Security.dll"];
            Assembly coreAsm = assemblyDictionary["System.Core.dll"];

            #endregion

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Assembly_loaded_time__ + watch.ElapsedMilliseconds);
#endif
            var performanceDerivative = new PerformanceDerivative(cryptographicRepresentative.InstanceKeyCreator.PerformanceDerivative);

            KeyDerive keyDevice = this._transformer.SecureStringToKeyDerive(password, cryptographicRepresentative.InstanceKeyCreator.Salt,
                performanceDerivative, cryptographicRepresentative.InstanceKeyCreator.KeyAlgorithm);

            ((IProgress<int>)this._decryptionProgress)?.Report(10);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Password_managed_time__ + watch.ElapsedMilliseconds);
#endif
            HMAC hmacAlg = null;

            if (cryptographicRepresentative.Hmac.HashAlgorithm != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(cryptographicRepresentative.Hmac.HashAlgorithm);
            }

            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(Type.GetType(cryptographicRepresentative.CryptoManager)
                                                                             ?? securityAsm.GetType(cryptographicRepresentative.CryptoManager)
                                                                             ?? coreAsm.GetType(cryptographicRepresentative.CryptoManager));

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Object_built_time__ + watch.ElapsedMilliseconds);
#endif
            FileStatics.RemovePrependData(filePath, App.This.HeaderLessTempFile, cryptographicRepresentative.HeaderLength);

            ((IProgress<int>)this._decryptionProgress)?.Report(20);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Header_removed_time__ + watch.ElapsedMilliseconds);
#endif
            byte[] key = keyDevice.GetBytes((int)cryptographicRepresentative.TransformationModeInfo.KeySize / 8);

            GCHandle gch = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicRepresentative.Hmac.HashAlgorithm != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(App.This.HeaderLessTempFile, key,
                    cryptographicRepresentative.Hmac.HashBytes, hmacAlg);
            }

            ((IProgress<int>)this._decryptionProgress)?.Report(35);

#if VERBOSE
            Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_HMAC_verified_time__ + watch.ElapsedMilliseconds);
#endif

            // If that didn't succeed, the file has been tampered with
            if (cryptographicRepresentative.Hmac.HashAlgorithm != null && !isVerified)
            {
                throw new CryptographicException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
#if VERBOSE
                Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Pre_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                decryptor.DecryptFileBytes(App.This.HeaderLessTempFile, App.This.DataTempFile, key, cryptographicRepresentative.TransformationModeInfo.InitializationVector);
#if VERBOSE
                ((IProgress<int>)this._decryptionProgress)?.Report(75);
                Console.WriteLine(Resources.MainWindow_DecryptDataWithHeader_Post_decryption_time__ + watch.ElapsedMilliseconds);
#endif
                // Move the file to the original file location
                File.Copy(App.This.DataTempFile, filePath, true);
                ((IProgress<int>)this._decryptionProgress)?.Report(100);
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
                MainWindow.ZeroMemory(gch.AddrOfPinnedObject(), key.Length);
                gch.Free();
            }
        }



        // Dynamic issue
        // ReSharper disable once UnusedMember.Local
        private static void Encryptor_OnDebugValuesFinalised(object sender, DebugValuesFinalisedEventArgs e)
        {
            try
            {
                FileStatics.WriteToLogFile(e.FinalisedStrings.ToArray<object>()); // little bit of a hack, prevents covariant conversion warning, which is managed in the function
            }
            catch (IOException exception)
            {
                MessageBox.Show($"Unable to log values - IO exception occured with message: {exception.Message}");
            }
        }
    }
}
