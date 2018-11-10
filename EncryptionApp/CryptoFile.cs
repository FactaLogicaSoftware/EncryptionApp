using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Events;
using FactaLogicaSoftware.CryptoTools.Exceptions;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;

namespace Encryption_App
{
    internal class CryptoFile
    {
        private readonly string _filePath;
        private readonly Progress<int> _progress;

        public CryptoFile(string filePath)
        {
            this._filePath = filePath;
            this._progress = null;
        }

        public CryptoFile(string filePath, Progress<int> progress)
        {
            this._filePath = filePath;
            this._progress = progress;
        }

        public bool FileContainsHeader()
        {
            var buff = new char[1024];
            string checkString;

            try
            {
                using (var reader = new StreamReader(this._filePath))
                {
                    try
                    {
                        reader.ReadBlock(buff, 0, buff.Length);
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

            return checkString.IndexOf(CryptographicRepresentative.StartChars, StringComparison.Ordinal) != -1 &&
                   checkString.IndexOf(CryptographicRepresentative.EndChars, StringComparison.Ordinal) != -1;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="request"></param>
        /// <param name="password"></param>
        /// <param name="desiredKeyDerivationMilliseconds"></param>
        public void EncryptDataWithHeader(RequestStateRecord request, SecureString password,
            int desiredKeyDerivationMilliseconds)
        {
            ((IProgress<int>)this._progress)?.Report(0);
            password.MakeReadOnly();

#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif

            // Create a random salt and iv
            var salt = new byte[request.Contract.InstanceKeyContract.SaltLengthBytes];
            var iv = new byte[request.Contract.TransformationContract.InitializationVectorSizeBytes];
            var rng = new RNGCryptoServiceProvider();
            try
            {
                rng.GetBytes(iv);
                rng.GetBytes(salt);
            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "There was an error generating secure random numbers. Please try again - check log file for more details");
            }

            var performanceDerivative =
                new PerformanceDerivative(request.Contract.InstanceKeyContract.PerformanceDerivative);

            ((IProgress<int>)this._progress)?.Report(25);

            // Get the password

            if (password.Length == 0)
            {
                MessageBox.Show("You must enter a password");

                ((IProgress<int>)this._progress)?.Report(0);
                return;
            }
#if TRACE
            if (password.Length < App.This.CurrentSettings.MinPasswordLength)
            {
                MessageBox.Show("Password too short");
                ((IProgress<int>)_progress)?.Report(0);
                return;
            }
#endif

            GCHandle byteHandle = SecureStringConverter.SecureStringToKeyDerive(password, salt,
                performanceDerivative, request.Contract.InstanceKeyContract.KeyAlgorithm, out KeyDerive keyDevice);

            ((IProgress<int>)this._progress)?.Report(35);

            HMAC hmacAlg = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC)Activator.CreateInstance(request.Contract.HmacContract.HashAlgorithm);
            }

            var @params = new object[] { 1024 * 1024 * 1024, new AesCryptoServiceProvider() };

            var encryptor =
                (SymmetricCryptoManager)Activator.CreateInstance(request.Contract.TransformationContract.CryptoManager,
                    @params);

            encryptor.DebugValuesFinalised += Encryptor_OnDebugValuesFinalised;

#if VERBOSE
            long offset = watch.ElapsedMilliseconds;
#endif
            byte[] key = keyDevice.GetBytes((int)request.Contract.TransformationContract.KeySize / 8);

            Externals.ZeroMemory(byteHandle.AddrOfPinnedObject(), ((byte[])byteHandle.Target).Length);

            byteHandle.Free();
#if VERBOSE
            Console.WriteLine(DebugResources.ActualKeyDerivationTime_WriteString +
                              (watch.ElapsedMilliseconds - offset));
            Console.WriteLine(DebugResources.ExpectedKeyDerivationTime_WriteString + desiredKeyDerivationMilliseconds);
#endif
            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

#if VERBOSE
            Console.WriteLine(DebugResources.PreEncryptionTime_WriteString + watch.ElapsedMilliseconds);
#endif
            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(this._filePath, App.This.DataTempFile, key, iv);

            ((IProgress<int>)this._progress)?.Report(90);
#if VERBOSE
            Console.WriteLine(DebugResources.PostEncryptionTime_WriteString + watch.ElapsedMilliseconds);
#endif

            byte[] hash = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(App.This.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicRepresentative object
                hash = signature;
            }

            HmacRepresentative hmac = request.Contract.HmacContract != null && hash != null
                                        ? new HmacRepresentative(request.Contract.HmacContract.HashAlgorithm, hash)
                                        : null;

            // Delete the key from memory for security
            Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();
#if VERBOSE
            Console.WriteLine(DebugResources.PostHMACCreationTime_WriteString + watch.ElapsedMilliseconds);
#endif
            var cryptographicInfo = new SymmetricCryptographicRepresentative
            (
                new TransformationRepresentative
                (
                    request.Contract.TransformationContract.CryptoManager,
                    iv,
                    request.Contract.TransformationContract.CipherMode,
                    request.Contract.TransformationContract.PaddingMode,
                    request.Contract.TransformationContract.KeySize,
                    request.Contract.TransformationContract.BlockSize
                ),
                new KeyRepresentative
                (
                    request.Contract.InstanceKeyContract.KeyAlgorithm,
                    request.Contract.InstanceKeyContract.PerformanceDerivative,
                    salt
                ),
                hmac
            );

            // Write the CryptographicRepresentative object to a file
            cryptographicInfo.WriteHeaderToFile(this._filePath);

            ((IProgress<int>)this._progress)?.Report(98);
#if VERBOSE
            // We have to use Dispatcher.Invoke as the current thread can't access these objects this.dispatcher.Invoke(() => { EncryptOutput.Content = "Transferring the data to the file"; });
            Console.WriteLine(DebugResources.PostHeaderWriteTime_WriteString, watch.ElapsedMilliseconds);
#endif
            FileStatics.AppendToFile(this._filePath, App.This.DataTempFile);

            ((IProgress<int>)this._progress)?.Report(100);
#if VERBOSE
            Console.WriteLine(DebugResources.FileWriteTime_WriteString + watch.ElapsedMilliseconds);
#endif
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="cryptographicRepresentative"></param>
        /// <param name="password"></param>
        /// TODO decompose
        public void DecryptDataWithHeader(SymmetricCryptographicRepresentative cryptographicRepresentative, SecureString password)
        {
            ((IProgress<int>)this._progress)?.Report(0);
            password.MakeReadOnly();
#if VERBOSE
            Stopwatch watch = Stopwatch.StartNew();
#endif
            var performanceDerivative = new PerformanceDerivative(cryptographicRepresentative.InstanceKeyCreator.PerformanceDerivative);

            GCHandle byteHandle = SecureStringConverter.SecureStringToKeyDerive(password, cryptographicRepresentative.InstanceKeyCreator.Salt,
                performanceDerivative, cryptographicRepresentative.InstanceKeyCreator.KeyAlgorithm, out KeyDerive keyDevice);

            ((IProgress<int>)this._progress)?.Report(10);

#if VERBOSE
            Console.WriteLine(DebugResources.PasswordControlledTime__WriteString + watch.ElapsedMilliseconds);
#endif
            HMAC hmacAlg = null;

            if (cryptographicRepresentative.Hmac != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(cryptographicRepresentative.Hmac.HashAlgorithm);
            }

            var @params = new object[]
            {
                1024 * 1024 * 8, new AesCng
                {
                    BlockSize = (int)cryptographicRepresentative.TransformationModeInfo.BlockSize,
                    KeySize = (int)cryptographicRepresentative.TransformationModeInfo.KeySize,
                    Mode = cryptographicRepresentative.TransformationModeInfo.CipherMode,
                    Padding = cryptographicRepresentative.TransformationModeInfo.PaddingMode
                }
            };


            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(cryptographicRepresentative.TransformationModeInfo.CryptoManager, @params);

            FileStatics.RemovePrependData(this._filePath, App.This.HeaderLessTempFile, cryptographicRepresentative.HeaderLength);

            ((IProgress<int>)this._progress)?.Report(20);

#if VERBOSE
            Console.WriteLine(DebugResources.HeaderRemovedTime + watch.ElapsedMilliseconds);
#endif
            byte[] key = keyDevice.GetBytes((int)cryptographicRepresentative.TransformationModeInfo.KeySize / 8);

            Externals.ZeroMemory(byteHandle.AddrOfPinnedObject(), ((byte[])byteHandle.Target).Length);

            byteHandle.Free();

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicRepresentative.Hmac != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(App.This.HeaderLessTempFile, key,
                    cryptographicRepresentative.Hmac.HashBytes, hmacAlg);
            }

            ((IProgress<int>)this._progress)?.Report(35);

#if VERBOSE
            Console.WriteLine(DebugResources.PostHMACAuthenticationTime_WriteString + watch.ElapsedMilliseconds);
#endif

            // If that didn't succeed, the file has been tampered with
            if (cryptographicRepresentative.Hmac != null && !isVerified)
            {
                throw new UnverifiableDataException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
#if VERBOSE
                Console.WriteLine(DebugResources.PreDecryptionTime_WriteString + watch.ElapsedMilliseconds);
#endif
                decryptor.DecryptFileBytes(App.This.HeaderLessTempFile, App.This.DataTempFile, key, cryptographicRepresentative.TransformationModeInfo.InitializationVector);
#if VERBOSE
                ((IProgress<int>)this._progress)?.Report(75);
                Console.WriteLine(DebugResources.PostDecryptionTime_WriteString + watch.ElapsedMilliseconds);
#endif
                // Move the file to the original file location
                File.Copy(App.This.DataTempFile, this._filePath, true);
                ((IProgress<int>)this._progress)?.Report(100);
#if VERBOSE
                Console.WriteLine(DebugResources.FileCopiedTime_WriteString + watch.ElapsedMilliseconds);
#endif
            }
            finally
            {
                // Delete the key from memory for security
                Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
                keyHandle.Free();
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