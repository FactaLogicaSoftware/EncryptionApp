using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;
using Encryption_App;

namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    public sealed class Pbkdf2Advanced : KeyDerive
    {
        private byte[] _buffer;
        private readonly byte[] _salt;
        private readonly System.Security.Cryptography.HMAC _hmac;

        private uint _iterations;
        private uint _blockCount;
        private int _begin, _end;

        //needs to be fixed
        private const int BlockSize = 20;
        //something about mode needing to be const or default
        public Pbkdf2Advanced(string password, int saltSize, uint iterations/*1000*/, Type mode/* = typeof(HMACSHA256)*/)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException(nameof(saltSize));

            var salt = new byte[saltSize];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(salt);

            _salt = salt;
            _iterations = iterations;
            if (mode.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
            {
                _hmac = (System.Security.Cryptography.HMAC)Activator.CreateInstance(mode, new UTF8Encoding(false).GetBytes(password));
            }
            else
            {
                throw new ArgumentException("You did not supply a valid Hashing algorithm");
            }

            Reset();
        }

        public Pbkdf2Advanced(string password, byte[] salt, uint iterations/*=1000*/, Type mode/* = typeof(HMACSHA256)*/) : this(new UTF8Encoding(false).GetBytes(password), salt, iterations, mode) { }

        public Pbkdf2Advanced(IEnumerable password, byte[] salt, uint iterations/*=1000*/, Type mode/* = typeof(HMACSHA256)*/)
        {
            _salt = salt;
            _iterations = iterations;
            if (mode.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
            {
                _hmac = (System.Security.Cryptography.HMAC)Activator.CreateInstance(mode, password);
            }
            else
            {
                throw new ArgumentException("You did not supply a valid Hashing algorithm");
            }

            Reset();
        }

        public override void GetBytes(byte[] toFill)
        {
            if (toFill.Length <= 0)
                throw new ArgumentOutOfRangeException(nameof(toFill.Length));
            var password = new byte[toFill.Length];

            var offset = 0;
            int size = _end - _begin;

            if (size > 0)
            {
                if (toFill.Length >= size)
                {
                    Buffer.BlockCopy(_buffer, _begin, password, 0, size);
                    _begin = _end = 0;
                    offset += size;
                }
                else
                {
                    Buffer.BlockCopy(_buffer, _begin, password, 0, toFill.Length);
                    _begin += toFill.Length;
                    toFill = password;
                }
            }

            System.Diagnostics.Debug.Assert(_begin == 0 && _end == 0, "Invalid start or end indexes in the buffer!");

            while (offset < toFill.Length)
            {
                byte[] block = Transform();
                int remainder = toFill.Length - offset;

                if (remainder > BlockSize)
                {
                    Buffer.BlockCopy(block, 0, password, offset, BlockSize);
                    offset += BlockSize;
                }
                else
                {
                    Buffer.BlockCopy(block, 0, password, offset, remainder);
                    Buffer.BlockCopy(block, remainder, _buffer, _begin, BlockSize - remainder);
                    _end += (BlockSize - remainder);
                    toFill = password;
                }
            }
            toFill = password;
        }

        public override object PerformanceValues
        {
            get => _iterations;
            private protected set => _iterations = (uint)value;
        }

        /// <inheritdoc />
        /// <summary>
        /// The password, stored encrypted
        /// </summary>
        public override byte[] Password
        {
            get => ProtectedData.Unprotect(BackEncryptedArray, null, DataProtectionScope.CurrentUser);
            private protected set
            {
                BackEncryptedArray = ProtectedData.Protect(value, null, DataProtectionScope.CurrentUser);
                Usable = PerformanceValues != null;
            }
        }

        public override void Reset()
        {
            if (_buffer != null)
            {
                Array.Clear(_buffer, 0, _buffer.Length);
            }

            _buffer = new byte[BlockSize];
            _blockCount = 1;
            _begin = _end = 0;
        }

        public override void TransformPerformance(PerformanceDerivative performanceDerivative, ulong milliseconds)
        {
            PerformanceValues = performanceDerivative.TransformToRfc2898(milliseconds);
        }

        private byte[] Transform()
        {
            byte[] b = BitConverter.GetBytes(_blockCount);
            byte[] littleEndianBytes = { b[3], b[2], b[1], b[0] };
            byte[] intBlock = BitConverter.IsLittleEndian ? littleEndianBytes : b;

            _hmac.TransformBlock(_salt, 0, _salt.Length, _salt, 0);
            _hmac.TransformFinalBlock(intBlock, 0, intBlock.Length);
            byte[] temporaryHash = _hmac.Hash;
            _hmac.Initialize();

            byte[] ret = temporaryHash;
            for (var i = 2; i <= _iterations; i++)
            {
                temporaryHash = _hmac.ComputeHash(temporaryHash);
                for (var j = 0; j < BlockSize; j++)
                {
                    ret[j] ^= temporaryHash[j];
                }
            }

            // increment the blockCount count.
            _blockCount++;
            return ret;
        }
    }
}
