namespace FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation
{
    using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
    using System;
    using System.Collections;
    using System.Security.Cryptography;
    using System.Text;

#pragma warning disable CS1591
    // TODO @NATHAN

    public sealed class Pbkdf2Advanced : KeyDerive
    {
        // needs to be fixed
        private const int BlockSize = 20;

        private readonly HMAC _hmac;

        private readonly byte[] _salt;

        private int _begin;

        private int _end;

        private uint _blockCount;

        private byte[] _buffer;

        private uint _iterations;

        // something about mode needing to be const or default
        public Pbkdf2Advanced(
            string password,
            int saltSize,
            uint iterations /*1000*/,
            Type mode /* = typeof(HMACSHA256)*/)
        {
            if (saltSize < 0)
                throw new ArgumentOutOfRangeException(nameof(saltSize));

            var salt = new byte[saltSize];
            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(salt);

            this._salt = salt;
            this._iterations = iterations;
            if (mode.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
            {
                this._hmac = (System.Security.Cryptography.HMAC)Activator.CreateInstance(
                    mode,
                    new UTF8Encoding(false).GetBytes(password));
            }
            else
            {
                throw new ArgumentException("You did not supply a valid Hashing algorithm");
            }

            this.Reset();
        }

        public Pbkdf2Advanced(
            string password,
            byte[] salt,
            uint iterations /*=1000*/,
            Type mode /* = typeof(HMACSHA256)*/)
            : this(new UTF8Encoding(false).GetBytes(password), salt, iterations, mode)
        {
        }

        public Pbkdf2Advanced(
            IEnumerable password,
            byte[] salt,
            uint iterations /*=1000*/,
            Type mode /* = typeof(HMACSHA256)*/)
        {
            this._salt = salt;
            this._iterations = iterations;
            if (mode.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
            {
                this._hmac = (System.Security.Cryptography.HMAC)Activator.CreateInstance(mode, password);
            }
            else
            {
                throw new ArgumentException("You did not supply a valid Hashing algorithm");
            }

            this.Reset();
        }

        /// <inheritdoc />
        /// <summary>
        /// The password, stored encrypted
        /// </summary>
        public override byte[] Password
        {
            get => ProtectedData.Unprotect(this.BackEncryptedArray, null, DataProtectionScope.CurrentUser);
            private protected set
            {
                this.BackEncryptedArray = ProtectedData.Protect(value, null, DataProtectionScope.CurrentUser);
            }
        }

        public override object PerformanceValues
        {
            get => this._iterations;
            private protected set => this._iterations = (uint)value;
        }

        public override byte[] GetBytes(int length)
        {
            if (length <= 0)
                throw new ArgumentOutOfRangeException(nameof(length));
            var password = new byte[length];

            var offset = 0;
            int size = this._end - this._begin;

            if (size > 0)
            {
                if (length >= size)
                {
                    Buffer.BlockCopy(this._buffer, this._begin, password, 0, size);
                    this._begin = this._end = 0;
                    offset += size;
                }
                else
                {
                    Buffer.BlockCopy(this._buffer, this._begin, password, 0, (int)length);
                    this._begin += (int)length;
                    return password;
                }
            }

            System.Diagnostics.Debug.Assert(
                this._begin == 0 && this._end == 0,
                "Invalid start or end indexes in the buffer!");

            while (offset < length)
            {
                byte[] block = this.Transform();
                int remainder = (int)length - offset;

                if (remainder > BlockSize)
                {
                    Buffer.BlockCopy(block, 0, password, offset, BlockSize);
                    offset += BlockSize;
                }
                else
                {
                    Buffer.BlockCopy(block, 0, password, offset, remainder);
                    Buffer.BlockCopy(block, remainder, this._buffer, this._begin, BlockSize - remainder);
                    this._end += (BlockSize - remainder);
                    return password;
                }
            }

            return password;
        }

        public override void Reset()
        {
            if (this._buffer != null)
            {
                Array.Clear(this._buffer, 0, this._buffer.Length);
            }

            this._buffer = new byte[BlockSize];
            this._blockCount = 1;
            this._begin = this._end = 0;
        }

        public static ulong TransformPerformance(PerformanceDerivative performanceDerivative, ulong milliseconds)
        {
            return performanceDerivative.TransformToRfc2898(milliseconds);
        }

        private byte[] Transform()
        {
            byte[] b = BitConverter.GetBytes(this._blockCount);
            byte[] littleEndianBytes = { b[3], b[2], b[1], b[0] };
            byte[] intBlock = BitConverter.IsLittleEndian ? littleEndianBytes : b;

            this._hmac.TransformBlock(this._salt, 0, this._salt.Length, this._salt, 0);
            this._hmac.TransformFinalBlock(intBlock, 0, intBlock.Length);
            byte[] temporaryHash = this._hmac.Hash;
            this._hmac.Initialize();

            byte[] ret = temporaryHash;
            for (var i = 2; i <= this._iterations; i++)
            {
                temporaryHash = this._hmac.ComputeHash(temporaryHash);
                for (var j = 0; j < BlockSize; j++)
                {
                    ret[j] ^= temporaryHash[j];
                }
            }

            // increment the blockCount count.
            this._blockCount++;
            return ret;
        }
    }
}