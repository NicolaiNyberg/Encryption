using System;
using System.Security.Cryptography;
using System.Text;

namespace Encryption.Symmetrical
{
    public class Rfc2898DeriveBytesSha1 : Rfc2898DeriveBytesBase
    {
        public Rfc2898DeriveBytesSha1(string password, byte[] salt, int iterations)
            : this(new UTF8Encoding(false).GetBytes(password), salt, iterations) { }

        public Rfc2898DeriveBytesSha1(byte[] password, byte[] salt, int iterations)
            : base(salt, iterations, new HMACSHA1(password))
        { }
    }

    public class Rfc2898DeriveBytesSha256 : Rfc2898DeriveBytesBase
    {
        public Rfc2898DeriveBytesSha256(string password, byte[] salt, int iterations)
            : this(new UTF8Encoding(false).GetBytes(password), salt, iterations) { }

        public Rfc2898DeriveBytesSha256(byte[] password, byte[] salt, int iterations)
            : base(salt, iterations, new HMACSHA256(password))
        { }
    }

    public class Rfc2898DeriveBytesSha384 : Rfc2898DeriveBytesBase
    {
        public Rfc2898DeriveBytesSha384(string password, byte[] salt, int iterations)
            : this(new UTF8Encoding(false).GetBytes(password), salt, iterations) { }

        public Rfc2898DeriveBytesSha384(byte[] password, byte[] salt, int iterations)
            : base(salt, iterations, new HMACSHA384(password))
        { }
    }

    // Inparticular SHA512 is not GPU-friendly
    public class Rfc2898DeriveBytesSha512 : Rfc2898DeriveBytesBase
    {
        public Rfc2898DeriveBytesSha512(string password, byte[] salt, int iterations)
            : this(new UTF8Encoding(false).GetBytes(password), salt, iterations) { }

        public Rfc2898DeriveBytesSha512(byte[] password, byte[] salt, int iterations)
            : base(salt, iterations, new HMACSHA512(password))
        { }
    }

    // Converted from Microsofts Rfc2898DeriveBytes.
    // Implements PBKDF2 using a customizable HMAC
    public abstract class Rfc2898DeriveBytesBase
        : DeriveBytes
    {
        readonly HMAC _hmac;
        byte[] _buffer;
        byte[] _salt;

        uint _iterations;
        uint _block;
        int _startIndex;
        int _endIndex;

        const int BlockSize = 20;

        protected Rfc2898DeriveBytesBase(byte[] salt, int iterations, HMAC hmac)
        {
            Salt = salt;
            IterationCount = iterations;
            _hmac = hmac;
            Initialize();
        }

        public int IterationCount
        {
            get { return (int)_iterations; }
            set
            {
                _iterations = (uint)value;
                Initialize();
            }
        }

        public byte[] Salt
        {
            get { return (byte[])_salt.Clone(); }
            set
            {
                _salt = (byte[])value.Clone();
                Initialize();
            }
        }

        [System.Security.SecuritySafeCritical]  // auto-generated
        public override byte[] GetBytes(int cb)
        {
            var password = new byte[cb];

            var offset = 0;
            var size = _endIndex - _startIndex;
            if (size > 0)
            {
                if (cb >= size)
                {
                    Array.Copy(_buffer, _startIndex, password, 0, size);
                    _startIndex = _endIndex = 0;
                    offset += size;
                }
                else
                {
                    Array.Copy(_buffer, _startIndex, password, 0, cb);
                    _startIndex += cb;
                    return password;
                }
            }

            while (offset < cb)
            {
                var block = Func();
                var remainder = cb - offset;
                if (remainder > BlockSize)
                {
                    Array.Copy(block, 0, password, offset, BlockSize);
                    offset += BlockSize;
                }
                else
                {
                    Array.Copy(block, 0, password, offset, remainder);
                    offset += remainder;
                    Array.Copy(block, remainder, _buffer, _startIndex, BlockSize - remainder);
                    _endIndex += (BlockSize - remainder);
                    return password;
                }
            }
            return password;
        }

        public override void Reset()
        {
            Initialize();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (!disposing) return;
            _hmac?.Dispose();
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);
            if (_salt != null)
                Array.Clear(_salt, 0, _salt.Length);
        }

        void Initialize()
        {
            if (_buffer != null)
                Array.Clear(_buffer, 0, _buffer.Length);
            _buffer = new byte[BlockSize];
            _block = 1;
            _startIndex = _endIndex = 0;
        }

        // This function is defined as follow :
        // Func (S, i) = HMAC(S || i) | HMAC2(S || i) | ... | HMAC(iterations) (S || i) 
        // where i is the block number. 
        byte[] Func()
        {
            var intBlock = UnitToBigEndianBytes(_block);

            _hmac.TransformBlock(_salt, 0, _salt.Length, _salt, 0);
            _hmac.TransformFinalBlock(intBlock, 0, intBlock.Length);
            var temp = _hmac.Hash;
            _hmac.Initialize();

            var ret = temp;
            for (var i = 2; i <= _iterations; i++)
            {
                temp = _hmac.ComputeHash(temp);
                for (var j = 0; j < BlockSize; j++)
                {
                    ret[j] ^= temp[j];
                }
            }

            // increment the block count. 
            _block++;
            return ret;
        }

        // encodes the integer i into a 4-byte array, in big endian. 
        static byte[] UnitToBigEndianBytes(uint i)
        {
            var b = BitConverter.GetBytes(i);
            byte[] littleEndianBytes = { b[3], b[2], b[1], b[0] };
            return BitConverter.IsLittleEndian ? littleEndianBytes : b;
        }
    }
}
