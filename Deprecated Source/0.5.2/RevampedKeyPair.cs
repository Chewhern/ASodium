using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public class RevampedKeyPair
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        /// <summary>Initializes a new instance of the <see cref="KeyPair"/> class.</summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <exception cref="KeyOutOfRangeException"></exception>
        public RevampedKeyPair(byte[] publicKey, byte[] privateKey)
        {
            //verify that the private key length is a multiple of 16
            if (privateKey.Length % 16 != 0)
                throw new ArgumentException("Private Key length must be a multiple of 16 bytes.");

            _publicKey = publicKey;

            _privateKey = privateKey;
            _ProtectKey();
        }

        ~RevampedKeyPair()
        {
            Clear();
        }

        /// <summary>Gets the Public Key.</summary>
        public byte[] PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>Gets the Private Key.</summary>
        public byte[] PrivateKey
        {
            get
            {
                _UnprotectKey();
                var tmp = new byte[_privateKey.Length];
                Array.Copy(_privateKey, tmp, tmp.Length);
                _ProtectKey();

                return tmp;
            }
        }

        /// <summary>Clear private key and public key through cryptographically secure way.</summary>
        public void Clear()
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(_privateKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), _privateKey.Length);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(_publicKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), _publicKey.Length);
            MyGeneralGCHandle.Free();
        }

        private void _ProtectKey()
        {
            #if NET461
                ProtectedMemory.Protect(_privateKey, MemoryProtectionScope.SameProcess);
            #endif
        }

        private void _UnprotectKey()
        {
            #if NET461
                ProtectedMemory.Unprotect(_privateKey, MemoryProtectionScope.SameProcess);
            #endif
        }
    }
}
