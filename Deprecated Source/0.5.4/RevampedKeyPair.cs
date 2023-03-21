using System;

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
                return _privateKey;
            }
        }

        /// <summary>Clear private key and public key through cryptographically secure way.</summary>
        public void Clear()
        {
            SodiumSecureMemory.SecureClearBytes(_privateKey);
            SodiumSecureMemory.SecureClearBytes(_publicKey);
        }
    }
}
