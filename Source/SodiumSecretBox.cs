using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumSecretBox
    {
        private const ulong KEY_BYTES = 32;
        private const int INT_KEY_BYTES = 32;
        private const ulong NONCE_BYTES = 24;
        private const int INT_NONCE_BYTES = 24;
        private const ulong MAC_BYTES = 16;
        private const int INT_MAC_BYTES = 16;

        public static Byte[] GenerateSeededKey(Byte[] Seed)
        {
            Byte[] Key = new Byte[] { };

            Key=SodiumRNG.GetSeededRandomBytes(KEY_BYTES,Seed);

            return Key;
        }

        public static Byte[] GenerateKey() 
        {
            Byte[] Key = new Byte[INT_KEY_BYTES];

            SodiumSecretBoxLibrary.crypto_secretbox_keygen(Key);

            return Key;
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(INT_NONCE_BYTES);
        }

        public static Byte[] GenerateSeededNonce(Byte[] Seed) 
        {
            return SodiumRNG.GetSeededRandomBytes(NONCE_BYTES, Seed);
        }

        public static Byte[] Create(Byte[] message, Byte[] nonce, Byte[] key) 
        {
            if (key == null || key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (nonce == null || nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            var buffer = new Byte[INT_MAC_BYTES + message.Length];
            var ret = SodiumSecretBoxLibrary.crypto_secretbox_easy(buffer, message, message.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return buffer;
        }

        /// <summary>Opens a Secret Box</summary>
        /// <param name="cipherText">The cipherText.</param>
        /// <param name="nonce">The 24 byte nonce.</param>
        /// <param name="key">The 32 byte key.</param>
        /// <returns>The decrypted text.</returns>
        /// <exception cref="CryptographicException"></exception>
        public static Byte[] Open(Byte[] cipherText, Byte[] nonce, Byte[] key)
        {
            //validate the length of the key
            if (key == null || key.Length != INT_KEY_BYTES)
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");

            //validate the length of the nonce
            if (nonce == null || nonce.Length != INT_NONCE_BYTES)
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (cipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < INT_MAC_BYTES - 1; i++)
                {
                    if (cipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new Byte[cipherText.Length - INT_MAC_BYTES];
                    Array.Copy(cipherText, INT_MAC_BYTES, temp, 0, cipherText.Length - INT_MAC_BYTES);

                    cipherText = temp;
                }
            }

            var buffer = new Byte[cipherText.Length - INT_MAC_BYTES];
            var ret = SodiumSecretBoxLibrary.crypto_secretbox_open_easy(buffer, cipherText, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return buffer;
        }

        public static DetachedBox CreateDetached(string message, Byte[] nonce, Byte[] key)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(message), nonce, key);
        }

        public static DetachedBox CreateDetached(Byte[] message, Byte[] nonce, Byte[] key)
        {
            if (key == null || key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (nonce == null || nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            var cipher = new Byte[message.Length];
            var mac = new Byte[MAC_BYTES];
            var ret = SodiumSecretBoxLibrary.crypto_secretbox_detached(cipher, mac, message, message.Length, nonce, key);
            if (ret != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(cipher, mac);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] nonce, Byte[] key)
        {
            return OpenDetached(detached.CipherText, detached.Mac, nonce, key);
        }

        public static Byte[] OpenDetached(Byte[] cipherText, Byte[] mac, Byte[] nonce, Byte[] key)
        {
            if (key == null || key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (nonce == null || nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            if (mac == null || mac.Length != INT_MAC_BYTES)
            {
                throw new ArgumentException("Error: MAC must be " + INT_MAC_BYTES + " bytes in length.");
            }

            var buffer = new Byte[cipherText.Length];
            var ret = SodiumSecretBoxLibrary.crypto_secretbox_open_detached(buffer, cipherText, mac, cipherText.Length, nonce, key);

            if (ret != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return buffer;
        }
    }
}
