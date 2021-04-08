using System;
using System.Text;
using System.Security.Cryptography;

namespace ASodium
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

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] Key) 
        {
            if (Key == null || Key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            Byte[] CipherText = new Byte[INT_MAC_BYTES + Message.Length];
            int result = SodiumSecretBoxLibrary.crypto_secretbox_easy(CipherText, Message, Message.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to create SecretBox");

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != INT_KEY_BYTES)
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");

            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");

            //check to see if there are MAC_BYTES of leading nulls, if so, trim.
            //this is required due to an error in older versions.
            if (CipherText[0] == 0)
            {
                //check to see if trim is needed
                var trim = true;
                for (var i = 0; i < INT_MAC_BYTES - 1; i++)
                {
                    if (CipherText[i] != 0)
                    {
                        trim = false;
                        break;
                    }
                }

                //if the leading MAC_BYTES are null, trim it off before going on.
                if (trim)
                {
                    var temp = new Byte[CipherText.Length - INT_MAC_BYTES];
                    Array.Copy(CipherText, INT_MAC_BYTES, temp, 0, CipherText.Length - INT_MAC_BYTES);

                    CipherText = temp;
                }
            }

            Byte[] Message = new Byte[CipherText.Length - INT_MAC_BYTES];
            int result = SodiumSecretBoxLibrary.crypto_secretbox_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open SecretBox");

            return Message;
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, Byte[] Key)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key);
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            Byte[] CipherText = new Byte[Message.Length];
            Byte[] MAC = new Byte[MAC_BYTES];
            int result = SodiumSecretBoxLibrary.crypto_secretbox_detached(CipherText, MAC, Message, Message.Length, Nonce, Key);
            if (result != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            return new DetachedBox(CipherText, MAC);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, Byte[] Key)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key);
        }

        public static Byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] Key)
        {
            if (Key == null || Key.Length != INT_KEY_BYTES)
            {
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            if (MAC == null || MAC.Length != INT_MAC_BYTES)
            {
                throw new ArgumentException("Error: MAC must be " + INT_MAC_BYTES + " bytes in length.");
            }

            Byte[] Message = new Byte[CipherText.Length];
            int result = SodiumSecretBoxLibrary.crypto_secretbox_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open detached SecretBox");

            return Message;
        }
    }
}
