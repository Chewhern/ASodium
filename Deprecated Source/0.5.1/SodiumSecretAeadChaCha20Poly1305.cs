using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretAeadChaCha20Poly1305
    {

        public static int GetKeyLength() 
        {
            return SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_keybytes();
        }

        public static int GetNoncePublicLength() 
        {
            return SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_npubbytes();
        }

        public static int GetNonceSecurityLength() 
        {
            return SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_nsecbytes();
        }

        public static int GetABytesLength()
        {
            return SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_abytes();
        }

        public static long GetMessageMaxLength() 
        {
            return SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_messagebytes_max();
        }

        public static Byte[] GeneratePublicNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNoncePublicLength());
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_keygen(Key);
            return Key;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity=null) 
        {
            Byte[] CipherText = new Byte[Message.LongLength+GetABytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (AdditionalData != null && AdditionalData.Length!=0) 
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (result !=0) 
            {
                throw new CryptographicException("Error encrypting message.");
            }

            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText,Byte[] NoncePublic,Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null) 
        {
            Byte[] MessageByte = new Byte[CipherText.LongLength - GetABytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }            

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt(MessageByte, MessageLength,NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1) 
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            return MessageByte;
        }

        public static ChaCha20Poly1305DetachedBox CreateDetachedBox(Byte[] Message,Byte[] NoncePublic,Byte[] Key,Byte[] NonceSec=null,Byte[] AdditionalData=null) 
        {
            ChaCha20Poly1305DetachedBox MyDetachedBox = new ChaCha20Poly1305DetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[GetABytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");

            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSec, NoncePublic, Key);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MACLength = MAC.LongLength;

            MyDetachedBox.CipherText = CipherText;
            MyDetachedBox.MAC = MAC;
            MyDetachedBox.MACLength = MACLength;

            return MyDetachedBox;
        }

        public static Byte[] OpenDetachedBox(ChaCha20Poly1305DetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText,MyDetachedBox.MAC,NoncePublic,Key,AdditionalData,NonceSecurity);
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText,Byte[] MAC , Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null) 
        {
            Byte[] Message = new Byte[CipherText.LongLength];
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;

            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");

            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            return Message;
        }
    }
}
