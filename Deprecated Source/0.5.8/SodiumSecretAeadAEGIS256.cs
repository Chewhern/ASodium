using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace ASodium
{
    public static class SodiumSecretAeadAEGIS256
    {
        public static int GetKeyLength()
        {
            return SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_keybytes();
        }

        public static int GetNoncePublicLength()
        {
            return SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_npubbytes();
        }

        public static int GetNonceSecurityLength()
        {
            return SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_nsecbytes();
        }

        public static int GetABytesLength()
        {
            return SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_abytes();
        }

        public static long GetMessageMaxLength()
        {
            return SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_messagebytes_max();
        }

        public static Byte[] GeneratePublicNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNoncePublicLength());
        }

        public static Byte[] GenerateSecurityNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceSecurityLength());
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_keygen(Key);
            return Key;
        }

        public static IntPtr GenerateKey(ref Boolean IsZero)
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_keygen(Key);
            Boolean LocalIsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref LocalIsZero, GetKeyLength());
            if (LocalIsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(KeyIntPtr);
                SodiumSecureMemory.SecureClearBytes(Key);
                return KeyIntPtr;
            }
            else
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                IsZero = LocalIsZero;
                return IntPtr.Zero;
            }
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] CipherText = new Byte[Message.LongLength + GetABytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security must exactly be " + GetNonceSecurityLength().ToString() + " bytes in length");
                }
            }

            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            int result = SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }
            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
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
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security must exactly be " + GetNonceSecurityLength().ToString() + " bytes in length");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_decrypt(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            return MessageByte;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] NonceSecurity = null, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();
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
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security must exactly be " + GetNonceSecurityLength().ToString() + " bytes in length");
                }
            }

            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            return MyDetachedBox;
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.Mac, NoncePublic, Key, AdditionalData, NonceSecurity, ClearKey);
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText, Byte[] MAC, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
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
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security must exactly be " + GetNonceSecurityLength().ToString() + " bytes in length");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAEGIS256Library.crypto_aead_aegis256_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Failed to open detached box");
            }

            return Message;
        }
    }
}
