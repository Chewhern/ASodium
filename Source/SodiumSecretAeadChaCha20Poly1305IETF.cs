using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretAeadChaCha20Poly1305IETF
    {
        public static int GetKeyLength()
        {
            return SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_keybytes();
        }

        public static int GetNoncePublicLength()
        {
            return SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_npubbytes();
        }

        public static int GetNonceSecurityLength()
        {
            return SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_nsecbytes();
        }

        public static int GetMACBytesLength()
        {
            return SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_abytes();
        }

        public static long GetMessageMaxLength()
        {
            return SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_messagebytes_max();
        }

        public static Byte[] GeneratePublicNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNoncePublicLength());
        }

        public static Byte[] GenerateSecurityNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceSecurityLength());
        }

        public static IntPtr GenerateSecurityNonceIntPtr()
        {
            IntPtr MySecurityNonce = SodiumRNG.GetRandomBytesIntPtr(GetNonceSecurityLength());
            if (MySecurityNonce != IntPtr.Zero)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(MySecurityNonce);
            }
            return MySecurityNonce;
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_keygen(Key);
            return Key;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyLength());
            if (IsZero == false) 
            {
                SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else 
            {
                Key = IntPtr.Zero;
            }
            return Key;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] CipherText = new Byte[Message.LongLength + GetMACBytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
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
            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(NonceSecurity);
            }

            return CipherText;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, IntPtr NonceSecurity, IntPtr Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            Byte[] CipherText = new Byte[Message.LongLength + GetMACBytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NonceSecurity);
            }
            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);
            if (NonceSecurity != IntPtr.Zero)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(NonceSecurity);
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(NonceSecurity);
                SodiumGuardedHeapAllocation.Sodium_Free(NonceSecurity);
            }

            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] MessageByte = new Byte[CipherText.LongLength - GetMACBytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
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

            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_decrypt(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(NonceSecurity);
            }

            return MessageByte;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, IntPtr NonceSecurity,IntPtr Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            Byte[] MessageByte = new Byte[CipherText.LongLength - GetMACBytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NonceSecurity);
            }
            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_decrypt(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(NonceSecurity);
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(NonceSecurity);
                SodiumGuardedHeapAllocation.Sodium_Free(NonceSecurity);
            }

            return MessageByte;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] NonceSecurity = null, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[GetMACBytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
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

            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(NonceSecurity);
            }

            return MyDetachedBox;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, IntPtr NonceSecurity,IntPtr Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[GetMACBytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NonceSecurity);
            }
            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(NonceSecurity);
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(NonceSecurity);
                SodiumGuardedHeapAllocation.Sodium_Free(NonceSecurity);
            }

            return MyDetachedBox;
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.Mac, NoncePublic, Key, AdditionalData, NonceSecurity, ClearKey);
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, IntPtr NonceSecurity,IntPtr Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.Mac, NoncePublic, NonceSecurity,Key, AdditionalData, ClearKey);
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

            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(NonceSecurity);
            }

            return Message;
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText, Byte[] MAC, Byte[] NoncePublic, IntPtr NonceSecurity,IntPtr Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            Byte[] Message = new Byte[CipherText.LongLength];
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;

            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            if (NonceSecurity != IntPtr.Zero) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NonceSecurity);
            }
            int result = SodiumSecretAeadChaCha20Poly1305IETFLibrary.crypto_aead_chacha20poly1305_ietf_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);
            if (NonceSecurity != IntPtr.Zero)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(NonceSecurity);
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(NonceSecurity);
                SodiumGuardedHeapAllocation.Sodium_Free(NonceSecurity);
            }

            return Message;
        }
    }
}
