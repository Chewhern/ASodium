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

        public static Byte[] GenerateSecurityNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceSecurityLength());
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_keygen(Key);
            return Key;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyLength());
            if (IsZero == false)
            {
                SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else
            {
                Key = IntPtr.Zero;
            }
            return Key;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity=null,Boolean ClearKey=false) 
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
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security must exactly be " + GetNonceSecurityLength().ToString() + " bytes in length");
                }
            }
            if (AdditionalData != null && AdditionalData.Length!=0) 
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (result !=0) 
            {
                throw new CryptographicException("Error encrypting message.");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, IntPtr Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] CipherText = new Byte[Message.LongLength + GetABytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
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

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText,Byte[] NoncePublic,Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false) 
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

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt(MessageByte, MessageLength,NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1) 
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return MessageByte;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, IntPtr Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] MessageByte = new Byte[CipherText.LongLength - GetABytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
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

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return MessageByte;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message,Byte[] NoncePublic,Byte[] Key,Byte[] NonceSecurity=null,Byte[] AdditionalData=null,Boolean ClearKey=false) 
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

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return MyDetachedBox;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, IntPtr Key, Byte[] NonceSecurity = null, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            DetachedBox MyDetachedBox = new DetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[GetABytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
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

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_encrypt_detached(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, Key);
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
            }

            return MyDetachedBox;
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText,MyDetachedBox.Mac,NoncePublic,Key,AdditionalData,NonceSecurity,ClearKey);
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, IntPtr Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.Mac, NoncePublic, Key, AdditionalData, NonceSecurity, ClearKey);
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText,Byte[] MAC , Byte[] NoncePublic, Byte[] Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false) 
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

            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText, Byte[] MAC, Byte[] NoncePublic, IntPtr Key, Byte[] AdditionalData = null, Byte[] NonceSecurity = null, Boolean ClearKey = false)
        {
            Byte[] Message = new Byte[CipherText.LongLength];
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;

            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");
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

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretAeadChaCha20Poly1305Library.crypto_aead_chacha20poly1305_decrypt_detached(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }
    }
}
