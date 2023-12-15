using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretAeadAES256GCMPC
    {

        public static int GetStateBytesLength() 
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_statebytes();
        }

        public static Byte[] InitializeState(Byte[] Key,Boolean ClearKey=false) 
        {
            if (Key == null || Key.Length != SodiumSecretAeadAES256GCM.GetKeyLength())
                throw new ArgumentException("Error: Key must be " + SodiumSecretAeadAES256GCM.GetKeyLength() + " bytes in length");
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_beforenm(StateBytes, Key);

            if (result != 0) 
            {
                throw new SystemException("Error: Failed to initialized state for AES256 GCM");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return StateBytes;
        }

        public static IntPtr InitializeState(Byte[] Key,ref Boolean IsZero)
        {
            if (Key == null || Key.Length != SodiumSecretAeadAES256GCM.GetKeyLength())
                throw new ArgumentException("Error: Key must be " + SodiumSecretAeadAES256GCM.GetKeyLength() + " bytes in length");
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_beforenm(StateBytes, Key);

            if (result != 0)
            {
                throw new SystemException("Error: Failed to initialized state for AES256 GCM");
            }
            Boolean LocalIsZero = true;
            SodiumSecureMemory.SecureClearBytes(Key);
            IntPtr StateIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref LocalIsZero, GetStateBytesLength());
            if (LocalIsZero == false) 
            {
                Marshal.Copy(StateBytes, 0, StateIntPtr, GetStateBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(StateIntPtr);
                IsZero = LocalIsZero;
                SodiumSecureMemory.SecureClearBytes(StateBytes);
                return StateIntPtr;
            }
            else 
            {
                IsZero = LocalIsZero;
                return IntPtr.Zero;
            }
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (SodiumSecretAeadAES256GCM.IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] CipherText = new Byte[Message.LongLength + SodiumSecretAeadAES256GCM.GetABytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != SodiumSecretAeadAES256GCM.GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + SodiumSecretAeadAES256GCM.GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > SodiumSecretAeadAES256GCM.GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + SodiumSecretAeadAES256GCM.GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null) 
            {
                if (NonceSecurity.Length != SodiumSecretAeadAES256GCM.GetNonceSecurityLength()) 
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + SodiumSecretAeadAES256GCM.GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_encrypt_afternm(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, StateBytes);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(StateBytes);
            }

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }
            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (SodiumSecretAeadAES256GCM.IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] MessageByte = new Byte[CipherText.LongLength - SodiumSecretAeadAES256GCM.GetABytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != SodiumSecretAeadAES256GCM.GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + SodiumSecretAeadAES256GCM.GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > SodiumSecretAeadAES256GCM.GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + SodiumSecretAeadAES256GCM.GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != SodiumSecretAeadAES256GCM.GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + SodiumSecretAeadAES256GCM.GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_decrypt_afternm(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, StateBytes);


            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(StateBytes);
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            return MessageByte;
        }

        public static DetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, Byte[] StateBytes, Byte[] NonceSecurity = null, Byte[] AdditionalData = null,Boolean ClearKey=false)
        {
            if (SodiumSecretAeadAES256GCM.IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            DetachedBox MyDetachedBox = new DetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[SodiumSecretAeadAES256GCM.GetABytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != SodiumSecretAeadAES256GCM.GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + SodiumSecretAeadAES256GCM.GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > SodiumSecretAeadAES256GCM.GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + SodiumSecretAeadAES256GCM.GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != SodiumSecretAeadAES256GCM.GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + SodiumSecretAeadAES256GCM.GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_encrypt_detached_afternm(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, StateBytes);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(StateBytes);
            }

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to create detached box");
            }

            MyDetachedBox = new DetachedBox(CipherText, MAC);

            return MyDetachedBox;
        }

        public static Byte[] OpenDetachedBox(DetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (SodiumSecretAeadAES256GCM.IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.Mac, NoncePublic, StateBytes, AdditionalData, NonceSecurity,ClearKey);
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText, Byte[] MAC, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (SodiumSecretAeadAES256GCM.IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] Message = new Byte[CipherText.LongLength];
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;

            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != SodiumSecretAeadAES256GCM.GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + SodiumSecretAeadAES256GCM.GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > SodiumSecretAeadAES256GCM.GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + SodiumSecretAeadAES256GCM.GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != SodiumSecretAeadAES256GCM.GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + SodiumSecretAeadAES256GCM.GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_decrypt_detached_afternm(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, StateBytes);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(StateBytes);
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Failed to open detached box");
            }

            return Message;
        }
    }
}
