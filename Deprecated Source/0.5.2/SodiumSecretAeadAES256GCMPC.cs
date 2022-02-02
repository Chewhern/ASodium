using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretAeadAES256GCMPC
    {
        public static Boolean IsAES256GCMAvailable()
        {
            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_is_available();

            if (result == 1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static int GetKeyLength()
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_keybytes();
        }

        public static int GetNoncePublicLength()
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_npubbytes();
        }

        public static int GetNonceSecurityLength()
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_nsecbytes();
        }

        public static int GetABytesLength()
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_abytes();
        }

        public static long GetMessageMaxLength()
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_messagebytes_max();
        }

        public static int GetStateBytesLength() 
        {
            return SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_statebytes();
        }

        public static Byte[] GeneratePublicNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNoncePublicLength());
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_keygen(Key);
            return Key;
        }

        public static IntPtr GenerateKey(ref Boolean IsZero)
        {
            Byte[] Key = new Byte[GetKeyLength()];
            SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_keygen(Key);
            Boolean LocalIsZero = true;
            GCHandle MyGeneralGCHandle = new GCHandle();
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref LocalIsZero, GetKeyLength());
            if (LocalIsZero == false) 
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(KeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                return KeyIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                IsZero = LocalIsZero;
                return IntPtr.Zero;
            }
        }

        public static Byte[] InitializeState(Byte[] Key,Boolean ClearKey=false) 
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_beforenm(StateBytes, Key);

            if (result != 0) 
            {
                throw new SystemException("Error: Failed to initialized state for AES256 GCM");
            }
            GCHandle MyGeneralGCHandle;

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
            }

            return StateBytes;
        }

        public static IntPtr InitializeState(Byte[] Key,ref Boolean IsZero)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + GetKeyLength() + " bytes in length");
            Byte[] StateBytes = new Byte[GetStateBytesLength()];

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_beforenm(StateBytes, Key);

            if (result != 0)
            {
                throw new SystemException("Error: Failed to initialized state for AES256 GCM");
            }
            Boolean LocalIsZero = true;
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();
            IntPtr StateIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref LocalIsZero, GetStateBytesLength());
            if (LocalIsZero == false) 
            {
                Marshal.Copy(StateBytes, 0, StateIntPtr, GetStateBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(StateIntPtr);
                IsZero = LocalIsZero;
                MyGeneralGCHandle = GCHandle.Alloc(StateBytes, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), StateBytes.Length);
                MyGeneralGCHandle.Free();
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
            if (IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] CipherText = new Byte[Message.LongLength + GetABytesLength()];
            long CipherTextLength = 0;
            long MessageLength = Message.LongLength;
            long AdditionalDataLength = 0;
            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null) 
            {
                if (NonceSecurity.Length != GetNonceSecurityLength()) 
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_encrypt_afternm(CipherText, CipherTextLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, StateBytes);

            GCHandle MyGeneralGCHandle;

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(StateBytes, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), StateBytes.Length);
                MyGeneralGCHandle.Free();
            }

            if (result != 0)
            {
                throw new CryptographicException("Error encrypting message.");
            }
            return CipherText;
        }

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] MessageByte = new Byte[CipherText.LongLength - GetABytesLength()];
            long MessageLength = 0;
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_decrypt_afternm(MessageByte, MessageLength, NonceSecurity, CipherText, CipherTextLength, AdditionalData, AdditionalDataLength, NoncePublic, StateBytes);

            GCHandle MyGeneralGCHandle;

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(StateBytes, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), StateBytes.Length);
                MyGeneralGCHandle.Free();
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Verification of MAC stored in cipher text failed");
            }

            return MessageByte;
        }

        public static AES256GCMDetachedBox CreateDetachedBox(Byte[] Message, Byte[] NoncePublic, Byte[] StateBytes, Byte[] NonceSecurity = null, Byte[] AdditionalData = null,Boolean ClearKey=false)
        {
            if (IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            AES256GCMDetachedBox MyDetachedBox = new AES256GCMDetachedBox();
            Byte[] CipherText = new Byte[Message.LongLength];
            Byte[] MAC = new Byte[GetABytesLength()];
            long MACLength = 0;
            long AdditionalDataLength = 0;
            long MessageLength = Message.LongLength;

            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_encrypt_detached_afternm(CipherText, MAC, MACLength, Message, MessageLength, AdditionalData, AdditionalDataLength, NonceSecurity, NoncePublic, StateBytes);

            GCHandle MyGeneralGCHandle;
            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(StateBytes, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), StateBytes.Length);
                MyGeneralGCHandle.Free();
            }

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

        public static Byte[] OpenDetachedBox(AES256GCMDetachedBox MyDetachedBox, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            return OpenDetachedBox(MyDetachedBox.CipherText, MyDetachedBox.MAC, NoncePublic, StateBytes, AdditionalData, NonceSecurity,ClearKey);
        }

        public static Byte[] OpenDetachedBox(Byte[] CipherText, Byte[] MAC, Byte[] NoncePublic, Byte[] StateBytes, Byte[] AdditionalData = null, Byte[] NonceSecurity = null,Boolean ClearKey=false)
        {
            if (IsAES256GCMAvailable() == false)
            {
                throw new SystemException("Error: Accelerated AES256GCM is not supported in this machine..");
            }

            Byte[] Message = new Byte[CipherText.LongLength];
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;

            if (StateBytes == null || StateBytes.Length != GetStateBytesLength())
                throw new ArgumentException("Error: StateBytes must be " + GetStateBytesLength() + " bytes in length");
            if (NoncePublic == null || NoncePublic.Length != GetNoncePublicLength())
                throw new ArgumentException("Error: Public nonce must be " + GetNoncePublicLength() + " bytes in length");
            if (AdditionalData != null && (AdditionalData.Length > GetABytesLength() || AdditionalData.Length < 0))
                throw new ArgumentException("Error: Additional data must be between 0 and " + GetABytesLength() + " in bytes in length");
            if (NonceSecurity != null)
            {
                if (NonceSecurity.Length != GetNonceSecurityLength())
                {
                    throw new ArgumentException("Error: Nonce Security length must exactly be " + GetNonceSecurityLength().ToString() + " bytes long");
                }
            }
            if (AdditionalData != null && AdditionalData.Length != 0)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }

            int result = SodiumSecretAeadAES256GCMLibrary.crypto_aead_aes256gcm_decrypt_detached_afternm(Message, NonceSecurity, CipherText, CipherTextLength, MAC, AdditionalData, AdditionalDataLength, NoncePublic, StateBytes);

            GCHandle MyGeneralGCHandle;

            if (ClearKey == true) 
            {
                MyGeneralGCHandle = GCHandle.Alloc(StateBytes, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), StateBytes.Length);
                MyGeneralGCHandle.Free();
            }

            if (result == -1)
            {
                throw new CryptographicException("Error: Failed to open detached box");
            }

            return Message;
        }
    }
}
