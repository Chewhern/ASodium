using System;
using System.Text;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretBox
    {
        private const int INT_KEY_BYTES = 32;
        private const int INT_NONCE_BYTES = 24;
        private const long MAC_BYTES = 16;
        private const int INT_MAC_BYTES = 16;

        public static Byte[] GenerateKey() 
        {
            Byte[] Key = new Byte[INT_KEY_BYTES];

            SodiumSecretBoxLibrary.crypto_secretbox_keygen(Key);

            return Key;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, INT_KEY_BYTES);
            if (IsZero == false) 
            {
                SodiumSecretBoxLibrary.crypto_secretbox_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else 
            {
                Key = IntPtr.Zero;
            }

            return Key;
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(INT_NONCE_BYTES);
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false) 
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
            {
                throw new CryptographicException("Failed to create SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return CipherText;
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }
            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            Byte[] CipherText = new Byte[INT_MAC_BYTES + Message.Length];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxLibrary.crypto_secretbox_easy(CipherText, Message, Message.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to create SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != INT_KEY_BYTES)
                throw new ArgumentException("Error: Key must be " + INT_KEY_BYTES + " bytes in length.");

            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");

            Byte[] Message = new Byte[CipherText.Length - INT_MAC_BYTES];
            int result = SodiumSecretBoxLibrary.crypto_secretbox_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to open SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");

            Byte[] Message = new Byte[CipherText.Length - INT_MAC_BYTES];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxLibrary.crypto_secretbox_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to open SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key,ClearKey);
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key, ClearKey);
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
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
            {
                throw new CryptographicException("Failed to create detached SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return new DetachedBox(CipherText, MAC);
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }
            if (Nonce == null || Nonce.Length != INT_NONCE_BYTES)
            {
                throw new ArgumentException("Error: Nonce must be " + INT_NONCE_BYTES + " bytes in length.");
            }
            Byte[] CipherText = new Byte[Message.Length];
            Byte[] MAC = new Byte[MAC_BYTES];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxLibrary.crypto_secretbox_detached(CipherText, MAC, Message, Message.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to create detached SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return new DetachedBox(CipherText, MAC);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key,ClearKey);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key, ClearKey);
        }

        public static Byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
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
            {
                throw new CryptographicException("Failed to open detached SecretBox");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Message;
        }

        public static Byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
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

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxLibrary.crypto_secretbox_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to open detached SecretBox");
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
