using System;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumSecretBoxXChaCha20Poly1305
    {

        public static int GetKeyBytesLength() 
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_keybytes();
        }

        public static int GetNonceBytesLength()
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_noncebytes();
        }

        public static int GetMACBytesLength() 
        {
            return SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_macbytes();
        }

        public static Byte[] GenerateKey()
        {
            return SodiumSecretBox.GenerateKey();
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            return SodiumSecretBox.GenerateKeyIntPtr();
        }

        public static Byte[] GenerateNonce()
        {
            return SodiumRNG.GetRandomBytes(GetNonceBytesLength());
        }

        public static Byte[] Create(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[GetMACBytesLength() + Message.Length];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_easy(CipherText, Message, Message.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to create SecretBox");

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
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[GetMACBytesLength() + Message.Length];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_easy(CipherText, Message, Message.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
                throw new CryptographicException("Failed to create SecretBox");

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }
            return CipherText;
        }

        public static Byte[] Open(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open SecretBox");
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

            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");

            Byte[] Message = new Byte[CipherText.Length - GetMACBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_easy(Message, CipherText, CipherText.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
                throw new CryptographicException("Failed to open SecretBox");
            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key,ClearKey);
        }

        public static DetachedBox CreateDetached(String Message, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return CreateDetached(Encoding.UTF8.GetBytes(Message), Nonce, Key, ClearKey);
        }

        public static DetachedBox CreateDetached(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[Message.Length];
            Byte[] MAC = new Byte[GetMACBytesLength()];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_detached(CipherText, MAC, Message, Message.Length, Nonce, Key);
            if (result != 0)
                throw new CryptographicException("Failed to create detached SecretBox");
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
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            Byte[] CipherText = new Byte[Message.Length];
            Byte[] MAC = new Byte[GetMACBytesLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_detached(CipherText, MAC, Message, Message.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
                throw new CryptographicException("Failed to create detached SecretBox");

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return new DetachedBox(CipherText, MAC);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key,ClearKey);
        }

        public static Byte[] OpenDetached(DetachedBox detached, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            return OpenDetached(detached.CipherText, detached.Mac, Nonce, Key, ClearKey);
        }

        public static Byte[] OpenDetached(Byte[] CipherText, Byte[] MAC, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false)
        {
            if (Key == null || Key.Length != GetKeyBytesLength())
            {
                throw new ArgumentException("Error: Key must be " + GetKeyBytesLength() + " bytes in length.");
            }
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            if (MAC == null || MAC.Length != GetMACBytesLength())
            {
                throw new ArgumentException("Error: MAC must be " + GetMACBytesLength() + " bytes in length.");
            }

            Byte[] Message = new Byte[CipherText.Length];
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, Key);

            if (result != 0)
                throw new CryptographicException("Failed to open detached SecretBox");
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
            if (Nonce == null || Nonce.Length != GetNonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be " + GetNonceBytesLength() + " bytes in length.");
            }
            if (MAC == null || MAC.Length != GetMACBytesLength())
            {
                throw new ArgumentException("Error: MAC must be " + GetMACBytesLength() + " bytes in length.");
            }

            Byte[] Message = new Byte[CipherText.Length];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumSecretBoxXChaCha20Poly1305Library.crypto_secretbox_xchacha20poly1305_open_detached(Message, CipherText, MAC, CipherText.Length, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
                throw new CryptographicException("Failed to open detached SecretBox");
            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Message;
        }
    }
}
