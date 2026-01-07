using System;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumSecretKeyAuth
    {

        public static int GetMACLength()
        {
            return SodiumSecretKeyAuthLibrary.crypto_auth_bytes();
        }

        public static int GetKeyLength() 
        {
            return SodiumSecretKeyAuthLibrary.crypto_auth_keybytes();
        }

        public static Byte[] GenKey() 
        {
            Byte[] Key = new Byte[GetKeyLength()];
            
            SodiumSecretKeyAuthLibrary.crypto_auth_keygen(Key);

            return Key;
        }

        public static IntPtr GenKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr Key = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyLength());

            if (IsZero == false) 
            {
                SodiumSecretKeyAuthLibrary.crypto_auth_keygen(Key);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            }
            else 
            {
                Key = IntPtr.Zero;
            }

            return Key;
        }

        public static Byte[] Sign(Byte[] message, Byte[] Key,Boolean ClearKey=false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be "+Key.Length+" in length");

            Byte[] MAC = new Byte[GetMACLength()];
            SodiumSecretKeyAuthLibrary.crypto_auth(MAC, message, message.Length, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return MAC;
        }

        public static Byte[] Sign(Byte[] message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");

            Byte[] MAC = new Byte[GetMACLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumSecretKeyAuthLibrary.crypto_auth(MAC, message, message.Length, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return MAC;
        }

        public static void Verify(Byte[] Message, Byte[] MAC, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            if (ret == -1)
            {
                throw new CryptographicException("Error: MAC does not match with Message...");
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
        }

        public static void Verify(Byte[] Message, Byte[] MAC, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ret == -1)
            {
                throw new CryptographicException("Error: MAC does not match with Message...");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }
        }

        public static Boolean VerifyMAC(Byte[] Message, Byte[] MAC, Byte[] Key, Boolean ClearKey = false)
        {
            if (Key == null || Key.Length != GetKeyLength())
                throw new ArgumentException("Error: Key must be " + Key.Length + " in length");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return ret == -1;
        }

        public static Boolean VerifyMAC(Byte[] Message, Byte[] MAC, IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
                throw new ArgumentException("Error: Key must not be null/empty");

            if (MAC == null || MAC.Length != GetMACLength())
                throw new ArgumentException("Error: MAC must be " + MAC.Length + " in length");

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            var ret = SodiumSecretKeyAuthLibrary.crypto_auth_verify(MAC, Message, Message.Length, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return ret == -1;
        }
    }
}
