using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumHMACSHA512256
    {

        public static int GetKeyBytesLength()
        {
            return SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_keybytes();
        }

        public static int GetComputedMACLength()
        {
            return SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_bytes();
        }

        public static Byte[] GenerateKey()
        {
            Byte[] Key = new Byte[GetKeyBytesLength()];

            SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_keygen(Key);

            return Key;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength());

            int TryAttempts = 5;
            int Count = 0;

            while (IsZero == true && Count < TryAttempts)
            {
                KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength());
                Count += 1;
            }

            if (IsZero == false && Count < TryAttempts)
            {
                SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_keygen(KeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
            }
            else
            {
                KeyIntPtr = IntPtr.Zero;
            }
            return KeyIntPtr;
        }

        public static Byte[] ComputeMAC(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key length must exactly be " + GetKeyBytesLength() + " bytes");
                }
            }
            Byte[] ComputedMAC = new Byte[GetComputedMACLength()];
            int result = SodiumHMACSHA512256Library.crypto_auth_hmacsha512256(ComputedMAC, Message, Message.LongLength, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to compute MAC using HMACSHA256");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return ComputedMAC;
        }

        public static Byte[] ComputeMAC(Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            Byte[] ComputedMAC = new Byte[GetComputedMACLength()];
            int result = SodiumHMACSHA512256Library.crypto_auth_hmacsha512256(ComputedMAC, Message, Message.LongLength, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            if (result != 0)
            {
                throw new CryptographicException("Failed to compute MAC using HMACSHA256");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return ComputedMAC;
        }

        public static Boolean VerifyMAC(Byte[] MAC, Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key length must exactly be " + GetKeyBytesLength() + " bytes");
                }
            }
            if (MAC == null)
            {
                throw new ArgumentException("Error: MAC must not be null");
            }
            else
            {
                if (MAC.Length != GetComputedMACLength())
                {
                    throw new ArgumentException("Error: MAC length must exactly be " + GetComputedMACLength() + " bytes");
                }
            }
            int result = SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_verify(MAC, Message, Message.LongLength, Key);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result != 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static Boolean VerifyMAC(Byte[] MAC, Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            if (MAC == null)
            {
                throw new ArgumentException("Error: MAC must not be null");
            }
            else
            {
                if (MAC.Length != GetComputedMACLength())
                {
                    throw new ArgumentException("Error: MAC length must exactly be " + GetComputedMACLength() + " bytes");
                }
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_verify(MAC, Message, Message.LongLength, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);
            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            if (result != 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
