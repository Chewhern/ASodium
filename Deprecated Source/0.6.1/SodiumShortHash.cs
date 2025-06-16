using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumShortHash
    {
        public static int GetComputedHashLength() 
        {
            return SodiumShortHashLibrary.crypto_shorthash_bytes();
        }

        public static int GetKeyLength()
        {
            return SodiumShortHashLibrary.crypto_shorthash_keybytes();
        }

        public static int GetSipHash_2_4ComputedHashLength()
        {
            return SodiumShortHashLibrary.crypto_shorthash_siphashx24_bytes();
        }

        public static Byte[] GenerateKey() 
        {
            Byte[] Key = new Byte[GetKeyLength()];

            SodiumShortHashLibrary.crypto_shorthash_keygen(Key);

            return Key;
        }

        public static IntPtr GenerateKeyIntPtr()
        {
            Byte[] Key = new Byte[GetKeyLength()];

            SodiumShortHashLibrary.crypto_shorthash_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyLength());
            if (IsZero == false) 
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                SodiumSecureMemory.SecureClearBytes(Key);
                return KeyIntPtr;
            }
            else 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                return IntPtr.Zero;
            }
        }

        public static Byte[] ComputeHash(Byte[] Message, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message should not be null");
            }
            if (Key == null) 
            {
                throw new ArgumentException("Error: Key should not be null");
            }
            else 
            {
                if (Key.Length != GetKeyLength()) 
                {
                    throw new ArgumentException("Error: Key should be " + GetKeyLength() + " bytes in length");
                }
            }

            Byte[] ComputedHash = new Byte[GetComputedHashLength()];

            int result = SodiumShortHashLibrary.crypto_shorthash(ComputedHash, Message, Message.LongLength, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to compute hash");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return ComputedHash;
        }

        public static Byte[] SipHash_2_4ComputeHash(Byte[] Message, Byte[] Key,Boolean ClearKey=false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message should not be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key should not be null");
            }
            else
            {
                if (Key.Length != GetKeyLength())
                {
                    throw new ArgumentException("Error: Key should be " + GetKeyLength() + " bytes in length");
                }
            }

            Byte[] ComputedHash = new Byte[GetSipHash_2_4ComputedHashLength()];

            int result = SodiumShortHashLibrary.crypto_shorthash_siphashx24(ComputedHash, Message, Message.LongLength, Key);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to compute hash");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return ComputedHash;
        }
    }
}
