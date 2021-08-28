﻿using System;
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
            Byte[] Key = new Byte[GetKeyBytesLength()];

            SodiumHMACSHA512256Library.crypto_auth_hmacsha512256_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetKeyBytesLength());

            GCHandle MyGeneralGCHandle = new GCHandle();

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetKeyBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.LongLength);
                MyGeneralGCHandle.Free();
                return KeyIntPtr;
            }
            else
            {
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.LongLength);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
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
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.LongLength);
                MyGeneralGCHandle.Free();
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
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.LongLength);
                MyGeneralGCHandle.Free();
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
