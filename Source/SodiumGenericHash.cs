using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumGenericHash
    {
        public static int GetStandardComputedHashLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_bytes();
        }

        public static int GetMinComputedHashLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_bytes_min();
        }

        public static int GetMaxComputedHashLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_bytes_max();
        }

        public static int GetStandardKeyLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_keybytes();
        }

        public static int GetMinKeyLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_keybytes_min();
        }

        public static int GetMaxKeyLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_keybytes_max();
        }

        public static int GetStateBytesLength() 
        {
            return SodiumGenericHashLibrary.crypto_generichash_statebytes();
        }

        public static Byte[] ComputeHash(Byte HashLength,Byte[] Message, Byte[] Key = null) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message cannot be null");
            }
            if (Key != null) 
            {
                if (Key.Length != GetStandardKeyLength()) 
                {
                    if((Key.Length>=GetMinKeyLength()&& Key.Length <= GetMaxKeyLength())==false) 
                    {
                        throw new ArgumentException("Error: Key must be in the range of " + GetMinKeyLength() + " bytes and " + GetMaxKeyLength() + " bytes in length");
                    }
                }
            }
            if (HashLength!=0)
            {
                if (HashLength!= GetStandardComputedHashLength())
                {
                    if ((HashLength >=GetMinComputedHashLength() && HashLength <= GetMaxComputedHashLength()) == false)
                    {
                        throw new ArgumentException("Error: Hash length must be in the range of " + GetMinComputedHashLength() + " bytes and " + GetMaxComputedHashLength() + " bytes in length");
                    }
                }
            }
            else 
            {
                throw new ArgumentException("Error: Hash Length cannot be 0");
            }
            Byte[] ComputedHash = new Byte[HashLength];
            int KeyLength = 0;
            if (Key != null) 
            {
                KeyLength = Key.Length;
            }
            int result = SodiumGenericHashLibrary.crypto_generichash(ComputedHash, ComputedHash.Length, Message, Message.LongLength, Key, KeyLength);

            if (result!=0) 
            {
                throw new CryptographicException("Error: Failed to compute hash");
            }

            if (KeyLength != 0) 
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), KeyLength);
                MyGeneralGCHandle.Free();
            }

            return ComputedHash;
        }

        public static Byte[] GenerateStandardKey() 
        {
            Byte[] Key = new Byte[GetStandardKeyLength()];

            SodiumGenericHashLibrary.crypto_generichash_keygen(Key);

            return Key;
        }

        public static IntPtr GenerateStandardKeyIntPtr() 
        {
            Byte[] Key = new Byte[GetStandardKeyLength()];

            SodiumGenericHashLibrary.crypto_generichash_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,GetStandardKeyLength());

            if (IsZero == false) 
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetStandardKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            if (IsZero == false) 
            {
                return KeyIntPtr;
            }
            else 
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateMinKey()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetMinKeyLength());

            return Key;
        }

        public static IntPtr GenerateMinKeyIntPtr()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetMinKeyLength());

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStandardKeyLength());

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetStandardKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            if (IsZero == false)
            {
                return KeyIntPtr;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateMaxKey()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetMaxKeyLength());

            return Key;
        }

        public static IntPtr GenerateMaxKeyIntPtr()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetMaxKeyLength());

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStandardKeyLength());

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetStandardKeyLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            if (IsZero == false)
            {
                return KeyIntPtr;
            }
            else
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] InitializeState(Byte[] Key, Byte OutLength) 
        {
            Byte[] State = new Byte[GetStateBytesLength()];

            if (Key != null)
            {
                if (Key.Length != GetStandardKeyLength())
                {
                    if ((Key.Length >= GetMinKeyLength() && Key.Length <= GetMaxKeyLength()) == false)
                    {
                        throw new ArgumentException("Error: Key must be in the range of " + GetMinKeyLength() + " bytes and " + GetMaxKeyLength() + " bytes in length");
                    }
                }
            }
            if (OutLength != 0)
            {
                if (OutLength != GetStandardComputedHashLength())
                {
                    if ((OutLength >= GetMinComputedHashLength() && OutLength <= GetMaxComputedHashLength()) == false)
                    {
                        throw new ArgumentException("Error: Out length must be in the range of " + GetMinComputedHashLength() + " bytes and " + GetMaxComputedHashLength() + " bytes in length");
                    }
                }
            }
            else
            {
                throw new ArgumentException("Error: Out Length cannot be 0");
            }

            int KeyLength = 0;
            if (Key != null)
            {
                KeyLength = Key.Length;
            }

            int result = SodiumGenericHashLibrary.crypto_generichash_init(State, Key,KeyLength,OutLength);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to initialize state");
            }

            if (KeyLength != 0)
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), KeyLength);
                MyGeneralGCHandle.Free();
            }

            return State;
        }

        public static Byte[] UpdateState(Byte[] OldState,Byte[] Message) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            if (OldState == null) 
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else 
            {
                if (OldState.Length != GetStateBytesLength()) 
                {
                    throw new ArgumentException("Error: State must be " + GetStateBytesLength() + " bytes in length");
                }
            }

            Byte[] NewState = OldState;

            int result = SodiumGenericHashLibrary.crypto_generichash_update(NewState, Message, Message.LongLength);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to update state");
            }

            return NewState;
        }

        public static Byte[] ComputeHashForFinalizedState(Byte[] State,Byte HashLength) 
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State must be " + GetStateBytesLength() + " bytes in length");
                }
            }

            if (HashLength != 0)
            {
                if (HashLength != GetStandardComputedHashLength())
                {
                    if ((HashLength >= GetMinComputedHashLength() && HashLength <= GetMaxComputedHashLength()) == false)
                    {
                        throw new ArgumentException("Error: Hash length must be in the range of " + GetMinComputedHashLength() + " bytes and " + GetMaxComputedHashLength() + " bytes in length");
                    }
                }
            }
            else
            {
                throw new ArgumentException("Error: Hash Length cannot be 0");
            }

            Byte[] ComputedHash = new Byte[HashLength];

            int result = SodiumGenericHashLibrary.crypto_generichash_final(State, ComputedHash, HashLength);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to compute hash for given state");
            }

            return ComputedHash;
        }
    }
}
