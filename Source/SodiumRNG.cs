using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumRNG
    {
        public static int GetSeedBytesValue() 
        {
            return SodiumRNGLibrary.randombytes_seedbytes();
        }

        public static Byte[] GetRandomBytes(int Count) 
        {
            var Buffer = new Byte[Count];
            SodiumRNGLibrary.randombytes_buf(Buffer, Count);

            return Buffer;
        }

        public static IntPtr GetRandomBytesIntPtr(int Count) 
        {
            Boolean IsZero = true;
            IntPtr DataIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Count);

            int TryAttempts = 5;
            int Loop = 0;

            while (IsZero == true && Loop < TryAttempts)
            {
                DataIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Count);
                Loop += 1;
            }

            if (IsZero == false && Loop < TryAttempts)
            {
                SodiumRNGLibrary.randombytes_buf(DataIntPtr, Count);
            }
            else
            {
                DataIntPtr = IntPtr.Zero;
            }

            return DataIntPtr;
        }

        public static Byte[] GetSeededRandomBytes(long Count, Byte[] Seed,Boolean ClearKey=false) 
        {
            var Buffer = new Byte[Count];
            long Checker = 274877766207;
            if (Seed.Length == GetSeedBytesValue()) 
            {
                if (Count <= Checker) 
                {
                    SodiumRNGLibrary.randombytes_buf_deterministic(Buffer, Count, Seed);
                }
                else 
                {
                    throw new ArgumentException("Error: Count size cannot bigger than "+Checker.ToString());
                }
            }
            else 
            {
                throw new ArgumentException("Error: Seed length is not equals to "+(GetSeedBytesValue()).ToString());
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Seed);
            }

            return Buffer;
        }

        public static IntPtr GetSeededRandomBytes(long Count, IntPtr Seed, Boolean ClearKey = false)
        {
            long Checker = 274877766207;
            if(Seed == IntPtr.Zero) 
            {
                throw new ArgumentException("Error: Seed must not be empty");
            }

            if (Count > Checker)
            {
                throw new ArgumentException("Error: Count size cannot bigger than " + Checker.ToString());
            }

            Boolean IsZero = true;
            IntPtr DataIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Count);

            int TryAttempts = 5;
            int Loop = 0;

            while (IsZero == true && Loop < TryAttempts)
            {
                DataIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, Count);
                Loop += 1;
            }

            if (IsZero == false && Loop < TryAttempts)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Seed);
                SodiumRNGLibrary.randombytes_buf_deterministic(DataIntPtr, Count, Seed);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Seed);
            }
            else
            {
                DataIntPtr = IntPtr.Zero;
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Seed);
                SodiumGuardedHeapAllocation.Sodium_Free(Seed);
            }

            return DataIntPtr;
        }

        public static uint GetUniformUpperBoundRandomNumber(uint upperBound)
        {
            if (upperBound < 2) 
            {
                throw new ArgumentException("Error: Upper Bound should not be less than 2");
            }

            var randomNumber = SodiumRNGLibrary.randombytes_uniform(upperBound);

            return randomNumber;
        }

        public static uint GetRandomNumber() 
        {
            var randomNumber = SodiumRNGLibrary.randombytes_random();

            return randomNumber;
        }
    }
}
