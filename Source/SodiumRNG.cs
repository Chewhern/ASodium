using System;

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

        public static Byte[] GetSeededRandomBytes(long Count, Byte[] Seed) 
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
            return Buffer;
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
