using System;

namespace ASodium
{
    public static class SodiumSecureMemory
    {
        public static void MemZero(IntPtr intPtr, long Length)
        {
            SodiumSecureMemoryLibrary.sodium_memzero(intPtr, Length);
        }

        public static void MemLock(IntPtr intPtr, long Length)
        {
            int TestInt;
            TestInt = SodiumSecureMemoryLibrary.sodium_mlock(intPtr, Length);
            if (TestInt == -1)
            {
                throw new Exception("Exception: Memory requested to lock exceeds the amount of memory that can be locked..");
            }
        }

        public static void MemUnlock(IntPtr intPtr, long Length)
        {
            int TestInt;
            TestInt = SodiumSecureMemoryLibrary.sodium_munlock(intPtr, Length);
            if (TestInt == -1)
            {
                throw new Exception("Exception: Unlock and MemZero process failed..");
            }
        }
    }
}
