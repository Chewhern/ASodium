using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sodium
{
    public static class SodiumSecureMemory
    {
        public static void MemZero(IntPtr intPtr, int Length)
        {
            SodiumSecureMemoryLibrary.sodium_memzero(intPtr, Length);
        }

        public static void MemLock(IntPtr intPtr, int Length)
        {
            int TestInt;
            TestInt = SodiumSecureMemoryLibrary.sodium_mlock(intPtr, Length);
            if (TestInt == -1)
            {
                throw new Exception("Exception: Memory requested to lock exceeds the amount of memory that can be locked..");
            }
        }

        public static void MemUnlock(IntPtr intPtr, int Length)
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
