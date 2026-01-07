using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ASodium
{
    public static class SodiumSecureMemory
    {
        //How Segmentation fault could occur
        //Assume you have an IntPtr with size of 32 bytes
        //or Byte[] with 32 bytes, if you remember the IntPtr
        //bytes size or Byte[] array size wrong,
        //like causing it to be 64 bytes or 33 bytes..
        //Segementation fault could occur as it might write
        //to memory address that belongs to the operating system
        //or other applications..
        public static void MemZero(IntPtr intPtr, long Length)
        {
            SodiumSecureMemoryLibrary.sodium_memzero(intPtr, Length);
        }

        public static void MemZero(Byte[] Source, long Length)
        {
            SodiumSecureMemoryLibrary.sodium_memzero(Source, Length);
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

        public static void SecureClearBytes(Byte[] Source)
        {
            MemZero(Source, Source.LongLength);
        }

        public static void SecureClearString(String Source)
        {
            Byte[] SourceBytes = Encoding.UTF8.GetBytes(Source);
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SourceBytes.LongLength);
            MyGeneralGCHandle.Free();
            SecureClearBytes(SourceBytes);
        }
    }
}
