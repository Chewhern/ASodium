using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ASodium
{
    public static class SodiumSecureMemory
    {
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

        public static void MemLock(Byte[] Source, long Length)
        {
            int TestInt;
            TestInt = SodiumSecureMemoryLibrary.sodium_mlock(Source, Length);
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

        public static void MemUnlock(Byte[] Source, long Length)
        {
            int TestInt;
            TestInt = SodiumSecureMemoryLibrary.sodium_munlock(Source, Length);
            if (TestInt == -1)
            {
                throw new Exception("Exception: Unlock and MemZero process failed..");
            }
        }

        //To prevent segmentation fault, it's advised to
        //not really use GCHandle that often to create
        //an IntPtr object in C#.
        //There's only so many IntPtr objects that can be
        //created by C# before segmentation fault occurs
        //and force stops the program.

        //Due to such reason, locking, unlocking and secure
        //overwrite a memory address with zero is best to 
        //be used with Byte[] which is equivalent to uint8*
        //or unsigned char* in C.

        //==Safe and performance guaranteed==
        public static void SecureClearBytes(Byte[] Source)
        {
            MemZero(Source, Source.LongLength);
        }

        public static void SecureMemoryLockBytes(Byte[] Source)
        {
            MemLock(Source, Source.LongLength);
        }

        public static void SecureMemoryUnlockBytes(Byte[] Source)
        {
            MemUnlock(Source, Source.LongLength);
        }

        //==Safe but there's a risk in the system or program
        //unable to generate IntPtr object via GCHandle
        //or via "static unsafe void Main()" ==
        public static void SecureClearString(String Source)
        {
            Byte[] SourceBytes = Encoding.UTF8.GetBytes(Source);
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SourceBytes.LongLength);
            MyGeneralGCHandle.Free();
            SecureClearBytes(SourceBytes);
        }

        public static void SecureMemoryLockString(String Source)
        {
            Byte[] SourceBytes = Encoding.UTF8.GetBytes(Source);
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), SourceBytes.LongLength);
            MyGeneralGCHandle.Free();
            SecureClearBytes(SourceBytes);
        }

        public static void SecureMemoryUnlockString(String Source)
        {
            Byte[] SourceBytes = Encoding.UTF8.GetBytes(Source);
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), SourceBytes.LongLength);
            MyGeneralGCHandle.Free();
            SecureClearBytes(SourceBytes);
        }

        //I try to optimize the String operations and reduce the likelihood of
        //having segmentation fault or having zero pointers/null pointer.
        //However, I only reduce and optimize the String operations.
        //I can't guarantee that it's 100% gone.
        //Please bear in mind when using String related operations.

        //Don't really know how to optimize or make the operations on char array
        //more proper.
        public static void SecureClearCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source.LongLength*2);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryLockCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.LongLength*2);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryUnlockCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.LongLength*2);
            MyGeneralGCHandle.Free();
        }
    }
}
