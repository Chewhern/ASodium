using System;
using System.Runtime.InteropServices;

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

        //Only data types below can use securememory functions
        //It's recommended to avoid using String
        //If you can just use Bytes[] or Char[]
        public static void SecureClearBytes(Byte[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source.LongLength);
            MyGeneralGCHandle.Free();
        }

        public static void SecureClearString(String Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureClearCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryLockBytes(Byte[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryLockString(String Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryLockCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemLock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryUnlockBytes(Byte[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryUnlockString(String Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }

        public static void SecureMemoryUnlockCharArray(Char[] Source)
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Source, GCHandleType.Pinned);
            MemUnlock(MyGeneralGCHandle.AddrOfPinnedObject(), Source.Length);
            MyGeneralGCHandle.Free();
        }
    }
}
