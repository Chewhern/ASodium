using System;

namespace ASodium
{
    public static class SodiumGuardedHeapAllocation
    {
        public static IntPtr Sodium_Malloc(ref Boolean IsZero,long Size) 
        {
            IntPtr intPtr = SodiumGuardedHeapAllocationLibrary.sodium_malloc(Size);
            if (intPtr == IntPtr.Zero) 
            {
                IsZero = true;
            }
            else 
            {
                IsZero = false;
            }
            return intPtr;
        }

        public static IntPtr Sodium_AllocArray(ref Boolean IsZero, long ArrayLength, long ArrayElementSizeInBytes) 
        {
            ulong ArrayLengthULong = ulong.Parse(ArrayLength.ToString());
            ulong ArrayElementSizeInBytesULong = ulong.Parse(ArrayElementSizeInBytes.ToString());

            if (ArrayLength >0) 
            {
                if (ArrayElementSizeInBytesULong >= (ulong.MaxValue / ArrayLengthULong))
                {
                    throw new ArgumentException("Error: The array elements size you want to initialize in bytes is not acceptable. The maximum array elements size in bytes that you can initialize was "+ (ulong.MaxValue / ArrayLengthULong).ToString());
                }
            }
            
            if(ArrayLength<0 || ArrayElementSizeInBytes < 0) 
            {
                throw new ArgumentException("Error: ArrayLength or ArrayElementsSizeInBytes shouldn't be a negative value.");
            }

            IntPtr intPtr = SodiumGuardedHeapAllocationLibrary.sodium_allocarray(ArrayLength, ArrayElementSizeInBytes);
            if (intPtr == IntPtr.Zero)
            {
                IsZero = true;
            }
            else
            {
                IsZero = false;
            }
            return intPtr;
        }

        public static void Sodium_Free(IntPtr intPtr) 
        {
            SodiumGuardedHeapAllocationLibrary.sodium_free(intPtr);
        }

        public static void Sodium_MProtect_NoAccess(IntPtr intPtr) 
        {
            int Status = 0;
            Status= SodiumGuardedHeapAllocationLibrary.sodium_mprotect_noaccess(intPtr);
            if (Status == -1) 
            {
                throw new Exception("Error: This pointer is already in no access state.");
            }
        }

        public static void Sodium_MProtect_ReadOnly(IntPtr intPtr)
        {
            int Status = 0;
            Status = SodiumGuardedHeapAllocationLibrary.sodium_mprotect_readonly(intPtr);
            if (Status == -1)
            {
                throw new Exception("Error: This pointer is already in read only state.");
            }
        }

        public static void Sodium_MProtect_ReadWrite(IntPtr intPtr)
        {
            int Status = 0;
            Status = SodiumGuardedHeapAllocationLibrary.sodium_mprotect_readwrite(intPtr);
            if (Status == -1)
            {
                throw new Exception("Error: This pointer is already in read write state.");
            }
        }
    }
}
