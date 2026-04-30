using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumGuardedHeapAllocationLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
        const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_malloc(long Size);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_allocarray(long ArrayLength,long ArrayElementSizeInBytes);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_free(IntPtr intPtr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mprotect_noaccess(IntPtr intPtr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mprotect_readonly(IntPtr intPtr);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_mprotect_readwrite(IntPtr intPtr);
    }
}
