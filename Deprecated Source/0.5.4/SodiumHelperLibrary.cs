using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static partial class SodiumHelperLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_memcmp(IntPtr ByteArray1IntPtr,IntPtr ByteArray2IntPtr, int BytesArrayMutualSize);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2hex(Byte[] Hex, int hexMaxlen, Byte[] bin, int binLen);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_hex2bin(IntPtr bin, int binMaxlen, string hex, int hexLen, string ignore, out int binLen, string hexEnd);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2base64(byte[] b64, int b64Maxlen, byte[] bin, int binLen, int variant);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base642bin(IntPtr bin, int binMaxlen, string b64, int b64Len, string ignore, out int binLen, out char b64End, int variant);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base64_encoded_len(int binLen, int variant);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(Byte[] NumberByte, int NumberByteLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_add(Byte[] NumberByte1, Byte[] NumberByte2, int NumberBytesMutualLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_sub(Byte[] NumberByte1, Byte[] NumberByte2, int NumberBytesMutualLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_compare(IntPtr ByteArray1IntPtr, IntPtr ByteArray2IntPtr, int NumberBytesMutualLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_is_zero(Byte[] Data, int DataLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_stackzero(int BytesArrayLength);
    }
}
