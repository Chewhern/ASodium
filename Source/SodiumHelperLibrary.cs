using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static partial class SodiumHelperLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //sodium_memcmp
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_memcmp(IntPtr ByteArray1IntPtr,IntPtr ByteArray2IntPtr, int BytesArrayMutualSize);

        //sodium_bin2hex
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2hex(Byte[] Hex, int hexMaxlen, Byte[] bin, int binLen);

        //sodium_hex2bin
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_hex2bin(IntPtr bin, int binMaxlen, string hex, int hexLen, string ignore, out int binLen, string hexEnd);

        //sodium_bin2base64
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr sodium_bin2base64(byte[] b64, int b64Maxlen, byte[] bin, int binLen, int variant);

        //sodium_base642bin
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base642bin(IntPtr bin, int binMaxlen, string b64, int b64Len, string ignore, out int binLen, out char b64End, int variant);

        //sodium_base64_encoded_len
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_base64_encoded_len(int binLen, int variant);

        //sodium_increment
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_increment(Byte[] NumberByte, int NumberByteLength);

        //sodium_add
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_add(Byte[] NumberByte1, Byte[] NumberByte2, int NumberBytesMutualLength);

        //sodium_sub
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void sodium_sub(Byte[] NumberByte1, Byte[] NumberByte2, int NumberBytesMutualLength);

        //sodium_compare
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_compare(IntPtr ByteArray1IntPtr, IntPtr ByteArray2IntPtr, int NumberBytesMutualLength);

        //sodium_is_zero
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_is_zero(Byte[] Data, int DataLength);

        //sodium_stackzero
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int sodium_stackzero(int BytesArrayLength);
    }
}
