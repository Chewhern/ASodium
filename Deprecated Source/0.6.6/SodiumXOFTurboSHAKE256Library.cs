using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static partial class SodiumXOFTurboSHAKE256Library
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_blockbytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_statebytes();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_xof_turboshake256_domain_standard();

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256(Byte[] HashedBuffer, long HashedBufferLength, Byte[] Buffer, long BufferLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_init(Byte[] StateBytes);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_init(IntPtr StateBytes);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_init_with_domain(Byte[] StateBytes, Byte DomainByte);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_init_with_domain(IntPtr StateBytes, Byte DomainByte);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_update(Byte[] StateBytes, Byte[] Buffer, long BufferLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_update(IntPtr StateBytes, IntPtr SecretBuffer, long SecretBufferLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_squeeze(Byte[] StateBytes, Byte[] SqueezedData, long SqueezedDataLength);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_xof_turboshake256_squeeze(IntPtr StateBytes, IntPtr SecretSqueezedData, long SecretSqueezedDataLength);

    }
}
