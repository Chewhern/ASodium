using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;


namespace Sodium
{
    public static partial class SodiumScalarMultLibrary
    {
        #if IOS
            const string DllName = "__Internal";
        #else
            const string DllName = "libsodium";
        #endif

        //crypto_scalarmult_base
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_base(Byte[] CurrentUserPublicKey, Byte[] CurrentUserSecretKey);

        //crypto_scalarmult
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult(Byte[] SharedSecret, Byte[] CurrentUserSecretKey,Byte[] OtherUserPublicKey);

        //crypto_scalarmult_bytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_bytes();

        //crypto_scalarmult_scalarbytes
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int crypto_scalarmult_scalarbytes();

        //crypto_scalarmult_primitive
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Byte crypto_scalarmult_primitive();
    }
}
