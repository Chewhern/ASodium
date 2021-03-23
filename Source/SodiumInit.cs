using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Sodium
{
    public static class SodiumInit
    {
        private static bool _isInit;

        static SodiumInit()
        {
            Init();
        }

        public static string SodiumVersionString()
        {
            var ptr = SodiumInitLibrary.sodium_version_string();

            return Marshal.PtrToStringAnsi(ptr);
        }

        public static void Init()
        {
            if (!_isInit)
            {
                SodiumInitLibrary.sodium_init();
                _isInit = true;
            }
        }
    }
}
