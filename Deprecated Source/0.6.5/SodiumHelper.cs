using System;
using System.Runtime.InteropServices;

namespace ASodium
{
    public static class SodiumHelper
    {
        public static void Sodium_Memory_Compare(Byte[] ByteArray1, Byte[] ByteArray2) 
        {
            if (ByteArray1 == null || ByteArray2 == null) 
            {
                throw new ArgumentException("Error: ByteArray1 and ByteArray2 must not be null");
            }
            if (ByteArray1.Length != ByteArray2.Length) 
            {
                throw new ArgumentException("Error: ByteArray1 and ByteArray2 must be the same length in bytes");
            }
            int result=SodiumHelperLibrary.sodium_memcmp(ByteArray1, ByteArray2, ByteArray1.LongLength);
            if (result == -1) 
            {
                throw new Exception("Error: Two bytes array does not match.");
            }
        }

        public static void Sodium_Memory_Compare(IntPtr ByteArray1, IntPtr ByteArray2, long ArrayLength)
        {
            if (ByteArray1 == IntPtr.Zero || ByteArray2 == IntPtr.Zero)
            {
                throw new ArgumentException("Error: ByteArray1 and ByteArray2 must not be null");
            }
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ByteArray1);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ByteArray2);
            int result = SodiumHelperLibrary.sodium_memcmp(ByteArray1, ByteArray2, ArrayLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ByteArray1);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(ByteArray2);
            if (result == -1)
            {
                throw new Exception("Error: Two bytes array does not match.");
            }
        }

        public enum Base64Variant
        {
            /// <summary>Original Base64 encoding variant.</summary>
            Original = 1,
            /// <summary>Original Base64 encoding variant with no padding.</summary>
            OriginalNoPadding = 3,
            /// <summary>Urlsafe Base64 encoding variant.</summary>
            UrlSafe = 5,
            /// <summary>Urlsafe Base64 encoding variant with no padding.</summary>
            UrlSafeNoPadding = 7
        }

        public static string BinaryToHex(Byte[] data)
        {
            var hex = new Byte[(data.Length * 2) + 1];
            var ret = SodiumHelperLibrary.sodium_bin2hex(hex, hex.Length, data, data.Length);

            if (ret == IntPtr.Zero)
            {
                throw new OverflowException("Internal error, encoding failed.");
            }

            return Marshal.PtrToStringAnsi(ret);
        }

        public static Byte[] HexToBinary(String hex)
        {
            const String IGNORED_CHARS = ":- ";

            var arr = new byte[hex.Length >> 1];
            var bin = Marshal.AllocHGlobal(arr.Length);
            int binLength;

            //we call sodium_hex2bin with some chars to be ignored
            var ret = SodiumHelperLibrary.sodium_hex2bin(bin, arr.Length, hex, hex.Length, IGNORED_CHARS, out binLength, null);

            Marshal.Copy(bin, arr, 0, binLength);
            Marshal.FreeHGlobal(bin);

            if (ret != 0)
            {
                throw new Exception("Internal error, decoding failed.");
            }

            //remove the trailing nulls from the array, if there were some format characters in the hex string before
            if (arr.Length != binLength)
            {
                var tmp = new Byte[binLength];
                Array.Copy(arr, 0, tmp, 0, binLength);
                return tmp;
            }

            return arr;
        }

        public static String BinaryToBase64(byte[] data, Base64Variant variant = Base64Variant.Original)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data is null, encoding failed");
            }

            if (data.Length == 0)
            {
                return string.Empty;
            }

            int base64MaxLen = SodiumHelperLibrary.sodium_base64_encoded_len(data.Length, (int)variant);
            var b64 = new Byte[base64MaxLen];
            var base64 = SodiumHelperLibrary.sodium_bin2base64(b64, base64MaxLen, data, data.Length, (int)variant);
            if (base64 == IntPtr.Zero)
            {
                throw new OverflowException("Internal error, encoding failed.");
            }
            return Marshal.PtrToStringAnsi(base64);
        }

        public static Byte[] Base64ToBinary(string base64, string ignoredChars, Base64Variant variant = Base64Variant.Original)
        {
            if (base64 == null)
            {
                throw new ArgumentNullException(nameof(base64), "Data is null, encoding failed");
            }
            if (base64 == string.Empty)
            {
                return new byte[] { };
            }

            var bin = Marshal.AllocHGlobal(base64.Length);
            var ret = SodiumHelperLibrary.sodium_base642bin(bin, base64.Length, base64, base64.Length, ignoredChars, out var binLength,
              out var lastChar, (int)variant);

            if (ret != 0)
            {
                throw new Exception("Internal error, decoding failed.");
            }

            var decodedArr = new Byte[binLength];
            Marshal.Copy(bin, decodedArr, 0, binLength);
            Marshal.FreeHGlobal(bin);

            return decodedArr;
        }

        //Sodium_Increment needs to have AMD64 ASM to work..
        //Uncertain if current code works..
        public static Byte[] Sodium_Increment(Byte[] UnsignedNumberInBytesFormat) 
        {
            Byte[] NewUnsignedNumberInBytesFormat = UnsignedNumberInBytesFormat;
            int BytesLength = NewUnsignedNumberInBytesFormat.Length;
            SodiumHelperLibrary.sodium_increment(NewUnsignedNumberInBytesFormat, BytesLength);

            return NewUnsignedNumberInBytesFormat;
        }

        //Unable to test..
        public static IntPtr Sodium_Increment(IntPtr UnsignedNumberInBytesFormat,int BytesLength)
        {
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(UnsignedNumberInBytesFormat);
            SodiumHelperLibrary.sodium_increment(UnsignedNumberInBytesFormat, BytesLength);

            return UnsignedNumberInBytesFormat;
        }

        public static Byte[] Sodium_Add(Byte[] UnsignedNumber1,Byte[] UnsignedNumber2) 
        {
            Byte[] ResultUnsignedNumber = UnsignedNumber1;
            int Length = UnsignedNumber1.Length;
            int Length2 = UnsignedNumber2.Length;

            if (Length != Length2) 
            {
                throw new ArgumentException("Error: These 2 numbers are not the same sizes in bytes");
            }

            SodiumHelperLibrary.sodium_add(ResultUnsignedNumber, UnsignedNumber2, Length);

            return ResultUnsignedNumber;
        }

        public static IntPtr Sodium_Add(IntPtr UnsignedNumber1, IntPtr UnsignedNumber2, int Length)
        {
            IntPtr ResultUnsignedNumber = UnsignedNumber1;

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ResultUnsignedNumber);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(UnsignedNumber2);

            SodiumHelperLibrary.sodium_add(ResultUnsignedNumber, UnsignedNumber2, Length);

            return ResultUnsignedNumber;
        }

        public static Byte[] Sodium_Sub(Byte[] UnsignedNumber1,Byte[] UnsignedNumber2) 
        {
            Byte[] ResultUnsignedNumber = UnsignedNumber1;
            int Length = UnsignedNumber1.Length;
            int Length2 = UnsignedNumber2.Length;

            if (Length != Length2)
            {
                throw new ArgumentException("Error: These 2 numbers are not the same sizes in bytes");
            }

            SodiumHelperLibrary.sodium_sub(ResultUnsignedNumber, UnsignedNumber2, Length);

            return ResultUnsignedNumber;
        }

        public static IntPtr Sodium_Sub(IntPtr UnsignedNumber1, IntPtr UnsignedNumber2, int Length)
        {
            IntPtr ResultUnsignedNumber = UnsignedNumber1;

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(ResultUnsignedNumber);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(UnsignedNumber2);
            SodiumHelperLibrary.sodium_sub(ResultUnsignedNumber, UnsignedNumber2, Length);

            return ResultUnsignedNumber;
        }

        public static int Sodium_Compare(Byte[] NumberInByteArray1, Byte[] NumberInByteArray2) 
        {
            return SodiumHelperLibrary.sodium_compare(NumberInByteArray1, NumberInByteArray2,NumberInByteArray1.LongLength);
        }

        public static int Sodium_Compare(IntPtr NumberInByteArray1, IntPtr NumberInByteArray2, int Length)
        {
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NumberInByteArray1);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(NumberInByteArray2);
            return SodiumHelperLibrary.sodium_compare(NumberInByteArray1, NumberInByteArray2, Length);
        }

        public static int Sodium_Is_Zero(Byte[] Data) 
        {
            int Length = Data.Length;

            return SodiumHelperLibrary.sodium_is_zero(Data, Length);
        }

        public static int Sodium_Is_Zero(IntPtr Data, int Length)
        {
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Data);

            return SodiumHelperLibrary.sodium_is_zero(Data, Length);
        }

        public static void Sodium_StackZero(int BytesArrayLength) 
        {
            SodiumHelperLibrary.sodium_stackzero(BytesArrayLength);
        }
    }
}
