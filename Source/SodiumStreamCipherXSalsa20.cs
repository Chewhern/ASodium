using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumStreamCipherXSalsa20
    {
        public static int GetXSalsa20KeyBytesLength()
        {
            return SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_keybytes();
        }

        public static int GetXSalsa20NonceBytesLength()
        {
            return SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_noncebytes();
        }

        public static Byte[] XSalsa20GenerateKey()
        {
            Byte[] Key = new Byte[GetXSalsa20KeyBytesLength()];

            SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_keygen(Key);

            return Key;
        }

        public static IntPtr XSalsa20GenerateKeyIntPtr()
        {
            Byte[] Key = new Byte[GetXSalsa20KeyBytesLength()];

            SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetXSalsa20KeyBytesLength());

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetXSalsa20KeyBytesLength());
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                return KeyIntPtr;
            }
            else
            {
                GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }

        public static Byte[] GenerateXSalsa20Nonce()
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetXSalsa20NonceBytesLength());

            return Nonce;
        }

        public static Byte[] XSalsa20Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetXSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetXSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] XSalsa20Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key)
        {
            return XSalsa20Encrypt(CipherText, Nonce, Key);
        }

        public static Byte[] XSalsa20StraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.Length == 0)
                {
                    throw new ArgumentException("Error: Message Length must not be 0");
                }
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null");
            }
            else
            {
                if (Nonce.Length != GetXSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetXSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetXSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetXSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherXSalsa20Library.crypto_stream_xsalsa20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] XSalsa20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC)
        {
            return XSalsa20StraightEncrypt(CipherText, Nonce, Key, IC);
        }
    }
}
