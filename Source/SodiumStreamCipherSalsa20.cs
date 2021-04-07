using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumStreamCipherSalsa20
    {
        public static int GetSalsa20KeyBytesLength()
        {
            return SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keybytes();
        }

        public static int GetSalsa20NonceBytesLength()
        {
            return SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_noncebytes();
        }

        public static Byte[] Salsa20GenerateKey()
        {
            Byte[] Key = new Byte[GetSalsa20KeyBytesLength()];

            SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keygen(Key);

            return Key;
        }

        public static IntPtr Salsa20GenerateKeyIntPtr()
        {
            Byte[] Key = new Byte[GetSalsa20KeyBytesLength()];

            SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetSalsa20KeyBytesLength());

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetSalsa20KeyBytesLength());
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

        public static Byte[] GenerateSalsa20Nonce()
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetSalsa20NonceBytesLength());

            return Nonce;
        }

        public static Byte[] Salsa20Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] Salsa20Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key)
        {
            return Salsa20Encrypt(CipherText, Nonce, Key);
        }

        public static Byte[] Salsa20StraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC)
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
                if (Nonce.Length != GetSalsa20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetSalsa20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetSalsa20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetSalsa20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherSalsa20Library.crypto_stream_salsa20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] Salsa20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC)
        {
            return Salsa20StraightEncrypt(CipherText, Nonce, Key, IC);
        }
    }
}
