using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumStreamCipherChaCha20
    {
        public static int GetChaCha20KeyBytesLength() 
        {
            return SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_keybytes();
        }

        public static int GetChaCha20NonceBytesLength() 
        {
            return SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_noncebytes();
        }

        public static int GetChaCha20IETFKeyBytesLength() 
        {
            return SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_ietf_keybytes();
        }

        public static int GetChaCha20IETFNonceBytesLength() 
        {
            return SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_ietf_noncebytes();
        }

        public static long GetChaCha20IETFMaxMessageLength() 
        {
            return SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_ietf_messagebytes_max();
        }

        public static Byte[] ChaCha20GenerateKey() 
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetChaCha20KeyBytesLength());

            return Key;
        }

        public static IntPtr ChaCha20GenerateKeyIntPtr() 
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetChaCha20KeyBytesLength());

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,GetChaCha20KeyBytesLength());

            if (IsZero == false) 
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetChaCha20KeyBytesLength());
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

        public static Byte[] ChaCha20IETFGenerateKey()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetChaCha20IETFKeyBytesLength());

            return Key;
        }

        public static IntPtr ChaCha20IETFGenerateKeyIntPtr()
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(GetChaCha20IETFKeyBytesLength());

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetChaCha20KeyBytesLength());

            if (IsZero == false)
            {
                Marshal.Copy(Key, 0, KeyIntPtr, GetChaCha20KeyBytesLength());
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

        public static Byte[] GenerateChaCha20Nonce() 
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetChaCha20NonceBytesLength());

            return Nonce;
        }

        public static Byte[] GenerateChaCha20IETFNonce() 
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(GetChaCha20IETFNonceBytesLength());

            return Nonce;
        }

        public static Byte[] ChaCha20Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key) 
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
                if (Nonce.Length != GetChaCha20NonceBytesLength()) 
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null) 
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else 
            {
                if (Key.Length != GetChaCha20KeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetChaCha20KeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] ChaCha20Decrypt(Byte[] CipherText,Byte[] Nonce,Byte[] Key) 
        {
            return ChaCha20Encrypt(CipherText, Nonce, Key);
        }

        public static Byte[] ChaCha20IETFEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key)
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
                if (Nonce.Length != GetChaCha20IETFNonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetChaCha20IETFNonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetChaCha20IETFKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetChaCha20IETFKeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_ietf_xor(OutPut, Message, Message.LongLength, Nonce, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] ChaCha20IETFDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key)
        {
            return ChaCha20IETFEncrypt(CipherText, Nonce, Key);
        }

        public static Byte[] ChaCha20StraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC) 
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
                if (Nonce.Length != GetChaCha20NonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetChaCha20NonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetChaCha20KeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetChaCha20KeyBytesLength() + " bytes");
                }
            }

            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to straight encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] ChaCha20StraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC) 
        {
            return ChaCha20StraightEncrypt(CipherText, Nonce, Key, IC);
        }

        public static Byte[] ChaCha20IETFStraightEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, ulong IC)
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
                if (Nonce.Length != GetChaCha20IETFNonceBytesLength())
                {
                    throw new ArgumentException("Error: Nonce Length must exactly be " + GetChaCha20IETFNonceBytesLength() + " bytes");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetChaCha20IETFKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key Length must exactly be " + GetChaCha20IETFKeyBytesLength() + " bytes");
                }
            }
            Byte[] OutPut = new Byte[Message.LongLength];

            int result = SodiumStreamCipherChaCha20Library.crypto_stream_chacha20_ietf_xor_ic(OutPut, Message, Message.LongLength, Nonce, IC, Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to straight encrypt using ChaCha20 stream cipher");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return OutPut;
        }

        public static Byte[] ChaCha20IETFStraightDecrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, ulong IC)
        {
            return ChaCha20IETFStraightEncrypt(CipherText, Nonce, Key, IC);
        }
    }
}
