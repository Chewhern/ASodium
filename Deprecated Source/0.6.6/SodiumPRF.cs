using System;

namespace ASodium
{
    public static class SodiumPRF
    {
        public static Byte[] NonceExtension(Byte[] Nonce, Byte[] Key, Byte[] Constant=null,Boolean ClearKey=false) 
        {
            if (Nonce == null) 
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null) 
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != 16) 
            {
                throw new ArgumentException("Error: Nonce must be 16 bytes in length");
            }
            if (Key.Length != 32) 
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }

            if (Constant != null && Constant.Length != 16)
            {
                throw new ArgumentException("Error: Constant must be 16 bytes in length");
            }

            Byte[] ExtendedNonce = new Byte[32];

            SodiumPRFLibrary.crypto_core_hchacha20(ExtendedNonce, Nonce, Key, Constant);

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return ExtendedNonce;
        }

        public static Byte[] NonceExtension(Byte[] Nonce, IntPtr Key, Byte[] Constant = null, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must be 16 bytes in length");
            }

            if (Constant != null && Constant.Length != 16)
            {
                throw new ArgumentException("Error: Constant must be 16 bytes in length");
            }

            Byte[] ExtendedNonce = new Byte[32];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_core_hchacha20(ExtendedNonce, Nonce, Key, Constant);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return ExtendedNonce;
        }

        public static Byte[] Salsa20PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_salsa20(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] Salsa20PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_salsa20(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }

        public static Byte[] Salsa2012PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0) 
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_salsa2012(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] Salsa2012PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }

            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_salsa2012(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }

        public static Byte[] Salsa208PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_salsa208(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] Salsa208PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherSalsa20.GetSalsa20NonceBytesLength() + "bytes in length");
            }

            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_salsa208(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }

        public static Byte[] ChaCha20PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_chacha20(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] ChaCha20PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherChaCha20.GetChaCha20NonceBytesLength() + "bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_chacha20(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }

        public static Byte[] XSalsa20PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_xsalsa20(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] XSalsa20PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherXSalsa20.GetXSalsa20NonceBytesLength() + "bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_xsalsa20(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }

        public static Byte[] XChaCha20PRF(long RandomOutputLength, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false) 
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherXChaCha20.GetXChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherXChaCha20.GetXChaCha20NonceBytesLength() + "bytes in length");
            }
            if (Key.Length != 32)
            {
                throw new ArgumentException("Error: Key must be 32 bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumPRFLibrary.crypto_stream_xchacha20(RandomOutput, RandomOutputLength, Nonce, Key);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return RandomOutput;
        }

        public static Byte[] XChaCha20PRF(long RandomOutputLength, Byte[] Nonce, IntPtr Key, Boolean ClearKey = false)
        {
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce must not be null/empty");
            }

            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null/empty");
            }

            if (Nonce.Length != SodiumStreamCipherXChaCha20.GetXChaCha20NonceBytesLength())
            {
                throw new ArgumentException("Error: Nonce must be" + SodiumStreamCipherXChaCha20.GetXChaCha20NonceBytesLength() + "bytes in length");
            }
            if (RandomOutputLength < 0)
            {
                throw new ArgumentException("Error: Random output's length must not be negative value");
            }

            Byte[] RandomOutput = new Byte[RandomOutputLength];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            SodiumPRFLibrary.crypto_stream_xchacha20(RandomOutput, RandomOutputLength, Nonce, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return RandomOutput;
        }
    }
}
