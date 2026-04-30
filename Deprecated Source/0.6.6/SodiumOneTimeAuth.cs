using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ASodium
{
    public static class SodiumOneTimeAuth
    {
        public static int GetStateBytesLength() 
        {
            return SodiumOneTimeAuthLibrary.crypto_onetimeauth_statebytes();
        }

        public static int GetPoly1305MACLength() 
        {
            return SodiumOneTimeAuthLibrary.crypto_onetimeauth_bytes();
        }

        public static int GetKeyBytesLength() 
        {
            return SodiumOneTimeAuthLibrary.crypto_onetimeauth_keybytes();
        }

        public static Byte[] GenerateKey() 
        {
            Byte[] Key = new Byte[GetKeyBytesLength()];

            SodiumOneTimeAuthLibrary.crypto_onetimeauth_keygen(Key);

            return Key;
        }

        public static IntPtr GenerateKeyIntPtr() 
        {
            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,GetKeyBytesLength());

            if (IsZero == false) 
            {
                SodiumOneTimeAuthLibrary.crypto_onetimeauth_keygen(KeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                return KeyIntPtr;
            }
            else 
            {
                return IntPtr.Zero;
            }
        }

        public static Byte[] ComputePoly1305MAC(Byte[] Message,Byte[] Key,Boolean ClearKey=false) 
        {
            if (Message == null) 
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else 
            {
                if (Message.LongLength == 0) 
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }
            if (Key == null) 
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else 
            {
                if (Key.Length != GetKeyBytesLength()) 
                {
                    throw new ArgumentException("Error: Key must exactly be " + GetKeyBytesLength() + " bytes");
                }
            }
            Byte[] Poly1305MAC = new Byte[GetPoly1305MACLength()];
            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth(Poly1305MAC, Message, Message.LongLength, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to compute Poly1305 MAC");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return Poly1305MAC;
        }

        public static Byte[] ComputePoly1305MAC(Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.LongLength == 0)
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }

            Byte[] Poly1305MAC = new Byte[GetPoly1305MACLength()];
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth(Poly1305MAC, Message, Message.LongLength, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (result != 0)
            {
                throw new CryptographicException("Failed to compute Poly1305 MAC");
            }

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            return Poly1305MAC;
        }

        public static Boolean VerifyPoly1305MAC(Byte[] Poly1305MAC, Byte[] Message, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.LongLength == 0)
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must exactly be " + GetKeyBytesLength() + " bytes");
                }
            }
            if (Poly1305MAC == null) 
            {
                throw new ArgumentException("Error: Poly1305 MAC must not be null");
            }
            else 
            {
                if (Poly1305MAC.Length != GetPoly1305MACLength()) 
                {
                    throw new ArgumentException("Error: Poly1305 MAC length must be " + GetPoly1305MACLength() + " bytes");
                }
            }

            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_verify(Poly1305MAC, Message, Message.LongLength, Key);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            if (result != 0) 
            {
                return false;
            }
            else 
            {
                return true;
            }
        }

        public static Boolean VerifyPoly1305MAC(Byte[] Poly1305MAC, Byte[] Message, IntPtr Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.LongLength == 0)
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            if (Poly1305MAC == null)
            {
                throw new ArgumentException("Error: Poly1305 MAC must not be null");
            }
            else
            {
                if (Poly1305MAC.Length != GetPoly1305MACLength())
                {
                    throw new ArgumentException("Error: Poly1305 MAC length must be " + GetPoly1305MACLength() + " bytes");
                }
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(Key);
            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_verify(Poly1305MAC, Message, Message.LongLength, Key);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(Key);

            if (ClearKey == true)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                SodiumGuardedHeapAllocation.Sodium_Free(Key);
            }

            if (result != 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public static Byte[] InitializeState(Byte[] Key,Boolean ClearKey=false) 
        {
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length != GetKeyBytesLength())
                {
                    throw new ArgumentException("Error: Key must exactly be " + GetKeyBytesLength() + " bytes");
                }
            }

            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_init(State, Key);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to initialize Poly1305 state");
            }

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return State;
        }

        public static IntPtr InitializeState(IntPtr Key, Boolean ClearKey = false)
        {
            if (Key == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Key must not be null");
            }

            Boolean IsZero = true;
            IntPtr StateIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStateBytesLength());

            if (IsZero == false)
            {
                int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_init(StateIntPtr, Key);

                if (result != 0)
                {
                    throw new CryptographicException("Error: Failed to initialize Poly1305 state");
                }

                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(StateIntPtr);
                return StateIntPtr;
            }
            else
            {
                if (ClearKey) 
                {
                    SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(Key);
                    SodiumGuardedHeapAllocation.Sodium_Free(Key);
                }
                return IntPtr.Zero;
            }
        }

        public static Byte[] UpdateState(Byte[] OldState, Byte[] Message) 
        {
            if (OldState == null) 
            {
                throw new ArgumentException("Error: State must not be null");
            }
            else 
            {
                if (OldState.Length != GetStateBytesLength()) 
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes");
                }
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.LongLength == 0)
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }
            Byte[] State = OldState;

            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_update(State, Message, Message.LongLength);

            if (result != 0) 
            {
                throw new CryptographicException("Failed to update Poly1305 state");
            }

            return State;
        }

        public static IntPtr UpdateState(IntPtr State, Byte[] Message)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State must not be null");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            else
            {
                if (Message.LongLength == 0)
                {
                    throw new ArgumentException("Error: Message length must not be 0");
                }
            }


            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_update(State, Message, Message.LongLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);

            if (result != 0)
            {
                throw new CryptographicException("Failed to update Poly1305 state");
            }

            return State;
        }

        public static Byte[] ComputeFinalizedStatePoly1305MAC(Byte[] State, Boolean ClearKey=false) 
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State must not be null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes");
                }
            }

            Byte[] Poly1305MAC = new Byte[GetPoly1305MACLength()];

            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_final(State, Poly1305MAC);

            if (result != 0) 
            {
                throw new CryptographicException("Error: Failed to compute Poly1305 MAC for finalized state");
            }

            if (ClearKey) 
            {
                SodiumSecureMemory.SecureClearBytes(State);
            }

            return Poly1305MAC;
        }

        public static Byte[] ComputeFinalizedStatePoly1305MAC(IntPtr State, Boolean ClearKey=false)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State must not be null");
            }

            Byte[] Poly1305MAC = new Byte[GetPoly1305MACLength()];

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
            int result = SodiumOneTimeAuthLibrary.crypto_onetimeauth_final(State, Poly1305MAC);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to compute Poly1305 MAC for finalized state");
            }

            if (ClearKey) 
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
                SodiumGuardedHeapAllocation.Sodium_Free(State);
            }

            return Poly1305MAC;
        }
    }
}
