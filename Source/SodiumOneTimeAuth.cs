using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
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
            Byte[] Key = new Byte[GetKeyBytesLength()];

            SodiumOneTimeAuthLibrary.crypto_onetimeauth_keygen(Key);

            Boolean IsZero = true;
            IntPtr KeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero,Key.Length);
            GCHandle MyGeneralGCHandle = new GCHandle();

            if (IsZero == false) 
            {
                Marshal.Copy(Key, 0, KeyIntPtr, Key.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(KeyIntPtr);
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                return KeyIntPtr;
            }
            else 
            {
                MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
                SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
                MyGeneralGCHandle.Free();
                return IntPtr.Zero;
            }
        }

        public static Byte[] ComputePoly1305MAC(Byte[] Message,Byte[] Key) 
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

            return Poly1305MAC;
        }

        public static Boolean VerifyPoly1305MAC(Byte[] Poly1305MAC, Byte[] Message, Byte[] Key) 
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

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            if (result != 0) 
            {
                return false;
            }
            else 
            {
                return true;
            }
        }

        public static Byte[] InitializeState(Byte[] Key) 
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

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(Key, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Key.Length);
            MyGeneralGCHandle.Free();

            return State;
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

        public static Byte[] ComputeFinalizedStatePoly1305MAC(Byte[] State) 
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

            return Poly1305MAC;
        }
    }
}
