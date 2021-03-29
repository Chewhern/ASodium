using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Sodium
{
    public static class SodiumPublicKeyAuthMPM
    {
        public static int GetStateBytesLength() 
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_statebytes();
        }

        public static int GetPublicKeyBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_publickeybytes();
        }

        public static int GetSecretKeyBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_secretkeybytes();
        }

        public static int GetSignatureBytesLength()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_bytes();
        }

        public static Byte GetPrimitiveByte()
        {
            return SodiumPublicKeyAuthLibrary.crypto_sign_primitive();
        }

        public static Byte[] InitializeState() 
        {
            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_init(State);

            if (result != 0) 
            {
                throw new Exception("Error: Failed to initialize state");
            }
            return State;
        }

        public static Byte[] UpdateState(Byte[] OldState,Byte[] Message) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message cannot be null");
            }

            if (OldState == null)
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else
            {
                if (OldState.LongLength != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be "+GetStateBytesLength()+" bytes in length");
                }
            }

            Byte[] NewState = OldState;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_update(NewState, Message, Message.LongLength);

            if (result != 0) 
            {
                throw new Exception("Error: Failed to update state");
            }

            return NewState;
        }

        public static Byte[] SignFinalState(Byte[] State,Byte[] SecretKey) 
        {
            Byte[] Signature = new Byte[GetSignatureBytesLength()];
            long SignatureLength = 0;

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_final_create(State, Signature, SignatureLength, SecretKey);

            if (result != 0)
            {
                throw new CryptographicException("Error: Failed to sign state and create signature");
            }

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(SecretKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), SecretKey.Length);
            MyGeneralGCHandle.Free();

            return Signature;
        }

        public static Boolean VerifySignedFinalState(Byte[] State, Byte[] Signature , Byte[] PublicKey)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State cannot be null");
            }
            else
            {
                if (State.LongLength != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State length must be " + GetStateBytesLength() + " bytes in length");
                }
            }

            if (Signature == null)
            {
                throw new ArgumentException("Error: Signature cannot be null");
            }
            else
            {
                if (Signature.LongLength != GetSignatureBytesLength())
                {
                    throw new ArgumentException("Error: Signature length must be " + GetSignatureBytesLength() + " bytes in length");
                }
            }

            if (PublicKey == null)
            {
                throw new ArgumentException("Error: Public Key cannot be null");
            }
            else
            {
                if (PublicKey.LongLength != GetPublicKeyBytesLength())
                {
                    throw new ArgumentException("Error: Public Key length must be " + GetPublicKeyBytesLength() + " bytes in length");
                }
            }

            int result = SodiumPublicKeyAuthLibrary.crypto_sign_final_verify(State, Signature, PublicKey);

            if (result != 0) 
            {
                return false;
            }
            else 
            {
                return true;
            }
        }
    }
}
