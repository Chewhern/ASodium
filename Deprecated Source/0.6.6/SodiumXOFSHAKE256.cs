using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ASodium
{
    public static class SodiumXOFSHAKE256
    {
        public static int GetBlockBytesLength()
        {
            return SodiumXOFSHAKE256Library.crypto_xof_shake256_blockbytes();
        }

        public static int GetStateBytesLength()
        {
            return SodiumXOFSHAKE256Library.crypto_xof_shake256_statebytes();
        }

        public static Byte GetDomainStandardByte()
        {
            return SodiumXOFSHAKE256Library.crypto_xof_shake256_domain_standard();
        }

        public static Byte[] ComputeHash(Byte[] Message, long HashedMessageLength)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null/empty");
            }
            if (HashedMessageLength == 0)
            {
                throw new ArgumentException("Error: Hashed message length must not be 0");
            }

            Byte[] HashedMessage = new Byte[HashedMessageLength];
            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256(HashedMessage, HashedMessageLength, Message, Message.LongLength);

            return HashedMessage;
        }

        public static Byte[] InitStateBytes()
        {
            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_init(State);

            return State;
        }

        public static IntPtr InitStateIntPtr()
        {
            Boolean IsZero = false;
            IntPtr State = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStateBytesLength());

            if (IsZero == false)
            {
                int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_init(State);
            }
            else
            {
                State = IntPtr.Zero;
            }

            return State;
        }

        public static Byte[] InitStateBytesWithCustomDomainByte(Byte CustomDomainByte)
        {
            if ((CustomDomainByte >= 0x01 && CustomDomainByte <= 0x7F) == false)
            {
                throw new ArgumentException("Error: Custom Domain Byte must be in the range of 0x01 to 0x7F");
            }

            Byte[] State = new Byte[GetStateBytesLength()];

            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_init_with_domain(State, CustomDomainByte);

            return State;
        }

        public static IntPtr InitStateIntPtrWithCustomDomainByte(Byte CustomDomainByte)
        {
            if ((CustomDomainByte >= 0x01 && CustomDomainByte <= 0x7F) == false)
            {
                throw new ArgumentException("Error: Custom Domain Byte must be in the range of 0x01 to 0x7F");
            }

            Boolean IsZero = false;
            IntPtr State = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, GetStateBytesLength());

            if (IsZero == false)
            {
                int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_init_with_domain(State, CustomDomainByte);
            }
            else
            {
                State = IntPtr.Zero;
            }

            return State;
        }

        public static Byte[] UpdateState(Byte[] State, Byte[] DataStream, Boolean ClearKey = false)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State must not be empty/null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State must be " + GetStateBytesLength() + " bytes in length");
                }
            }

            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_update(State, DataStream, DataStream.LongLength);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(DataStream);
            }

            return State;
        }

        public static IntPtr UpdateState(IntPtr State, IntPtr SecretDataStream, long SecretDataStreamLength, Boolean ClearKey = false)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State must not be empty/null");
            }
            if (SecretDataStream == IntPtr.Zero)
            {
                throw new ArgumentException("Error: Secret data stream must not be empty/null");
            }

            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
            SodiumGuardedHeapAllocation.Sodium_MProtect_ReadOnly(SecretDataStream);
            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_update(State, SecretDataStream, SecretDataStreamLength);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretDataStream);
            SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(SecretDataStream);
                SodiumGuardedHeapAllocation.Sodium_Free(SecretDataStream);
            }

            return State;
        }

        public static Byte[] SqueezeData(Byte[] State, long SqueezedDataLength, Boolean ClearKey = false)
        {
            if (State == null)
            {
                throw new ArgumentException("Error: State must not be empty/null");
            }
            else
            {
                if (State.Length != GetStateBytesLength())
                {
                    throw new ArgumentException("Error: State must be " + GetStateBytesLength() + " bytes in length");
                }
            }
            if (SqueezedDataLength == 0)
            {
                throw new ArgumentException("Error: Squeezed data length must not be 0");
            }
            Byte[] SqueezedData = new Byte[SqueezedDataLength];

            int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_squeeze(State, SqueezedData, SqueezedDataLength);

            if (ClearKey)
            {
                SodiumSecureMemory.SecureClearBytes(State);
            }

            return SqueezedData;
        }

        public static IntPtr SqueezeData(IntPtr State, long SqueezedDataLength, Boolean ClearKey = false)
        {
            if (State == IntPtr.Zero)
            {
                throw new ArgumentException("Error: State must not be empty/null");
            }
            if (SqueezedDataLength == 0)
            {
                throw new ArgumentException("Error: Squeezed data length must not be 0");
            }
            Boolean IsZero = false;
            IntPtr SqueezedData = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero, SqueezedDataLength);

            if (IsZero == false)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
                int result = SodiumXOFSHAKE256Library.crypto_xof_shake256_squeeze(State, SqueezedData, SqueezedDataLength);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(State);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SqueezedData);
            }
            else
            {
                SqueezedData = IntPtr.Zero;
            }

            if (ClearKey)
            {
                SodiumGuardedHeapAllocation.Sodium_MProtect_ReadWrite(State);
                SodiumGuardedHeapAllocation.Sodium_Free(State);
            }
            return SqueezedData;
        }
    }
}
