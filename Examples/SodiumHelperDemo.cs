using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Sodium;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace LibSodiumBinding
{
    public partial class SodiumHelperDemo : Form
    {
        public SodiumHelperDemo()
        {
            InitializeComponent();
        }

        private void SecretDataCMPBTN_Click(object sender, EventArgs e)
        {
            Byte[] AuthenticationTagByte = new Byte[16];
            Byte[] SampleAuthenticationTagByte = new Byte[16];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(SampleAuthenticationTagByte);
            rngCsp.GetBytes(AuthenticationTagByte);
            IntPtr BytesArrayIntPtr1 = Marshal.AllocHGlobal(16);
            IntPtr BytesArrayIntPtr2 = Marshal.AllocHGlobal(16);
            //For this demonstration we need to assume that the source of
            //authentication tag byte gets from others...            
            //Whereby sample authentication tag byte calculated through program..
            Marshal.Copy(AuthenticationTagByte, 0, BytesArrayIntPtr1, 16);
            Marshal.Copy(SampleAuthenticationTagByte, 0, BytesArrayIntPtr2, 16);
            try 
            {
                SodiumHelper.Sodium_Memory_Compare(BytesArrayIntPtr1, BytesArrayIntPtr2, 16);
            }
            catch 
            {
                MessageBox.Show("Bytes Data Array 1 does not match with Bytes Data Array 2");
            }
        }

        private void HexaEnDeCodeBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] ResultByte = new Byte[32];
            String ResultString = "";
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            ResultString=Sodium.SodiumHelper.BinaryToHex(RandomByte);
            ResultByte = Sodium.SodiumHelper.HexToBinary(ResultString);
            MessageBox.Show(ResultByte.SequenceEqual(RandomByte).ToString());
        }

        private void B64EnDecodeBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] ResultByte = new Byte[32];
            String ResultString = "";
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            ResultString = Sodium.SodiumHelper.BinaryToBase64(RandomByte);
            ResultByte = Sodium.SodiumHelper.Base64ToBinary(ResultString,null);
            MessageBox.Show(ResultByte.SequenceEqual(RandomByte).ToString());
        }

        private void SodiumIncrementBTN_Click(object sender, EventArgs e)
        {
            MessageBox.Show("To use Sodium Increment, one must have a CPU architecture of AMD64 ASM");
            Byte[] RandomByte = new Byte[32];
            Byte[] ResultByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            ResultByte = Sodium.SodiumHelper.Sodium_Increment(RandomByte);
            MessageBox.Show(ResultByte.SequenceEqual(RandomByte).ToString());
        }

        private void SodiumAddBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] RandomByte2 = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            rngCsp.GetBytes(RandomByte2);
            Byte[] ResultByte = new Byte[32];
            ResultByte = Sodium.SodiumHelper.Sodium_Add(RandomByte, RandomByte2);
            MessageBox.Show("The addition result was "+new System.Numerics.BigInteger(ResultByte).ToString());
        }

        private void SodiumSubBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] RandomByte2 = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            rngCsp.GetBytes(RandomByte2);
            Byte[] ResultByte = new Byte[32];
            ResultByte = Sodium.SodiumHelper.Sodium_Sub(RandomByte, RandomByte2);
            MessageBox.Show("The subtraction result was " + new System.Numerics.BigInteger(ResultByte).ToString());
        }

        private void CompareNumbersBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] RandomByte2 = new Byte[32];
            int Result = 0;
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            rngCsp.GetBytes(RandomByte2);
            IntPtr myIntPtr1 = Marshal.AllocHGlobal(32);
            IntPtr myIntPtr2 = Marshal.AllocHGlobal(32);
            Marshal.Copy(RandomByte, 0, myIntPtr1, 32);
            Marshal.Copy(RandomByte2, 0, myIntPtr2, 32);
            Result = Sodium.SodiumHelper.Sodium_Compare(myIntPtr1, myIntPtr2, 32);
            if (Result == -1) 
            {
                MessageBox.Show("First number is smaller than second number");
            }
            else if(Result == 0) 
            {
                MessageBox.Show("First number is equals to second number");
            }
            else 
            {
                MessageBox.Show("First number is greater than second number");
            }
        }

        private void SodiumIsZeroBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            Byte[] ZeroByte = new Byte[32];
            int Result = 0;
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            Result = Sodium.SodiumHelper.Sodium_Is_Zero(RandomByte);
            if (Result == 1) 
            {
                MessageBox.Show("First byte array contains only zero in its elements");
            }
            else 
            {
                MessageBox.Show("First byte array does not contain only zero in its elements");
            }
            Result = Sodium.SodiumHelper.Sodium_Is_Zero(ZeroByte);
            if (Result == 1)
            {
                MessageBox.Show("Second byte array contains only zero in its elements");
            }
            else
            {
                MessageBox.Show("Second byte array does not contain only zero in its elements");
            }
        }

        private void SodiumStackZeroBTN_Click(object sender, EventArgs e)
        {
            Sodium.SodiumHelper.Sodium_StackZero(32);
        }
    }
}
