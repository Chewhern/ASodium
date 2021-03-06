using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using ASodium;

namespace LibSodiumBinding
{
    public partial class SodiumRNGDemo : Form
    {
        public SodiumRNGDemo()
        {
            InitializeComponent();
        }

        private void RandomUIntNumberGenBTN_Click(object sender, EventArgs e)
        {
            uint MyRNGNumber = SodiumRNG.GetRandomNumber();
            MessageBox.Show(MyRNGNumber.ToString());
        }

        private void GetUpperBoundRNGUIntBTN_Click(object sender, EventArgs e)
        {
            uint MyRNGNumber = SodiumRNG.GetUniformUpperBoundRandomNumber(32);
            MessageBox.Show(MyRNGNumber.ToString());
        }

        private void RNGBytesBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = SodiumRNG.GetRandomBytes(32);
            MessageBox.Show(new System.Numerics.BigInteger(RandomByte).ToString());
        }

        private void GetSeedLengthBTN_Click(object sender, EventArgs e)
        {
            int SeedLength = SodiumRNG.GetSeedBytesValue();
            MessageBox.Show(SeedLength.ToString());
        }

        private void GetSeededRNGBytesBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomByte = new Byte[32];
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            rngCsp.GetBytes(RandomByte);
            Byte[] SeededRandomByte = new Byte[32];
            SeededRandomByte = SodiumRNG.GetSeededRandomBytes(128, RandomByte);
            MessageBox.Show(new System.Numerics.BigInteger(SeededRandomByte).ToString());
        }
    }
}
