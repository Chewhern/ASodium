using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using ASodium;

namespace LibSodiumBinding
{
    public partial class ShortHashDemo : Form
    {
        public ShortHashDemo()
        {
            InitializeComponent();
        }

        private void ComputeHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumShortHash.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] ComputedHash = SodiumShortHash.ComputeHash(RandomMessage, Key);
        }

        private void ComputeHashVariantBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumShortHash.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] ComputedHash = SodiumShortHash.SipHash_2_4ComputeHash(RandomMessage, Key);
        }
    }
}
