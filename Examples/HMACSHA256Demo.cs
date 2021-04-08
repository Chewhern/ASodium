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
    public partial class HMACSHA256Demo : Form
    {
        public HMACSHA256Demo()
        {
            InitializeComponent();
        }

        private void ComputeVerifyHMACBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumHMACSHA256.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(22);
            Byte[] ComputedHMAC = SodiumHMACSHA256.ComputeMAC(RandomMessage, Key);
            Boolean VerifyHMAC = SodiumHMACSHA256.VerifyMAC(ComputedHMAC, RandomMessage, Key);
            MessageBox.Show(VerifyHMAC.ToString());
        }
    }
}
