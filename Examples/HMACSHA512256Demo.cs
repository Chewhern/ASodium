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

namespace LibSodiumBinding
{
    public partial class HMACSHA512256Demo : Form
    {
        public HMACSHA512256Demo()
        {
            InitializeComponent();
        }

        private void ComputeVerifyHMACBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumHMACSHA512256.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(22);
            Byte[] ComputedHMAC = SodiumHMACSHA512256.ComputeMAC(RandomMessage, Key);
            Boolean VerifyHMAC = SodiumHMACSHA512256.VerifyMAC(ComputedHMAC, RandomMessage, Key);
            MessageBox.Show(VerifyHMAC.ToString());
        }
    }
}
