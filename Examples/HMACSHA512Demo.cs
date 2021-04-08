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
    public partial class HMACSHA512Demo : Form
    {
        public HMACSHA512Demo()
        {
            InitializeComponent();
        }

        private void ComputeVerifyHMACBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumHMACSHA512.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(22);
            Byte[] ComputedHMAC = SodiumHMACSHA512.ComputeMAC(RandomMessage, Key);
            Boolean VerifyHMAC = SodiumHMACSHA512.VerifyMAC(ComputedHMAC, RandomMessage, Key);
            MessageBox.Show(VerifyHMAC.ToString());
        }
    }
}
