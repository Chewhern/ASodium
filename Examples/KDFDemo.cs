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
    public partial class KDFDemo : Form
    {
        public KDFDemo()
        {
            InitializeComponent();
        }

        private void KDFBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomLongKey = SodiumRNG.GetRandomBytes(128);
            Byte[] SubKey = SodiumKDF.KDFFunction(32, 3, "For Demo", RandomLongKey);
            MessageBox.Show("Derived Key = " + new System.Numerics.BigInteger(SubKey).ToString());
        }
    }
}
