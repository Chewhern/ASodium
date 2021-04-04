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
    public partial class OneTimeAuthDemo : Form
    {
        public OneTimeAuthDemo()
        {
            InitializeComponent();
        }

        private void GenerateMACBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumOneTimeAuth.GenerateKey();
            Byte[] RandomMessage = SodiumRNG.GetRandomBytes(128);
            Byte[] MAC = SodiumOneTimeAuth.ComputePoly1305MAC(RandomMessage, Key);
            Boolean Verified = SodiumOneTimeAuth.VerifyPoly1305MAC(MAC, RandomMessage, Key);
            MessageBox.Show(Verified.ToString());
        }

        private void GenerateMPMMACBTN_Click(object sender, EventArgs e)
        {
            Byte[] Key = SodiumOneTimeAuth.GenerateKey();
            Byte[] RandomMessage1 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage2 = SodiumRNG.GetRandomBytes(128);
            Byte[] RandomMessage3 = SodiumRNG.GetRandomBytes(128);
            Byte[] State = SodiumOneTimeAuth.InitializeState(Key);
            State = SodiumOneTimeAuth.UpdateState(State, RandomMessage1);
            State = SodiumOneTimeAuth.UpdateState(State, RandomMessage2);
            State = SodiumOneTimeAuth.UpdateState(State, RandomMessage3);
            Byte[] MAC = SodiumOneTimeAuth.ComputeFinalizedStatePoly1305MAC(State);
            //Need to recompute MAC on other side and sees if it matches..
        }
    }
}
