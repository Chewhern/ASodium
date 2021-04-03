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
    public partial class ScryptSalsa208SHA256Demo : Form
    {
        public ScryptSalsa208SHA256Demo()
        {
            InitializeComponent();
        }

        private void PBKDF2BTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPassword = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashScryptSalsa208SHA256.GenerateSalt();
            Byte[] DerivedKey = SodiumPasswordHashScryptSalsa208SHA256.PBKDF2(32, RandomPassword, Salt);
        }

        private void CustomPBKDF2BTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPassword = SodiumRNG.GetRandomBytes(128);
            Byte[] Salt = SodiumPasswordHashScryptSalsa208SHA256.GenerateSalt();
            Byte[] DerivedKey = SodiumPasswordHashScryptSalsa208SHA256.CustomPBKDF2(32, RandomPassword, Salt, 1048576 ,33554432);
        }

        private void PasswordHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPassword = SodiumRNG.GetRandomBytes(128);
            String HashedPasswordWithParams = SodiumPasswordHashScryptSalsa208SHA256.ComputePasswordHash(RandomPassword);
            Boolean VerifyPassword = SodiumPasswordHashScryptSalsa208SHA256.VerifyPassword(HashedPasswordWithParams,RandomPassword);
        }

        private void CustomPasswordHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPassword = SodiumRNG.GetRandomBytes(128);
            String HashedPasswordWithParams = SodiumPasswordHashScryptSalsa208SHA256.CustomComputePasswordHash(RandomPassword, 1048576, 33554432);
            Boolean VerifyPassword = SodiumPasswordHashScryptSalsa208SHA256.VerifyPassword(HashedPasswordWithParams, RandomPassword);
        }

        private void PasswordHashWithParamsNeedsReHashBTN_Click(object sender, EventArgs e)
        {
            Byte[] RandomPassword = SodiumRNG.GetRandomBytes(128);
            String HashedPasswordWithParams = SodiumPasswordHashScryptSalsa208SHA256.ComputePasswordHash(RandomPassword);
            int NeedsRehash = SodiumPasswordHashScryptSalsa208SHA256.HashedPasswordWithParamsNeedReHash(HashedPasswordWithParams);
            MessageBox.Show(NeedsRehash.ToString());
        }
    }
}
