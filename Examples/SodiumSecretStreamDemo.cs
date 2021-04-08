using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;
using ASodium;

namespace LibSodiumBinding
{
    public partial class SodiumSecretStreamDemo : Form
    {
        public SodiumSecretStreamDemo()
        {
            InitializeComponent();
        }

        private void StreamEncryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretStreamKey = SodiumSecretStream.KeyGen();
            String Message1 = "Arbitrary data to encrypt";
            Byte[] Message1Byte = Encoding.UTF8.GetBytes(Message1);
            Byte[] CipherText1 = new Byte[SodiumSecretStream.GetABytesLength() + Message1Byte.Length];
            String Message2 = "split into";
            Byte[] Message2Byte = Encoding.UTF8.GetBytes(Message2);
            Byte[] CipherText2 = new Byte[SodiumSecretStream.GetABytesLength() + Message2Byte.Length];
            String Message3 = "three messages";
            Byte[] Message3Byte = Encoding.UTF8.GetBytes(Message3);
            Byte[] CipherText3 = new Byte[SodiumSecretStream.GetABytesLength() + Message3Byte.Length];
            SecretStreamInitPushBox MyInitPushBoxStream = new SecretStreamInitPushBox();
            MyInitPushBoxStream = SodiumSecretStream.SecretStreamInitPush(SecretStreamKey);
            SecretStreamPushBox MyPushBox1 = new SecretStreamPushBox();
            SecretStreamPushBox MyPushBox2 = new SecretStreamPushBox();
            SecretStreamPushBox MyPushBox3 = new SecretStreamPushBox();
            MyPushBox1 = SodiumSecretStream.SecretStreamPush(MyInitPushBoxStream.StateByte, Message1Byte, null, 0, SodiumSecretStream.GetTagMessageByte());
            MyPushBox2 = SodiumSecretStream.SecretStreamPush(MyPushBox1.StateByte, Message2Byte, null, 0, SodiumSecretStream.GetTagMessageByte());
            MyPushBox3 = SodiumSecretStream.SecretStreamPush(MyPushBox2.StateByte, Message3Byte, null, 0, SodiumSecretStream.GetTagFinalByte());
        }

        private void StreamDecryptBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretStreamKey = SodiumSecretStream.KeyGen();
            String Message1 = "Arbitrary data to encrypt";
            Byte[] Message1Byte = Encoding.UTF8.GetBytes(Message1);
            Byte[] CipherText1 = new Byte[SodiumSecretStream.GetABytesLength() + Message1Byte.Length];
            String Message2 = "split into";
            Byte[] Message2Byte = Encoding.UTF8.GetBytes(Message2);
            Byte[] CipherText2 = new Byte[SodiumSecretStream.GetABytesLength() + Message2Byte.Length];
            String Message3 = "three messages";
            Byte[] Message3Byte = Encoding.UTF8.GetBytes(Message3);
            Byte[] CipherText3 = new Byte[SodiumSecretStream.GetABytesLength() + Message3Byte.Length];
            Byte[] DecryptedMessage1Byte = new Byte[Message1Byte.LongLength];
            Byte[] DecryptedMessage2Byte = new Byte[Message2Byte.LongLength];
            Byte[] DecryptedMessage3Byte = new Byte[Message3Byte.LongLength];
            SecretStreamInitPushBox MyInitPushBoxStream = new SecretStreamInitPushBox();
            MyInitPushBoxStream = SodiumSecretStream.SecretStreamInitPush(SecretStreamKey);
            SecretStreamPushBox MyPushBox1 = new SecretStreamPushBox();
            SecretStreamPushBox MyPushBox2 = new SecretStreamPushBox();
            SecretStreamPushBox MyPushBox3 = new SecretStreamPushBox();
            MyPushBox1 = SodiumSecretStream.SecretStreamPush(MyInitPushBoxStream.StateByte, Message1Byte, null, 0, SodiumSecretStream.GetTagMessageByte());
            MyPushBox2 = SodiumSecretStream.SecretStreamPush(MyPushBox1.StateByte, Message2Byte, null, 0, SodiumSecretStream.GetTagMessageByte());
            MyPushBox3 = SodiumSecretStream.SecretStreamPush(MyPushBox2.StateByte, Message3Byte, null, 0, SodiumSecretStream.GetTagFinalByte());
            Byte[] StateByte = SodiumSecretStream.SecretStreamInitPull(MyInitPushBoxStream.HeaderByte,SecretStreamKey);
            Byte TagByte=0;
            SecretStreamPullBox MyPullBox1 = new SecretStreamPullBox();
            SecretStreamPullBox MyPullBox2 = new SecretStreamPullBox();
            SecretStreamPullBox MyPullBox3 = new SecretStreamPullBox();
            MyPullBox1 = SodiumSecretStream.SecretStreamPull(StateByte, TagByte, MyPushBox1.CipherText, null, 0);
            MyPullBox2 = SodiumSecretStream.SecretStreamPull(MyPullBox1.StateByte, MyPullBox1.TagByte, MyPushBox2.CipherText, null, 0);
            MyPullBox3 = SodiumSecretStream.SecretStreamPull(MyPullBox2.StateByte, MyPullBox2.TagByte, MyPushBox3.CipherText, null, 0);
        }

        private void FileEncryptionBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretStreamKey = SodiumSecretStream.KeyGen();
            Byte[] MessageByte = new Byte[] { };
            Byte SampleTag = 0;
            FileStream MessageFileStream = File.OpenRead(Application.StartupPath + "\\Message.txt");
            long MessageFileLengthInBytes = MessageFileStream.Length;
            long CurrentCount = 128;
            int LoopCount = 1;
            int EndOfFile = 0;
            FileStream CipherTextFileStream = File.OpenWrite(Application.StartupPath + "\\CipherText.txt");
            SecretStreamInitPushBox MyInitPushBox = new SecretStreamInitPushBox();
            MyInitPushBox = SodiumSecretStream.SecretStreamInitPush(SecretStreamKey);
            SecretStreamPushBox MyPushBox = new SecretStreamPushBox();
            CipherTextFileStream.Write(MyInitPushBox.HeaderByte, 0, MyInitPushBox.HeaderByte.Length);
            while (CurrentCount <= MessageFileLengthInBytes) 
            {
                MessageByte = new Byte[128];
                EndOfFile = MessageFileStream.Read(MessageByte, 0, 128);

                if(CurrentCount == MessageFileLengthInBytes) 
                {
                    SampleTag = SodiumSecretStream.GetTagFinalByte();
                    if (LoopCount == 1) 
                    {
                        MyPushBox = SodiumSecretStream.SecretStreamPush(MyInitPushBox.StateByte, MessageByte, null, 0, SampleTag);
                        CipherTextFileStream.Write(MyPushBox.CipherText, 0, MyPushBox.CipherText.Length);
                    }
                    else 
                    {
                        MyPushBox = SodiumSecretStream.SecretStreamPush(MyPushBox.StateByte, MessageByte, null, 0, SampleTag);
                        CipherTextFileStream.Write(MyPushBox.CipherText, 0, MyPushBox.CipherText.Length);
                    }
                    break;
                }
                else 
                {
                    if (LoopCount == 1)
                    {
                        MyPushBox = SodiumSecretStream.SecretStreamPush(MyInitPushBox.StateByte, MessageByte, null, 0, SodiumSecretStream.GetTagMessageByte());
                        CipherTextFileStream.Write(MyPushBox.CipherText, 0, MyPushBox.CipherText.Length);
                    }
                    else
                    {
                        MyPushBox = SodiumSecretStream.SecretStreamPush(MyPushBox.StateByte, MessageByte, null, 0, SodiumSecretStream.GetTagMessageByte());
                        CipherTextFileStream.Write(MyPushBox.CipherText, 0, MyPushBox.CipherText.Length);
                    }
                }
                LoopCount += 1;
                CurrentCount *= 2;
            }
            File.WriteAllBytes(Application.StartupPath + "\\Key.txt",SecretStreamKey);
            MessageFileStream.Close();
            CipherTextFileStream.Close();
        }

        private void FileDecryptionBTN_Click(object sender, EventArgs e)
        {
            Byte[] SecretStreamKey = File.ReadAllBytes(Application.StartupPath + "\\Key.txt");
            Byte[] SecretStreamHeader = new Byte[SodiumSecretStream.GetHeaderBytesLength()];
            Byte[] StateByte = new Byte[] { };
            Byte[] CipherText = new Byte[128 + SodiumSecretStream.GetABytesLength()];
            Byte SampleTag = SodiumSecretStream.GetTagMessageByte();
            FileStream CipherTextFileStream = File.OpenRead(Application.StartupPath + "\\CipherText.txt");
            long TotalCipherText = 0;
            long CurrentCount = 128 + SodiumSecretStream.GetABytesLength();
            int LoopCount = 1;
            FileStream PlainTextFileStream = File.OpenWrite(Application.StartupPath + "\\PlainText.txt");
            SecretStreamPullBox MyPullBox = new SecretStreamPullBox();
            CipherTextFileStream.Read(SecretStreamHeader, 0, SodiumSecretStream.GetHeaderBytesLength());
            StateByte = SodiumSecretStream.SecretStreamInitPull(SecretStreamHeader, SecretStreamKey);
            TotalCipherText = CipherTextFileStream.Length - SecretStreamHeader.Length;
            do
            {
                CipherText = new Byte[128 + SodiumSecretStream.GetABytesLength()];
                CipherTextFileStream.Read(CipherText, 0, CipherText.Length);
                if (CurrentCount==TotalCipherText) 
                {
                    if (LoopCount == 1) 
                    {
                        MyPullBox = SodiumSecretStream.SecretStreamPull(StateByte, SampleTag, CipherText, null, 0);
                        PlainTextFileStream.Write(MyPullBox.MessageByte, 0, MyPullBox.MessageByte.Length);
                    }
                    else 
                    {
                        MyPullBox = SodiumSecretStream.SecretStreamPull(MyPullBox.StateByte, SampleTag, CipherText, null, 0);
                        PlainTextFileStream.Write(MyPullBox.MessageByte, 0, MyPullBox.MessageByte.Length);
                    }
                }
                else 
                {
                    if (LoopCount == 1)
                    {
                        MyPullBox = SodiumSecretStream.SecretStreamPull(StateByte, SampleTag, CipherText, null, 0);
                        PlainTextFileStream.Write(MyPullBox.MessageByte, 0, MyPullBox.MessageByte.Length);
                    }
                    else
                    {
                        MyPullBox = SodiumSecretStream.SecretStreamPull(MyPullBox.StateByte, SampleTag, CipherText, null, 0);
                        PlainTextFileStream.Write(MyPullBox.MessageByte, 0, MyPullBox.MessageByte.Length);
                    }
                }

                CurrentCount *= 2;
                LoopCount += 1;
            }
            while (CurrentCount<=TotalCipherText);
            PlainTextFileStream.Close();
            CipherTextFileStream.Close();
        }
    }
}
