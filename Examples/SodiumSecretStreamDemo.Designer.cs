namespace LibSodiumBinding
{
    partial class SodiumSecretStreamDemo
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.StreamEncryptBTN = new System.Windows.Forms.Button();
            this.StreamDecryptBTN = new System.Windows.Forms.Button();
            this.FileEncryptionBTN = new System.Windows.Forms.Button();
            this.FileDecryptionBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // StreamEncryptBTN
            // 
            this.StreamEncryptBTN.Location = new System.Drawing.Point(13, 13);
            this.StreamEncryptBTN.Name = "StreamEncryptBTN";
            this.StreamEncryptBTN.Size = new System.Drawing.Size(220, 72);
            this.StreamEncryptBTN.TabIndex = 0;
            this.StreamEncryptBTN.Text = "Stream Encryption";
            this.StreamEncryptBTN.UseVisualStyleBackColor = true;
            this.StreamEncryptBTN.Click += new System.EventHandler(this.StreamEncryptBTN_Click);
            // 
            // StreamDecryptBTN
            // 
            this.StreamDecryptBTN.Location = new System.Drawing.Point(13, 115);
            this.StreamDecryptBTN.Name = "StreamDecryptBTN";
            this.StreamDecryptBTN.Size = new System.Drawing.Size(220, 72);
            this.StreamDecryptBTN.TabIndex = 1;
            this.StreamDecryptBTN.Text = "Stream Decryption";
            this.StreamDecryptBTN.UseVisualStyleBackColor = true;
            this.StreamDecryptBTN.Click += new System.EventHandler(this.StreamDecryptBTN_Click);
            // 
            // FileEncryptionBTN
            // 
            this.FileEncryptionBTN.Location = new System.Drawing.Point(264, 13);
            this.FileEncryptionBTN.Name = "FileEncryptionBTN";
            this.FileEncryptionBTN.Size = new System.Drawing.Size(220, 72);
            this.FileEncryptionBTN.TabIndex = 2;
            this.FileEncryptionBTN.Text = "File Encryption";
            this.FileEncryptionBTN.UseVisualStyleBackColor = true;
            this.FileEncryptionBTN.Click += new System.EventHandler(this.FileEncryptionBTN_Click);
            // 
            // FileDecryptionBTN
            // 
            this.FileDecryptionBTN.Location = new System.Drawing.Point(264, 115);
            this.FileDecryptionBTN.Name = "FileDecryptionBTN";
            this.FileDecryptionBTN.Size = new System.Drawing.Size(220, 72);
            this.FileDecryptionBTN.TabIndex = 3;
            this.FileDecryptionBTN.Text = "File Decryption";
            this.FileDecryptionBTN.UseVisualStyleBackColor = true;
            this.FileDecryptionBTN.Click += new System.EventHandler(this.FileDecryptionBTN_Click);
            // 
            // SodiumSecretStreamDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(879, 496);
            this.Controls.Add(this.FileDecryptionBTN);
            this.Controls.Add(this.FileEncryptionBTN);
            this.Controls.Add(this.StreamDecryptBTN);
            this.Controls.Add(this.StreamEncryptBTN);
            this.Name = "SodiumSecretStreamDemo";
            this.Text = "SodiumSecretStreamDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button StreamEncryptBTN;
        private System.Windows.Forms.Button StreamDecryptBTN;
        private System.Windows.Forms.Button FileEncryptionBTN;
        private System.Windows.Forms.Button FileDecryptionBTN;
    }
}