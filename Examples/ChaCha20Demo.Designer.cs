namespace LibSodiumBinding
{
    partial class ChaCha20Demo
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
            this.EncryptBTN = new System.Windows.Forms.Button();
            this.EncryptIETFBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // EncryptBTN
            // 
            this.EncryptBTN.Location = new System.Drawing.Point(13, 13);
            this.EncryptBTN.Name = "EncryptBTN";
            this.EncryptBTN.Size = new System.Drawing.Size(214, 83);
            this.EncryptBTN.TabIndex = 0;
            this.EncryptBTN.Text = "Encrypt";
            this.EncryptBTN.UseVisualStyleBackColor = true;
            this.EncryptBTN.Click += new System.EventHandler(this.EncryptBTN_Click);
            // 
            // EncryptIETFBTN
            // 
            this.EncryptIETFBTN.Location = new System.Drawing.Point(13, 124);
            this.EncryptIETFBTN.Name = "EncryptIETFBTN";
            this.EncryptIETFBTN.Size = new System.Drawing.Size(214, 83);
            this.EncryptIETFBTN.TabIndex = 1;
            this.EncryptIETFBTN.Text = "Encrypt IETF";
            this.EncryptIETFBTN.UseVisualStyleBackColor = true;
            this.EncryptIETFBTN.Click += new System.EventHandler(this.EncryptIETFBTN_Click);
            // 
            // ChaCha20Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.EncryptIETFBTN);
            this.Controls.Add(this.EncryptBTN);
            this.Name = "ChaCha20Demo";
            this.Text = "ChaCha20Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button EncryptBTN;
        private System.Windows.Forms.Button EncryptIETFBTN;
    }
}