namespace LibSodiumBinding
{
    partial class Salsa20Demo
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
            this.SuspendLayout();
            // 
            // EncryptBTN
            // 
            this.EncryptBTN.Location = new System.Drawing.Point(13, 13);
            this.EncryptBTN.Name = "EncryptBTN";
            this.EncryptBTN.Size = new System.Drawing.Size(211, 73);
            this.EncryptBTN.TabIndex = 0;
            this.EncryptBTN.Text = "Encrypt";
            this.EncryptBTN.UseVisualStyleBackColor = true;
            this.EncryptBTN.Click += new System.EventHandler(this.EncryptBTN_Click);
            // 
            // Salsa20Demo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.EncryptBTN);
            this.Name = "Salsa20Demo";
            this.Text = "Salsa20Demo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button EncryptBTN;
    }
}