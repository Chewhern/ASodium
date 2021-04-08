namespace LibSodiumBinding
{
    partial class ConvertDSAToDHDemo
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
            this.ConvertDSASKToDHSKBTN = new System.Windows.Forms.Button();
            this.ConvertDSAPKToDHPKBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // ConvertDSASKToDHSKBTN
            // 
            this.ConvertDSASKToDHSKBTN.Location = new System.Drawing.Point(13, 13);
            this.ConvertDSASKToDHSKBTN.Name = "ConvertDSASKToDHSKBTN";
            this.ConvertDSASKToDHSKBTN.Size = new System.Drawing.Size(306, 79);
            this.ConvertDSASKToDHSKBTN.TabIndex = 0;
            this.ConvertDSASKToDHSKBTN.Text = "Convert ED25519SK To X25519SK";
            this.ConvertDSASKToDHSKBTN.UseVisualStyleBackColor = true;
            this.ConvertDSASKToDHSKBTN.Click += new System.EventHandler(this.ConvertDSASKToDHSKBTN_Click);
            // 
            // ConvertDSAPKToDHPKBTN
            // 
            this.ConvertDSAPKToDHPKBTN.Location = new System.Drawing.Point(13, 121);
            this.ConvertDSAPKToDHPKBTN.Name = "ConvertDSAPKToDHPKBTN";
            this.ConvertDSAPKToDHPKBTN.Size = new System.Drawing.Size(306, 79);
            this.ConvertDSAPKToDHPKBTN.TabIndex = 1;
            this.ConvertDSAPKToDHPKBTN.Text = "Convert ED25519PK To X25519PK";
            this.ConvertDSAPKToDHPKBTN.UseVisualStyleBackColor = true;
            this.ConvertDSAPKToDHPKBTN.Click += new System.EventHandler(this.ConvertDSAPKToDHPKBTN_Click);
            // 
            // ConvertDSAToDHDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.ConvertDSAPKToDHPKBTN);
            this.Controls.Add(this.ConvertDSASKToDHSKBTN);
            this.Name = "ConvertDSAToDHDemo";
            this.Text = "ConvertDSAToDHDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button ConvertDSASKToDHSKBTN;
        private System.Windows.Forms.Button ConvertDSAPKToDHPKBTN;
    }
}