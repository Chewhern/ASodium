namespace LibSodiumBinding
{
    partial class KDFDemo
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
            this.KDFBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // KDFBTN
            // 
            this.KDFBTN.Location = new System.Drawing.Point(13, 13);
            this.KDFBTN.Name = "KDFBTN";
            this.KDFBTN.Size = new System.Drawing.Size(204, 76);
            this.KDFBTN.TabIndex = 0;
            this.KDFBTN.Text = "KDF ";
            this.KDFBTN.UseVisualStyleBackColor = true;
            this.KDFBTN.Click += new System.EventHandler(this.KDFBTN_Click);
            // 
            // KDFDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(856, 487);
            this.Controls.Add(this.KDFBTN);
            this.Name = "KDFDemo";
            this.Text = "KDFDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button KDFBTN;
    }
}