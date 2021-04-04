namespace LibSodiumBinding
{
    partial class OneTimeAuthDemo
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
            this.GenerateMACBTN = new System.Windows.Forms.Button();
            this.GenerateMPMMACBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // GenerateMACBTN
            // 
            this.GenerateMACBTN.Location = new System.Drawing.Point(13, 13);
            this.GenerateMACBTN.Name = "GenerateMACBTN";
            this.GenerateMACBTN.Size = new System.Drawing.Size(218, 74);
            this.GenerateMACBTN.TabIndex = 0;
            this.GenerateMACBTN.Text = "Generate MAC";
            this.GenerateMACBTN.UseVisualStyleBackColor = true;
            this.GenerateMACBTN.Click += new System.EventHandler(this.GenerateMACBTN_Click);
            // 
            // GenerateMPMMACBTN
            // 
            this.GenerateMPMMACBTN.Location = new System.Drawing.Point(13, 121);
            this.GenerateMPMMACBTN.Name = "GenerateMPMMACBTN";
            this.GenerateMPMMACBTN.Size = new System.Drawing.Size(218, 74);
            this.GenerateMPMMACBTN.TabIndex = 1;
            this.GenerateMPMMACBTN.Text = "Generate MPM MAC";
            this.GenerateMPMMACBTN.UseVisualStyleBackColor = true;
            this.GenerateMPMMACBTN.Click += new System.EventHandler(this.GenerateMPMMACBTN_Click);
            // 
            // OneTimeAuthDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.GenerateMPMMACBTN);
            this.Controls.Add(this.GenerateMACBTN);
            this.Name = "OneTimeAuthDemo";
            this.Text = "OneTimeAuthDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button GenerateMACBTN;
        private System.Windows.Forms.Button GenerateMPMMACBTN;
    }
}