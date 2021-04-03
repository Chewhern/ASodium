namespace LibSodiumBinding
{
    partial class ScalarMultDemo
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
            this.BaseBTN = new System.Windows.Forms.Button();
            this.MultBTN = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // BaseBTN
            // 
            this.BaseBTN.Location = new System.Drawing.Point(13, 13);
            this.BaseBTN.Name = "BaseBTN";
            this.BaseBTN.Size = new System.Drawing.Size(248, 71);
            this.BaseBTN.TabIndex = 0;
            this.BaseBTN.Text = "Base(Generate Public Key)";
            this.BaseBTN.UseVisualStyleBackColor = true;
            this.BaseBTN.Click += new System.EventHandler(this.BaseBTN_Click);
            // 
            // MultBTN
            // 
            this.MultBTN.Location = new System.Drawing.Point(13, 118);
            this.MultBTN.Name = "MultBTN";
            this.MultBTN.Size = new System.Drawing.Size(248, 71);
            this.MultBTN.TabIndex = 1;
            this.MultBTN.Text = "Mult(Compute Shared Secret)";
            this.MultBTN.UseVisualStyleBackColor = true;
            this.MultBTN.Click += new System.EventHandler(this.MultBTN_Click);
            // 
            // ScalarMultDemo
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.MultBTN);
            this.Controls.Add(this.BaseBTN);
            this.Name = "ScalarMultDemo";
            this.Text = "ScalarMultDemo";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button BaseBTN;
        private System.Windows.Forms.Button MultBTN;
    }
}