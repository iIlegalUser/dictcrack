// Gui.cs -- dictcrack-gui.exe WinForms frontend. Ports the v4/v5 flat
// design of the legacy PowerShell GUI (dark header band, blue primary
// button, slim custom progress bar, drag-drop, DPI-scaled layout) on top
// of the native C# engine, and adds the mask / combinator / rules /
// resume / benchmark surfaces. ASCII only source.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Media;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace DictCrack
{
    internal static class GuiProgram
    {
        [STAThread]
        private static void Main(string[] args)
        {
            NativeMethods.SetProcessDPIAware();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(args));
        }
    }

    internal static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();
    }

    internal sealed class MainForm : Form
    {
        private readonly string[] _args;

        // palette (port of the legacy GUI)
        private static readonly Color cBg = Color.FromArgb(247, 248, 250);
        private static readonly Color cHeader = Color.FromArgb(23, 32, 48);
        private static readonly Color cHeader2 = Color.FromArgb(148, 163, 184);
        private static readonly Color cPrimary = Color.FromArgb(37, 99, 235);
        private static readonly Color cPrimHov = Color.FromArgb(29, 78, 216);
        private static readonly Color cText = Color.FromArgb(31, 41, 55);
        private static readonly Color cSub = Color.FromArgb(107, 114, 128);
        private static readonly Color cBorder = Color.FromArgb(203, 213, 225);
        private static readonly Color cBtnHov = Color.FromArgb(243, 244, 246);
        private static readonly Color cTrack = Color.FromArgb(226, 232, 240);
        private static readonly Color cGreen = Color.FromArgb(22, 163, 74);
        private static readonly Color cGreenDk = Color.FromArgb(6, 95, 70);
        private static readonly Color cGreenBg = Color.FromArgb(236, 253, 245);
        private static readonly Color cRed = Color.FromArgb(220, 38, 38);
        private static readonly Color cOrange = Color.FromArgb(217, 119, 6);

        private readonly double _scale;
        private int S(double v) { return (int)Math.Round(v * _scale); }

        // controls
        private TextBox txtArch;
        private TextBox txtDict;
        private TextBox txtDictA;
        private TextBox txtDictB;
        private TextBox txtMask;
        private TextBox txtSet1;
        private TextBox txtSet2;
        private NumericUpDown numMin;
        private NumericUpDown numMax;
        private ComboBox cmbThreads;
        private readonly List<CheckBox> _ruleChecks = new List<CheckBox>();
        private RadioButton rbDict;
        private RadioButton rbMask;
        private RadioButton rbComb;
        private Panel pnlDict;
        private Panel pnlMask;
        private Panel pnlComb;
        private Label lblMaskSpace;
        private Label lblFormat;
        private CheckBox chkResume;
        private Panel pbTrack;
        private Panel pbFill;
        private Button btnStart;
        private Button btnStop;
        private Button btnBench;
        private Label lblStatus;
        private Label lblCurrent;
        private Label lblStats;
        private GroupBox grp;
        private TextBox txtPwd;
        private Button btnCopy;
        private Button btnMove;
        private Button btnExtract;
        private Label lblSave;

        private readonly string _cfgFile;
        private Thread _workThread;
        private CrackEngine _engine;
        private CrackResult _result;
        private System.Windows.Forms.Timer _timer;
        private readonly Stopwatch _watch = new Stopwatch();
        private readonly Stopwatch _rateTick = new Stopwatch();
        private long _rateTried;
        private double _rate;
        private bool _running;
        private string _lastDict;
        private System.Windows.Forms.Timer _spaceTimer;
        private System.Windows.Forms.Timer _formatTimer;
        private CancellationTokenSource _cts;
        private List<int> _threadValues;

        public MainForm(string[] args)
        {
            _args = args ?? new string[0];
            _cfgFile = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "dictcrack-gui.cfg");
            using (Bitmap b = new Bitmap(1, 1))
            using (Graphics g = Graphics.FromImage(b))
            {
                double d = g.DpiX / 96.0;
                _scale = d < 1.0 ? 1.0 : d;
            }
            BuildUi();
        }

        private static Label MkLabel(string text, int x, int y, int w, int h, Func<double, int> S)
        {
            Label l = new Label();
            l.Text = text;
            l.Location = new Point(S(x), S(y));
            l.Size = new Size(S(w), S(h));
            l.TextAlign = ContentAlignment.MiddleLeft;
            l.ForeColor = cSub;
            l.BackColor = Color.Transparent;
            return l;
        }

        private static Button Btn2(string text, int x, int y, int w, int h, Color fg, Func<double, int> S)
        {
            Button b = new Button();
            b.Text = text;
            b.Location = new Point(S(x), S(y));
            b.Size = new Size(S(w), S(h));
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = cBorder;
            b.FlatAppearance.MouseOverBackColor = cBtnHov;
            b.BackColor = Color.White;
            b.ForeColor = fg;
            b.Cursor = Cursors.Hand;
            b.Font = new Font("Microsoft YaHei UI", 9f);
            return b;
        }

        // ----------------------------------------------------------------
        private void BuildUi()
        {
            Func<double, int> S = this.S;
            Text = "DictCrack - 压缩包密码破解（原生引擎）";
            ClientSize = new Size(S(672), S(706));
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            BackColor = cBg;
            FormBorderStyle = FormBorderStyle.Sizable;
            AutoScaleMode = AutoScaleMode.None;
            // a 0 dimension is NOT "unlimited" here - it clamps to zero
            MaximumSize = new Size(S(1400), S(1100));

            Panel header = new Panel();
            header.Dock = DockStyle.Top;
            header.Height = S(68);
            header.BackColor = cHeader;
            Label lblTitle = new Label();
            lblTitle.Text = "DictCrack";
            lblTitle.ForeColor = Color.White;
            lblTitle.Font = new Font("Microsoft YaHei UI", 14f, FontStyle.Bold);
            lblTitle.Location = new Point(S(22), S(11));
            lblTitle.Size = new Size(S(320), S(30));
            lblTitle.BackColor = Color.Transparent;
            Label lblSub = new Label();
            lblSub.Text = "RAR5 / ZIP 原生加速 · RAR / 7Z 全格式 · 字典 / 掩码 / 组合";
            lblSub.ForeColor = cHeader2;
            lblSub.Font = new Font("Microsoft YaHei UI", 8.5f);
            lblSub.Location = new Point(S(24), S(45));
            lblSub.Size = new Size(S(520), S(18));
            lblSub.BackColor = Color.Transparent;
            header.Controls.Add(lblTitle);
            header.Controls.Add(lblSub);

            Panel content = new Panel();
            content.Dock = DockStyle.Fill;
            content.Padding = new Padding(S(20), S(10), S(20), S(8));
            content.BackColor = cBg;

            // ---- archive row ------------------------------------------
            content.Controls.Add(MkLabel("压缩包", 0, 14, 72, 24, S));
            txtArch = new TextBox();
            txtArch.Location = new Point(S(76), S(12));
            txtArch.Size = new Size(S(446), S(25));
            txtArch.ForeColor = cText;
            Button btnArch = Btn2("浏览...", 532, 9, 100, 30, cText, S);
            btnArch.Click += delegate(object s, EventArgs e)
            { Browse(txtArch, "压缩包 (*.rar;*.zip;*.7z)|*.rar;*.zip;*.7z|所有文件 (*.*)|*.*"); };
            EventHandler archChanged = delegate(object s, EventArgs e) { ScheduleFormatProbe(); };
            txtArch.TextChanged += archChanged;

            // ---- attack mode radios ------------------------------------
            rbDict = new RadioButton();
            rbDict.Text = "字典攻击";
            rbDict.Location = new Point(S(76), S(48));
            rbDict.Size = new Size(S(110), S(24));
            rbDict.ForeColor = cText;
            rbDict.BackColor = Color.Transparent;
            rbDict.Checked = true;
            rbMask = new RadioButton();
            rbMask.Text = "掩码暴力";
            rbMask.Location = new Point(S(196), S(48));
            rbMask.Size = new Size(S(110), S(24));
            rbMask.ForeColor = cText;
            rbMask.BackColor = Color.Transparent;
            rbComb = new RadioButton();
            rbComb.Text = "字典组合";
            rbComb.Location = new Point(S(316), S(48));
            rbComb.Size = new Size(S(110), S(24));
            rbComb.ForeColor = cText;
            rbComb.BackColor = Color.Transparent;
            rbDict.CheckedChanged += delegate(object s, EventArgs e) { UpdateModePanels(); };
            rbMask.CheckedChanged += delegate(object s, EventArgs e) { UpdateModePanels(); };
            rbComb.CheckedChanged += delegate(object s, EventArgs e) { UpdateModePanels(); };

            // ---- dict panel --------------------------------------------
            // children use CONTENT coordinates (panel sits at x=0), same
            // grid as the archive/threads rows: label 0-72, input 76,
            // button 532
            pnlDict = new Panel();
            pnlDict.Location = new Point(0, S(76));
            pnlDict.Size = new Size(S(632), S(156));
            pnlDict.BackColor = Color.Transparent;
            pnlDict.Controls.Add(MkLabel("字典文件", 0, 4, 72, 24, S));
            txtDict = new TextBox();
            txtDict.Location = new Point(S(76), S(2));
            txtDict.Size = new Size(S(446), S(25));
            txtDict.ForeColor = cText;
            Button btnDict = Btn2("浏览...", 532, -2, 100, 30, cText, S);
            btnDict.Click += delegate(object s, EventArgs e)
            { Browse(txtDict, "文本文件 (*.txt;*.dic;*.lst)|*.txt;*.dic;*.lst|所有文件 (*.*)|*.*"); };
            pnlDict.Controls.Add(txtDict);
            pnlDict.Controls.Add(btnDict);
            pnlDict.Controls.Add(MkLabel("变异规则", 0, 42, 72, 24, S));
            for (int i = 0; i < Rules.PresetNames.Length; i++)
            {
                CheckBox cb = new CheckBox();
                cb.Text = Rules.PresetDescZh[i];
                cb.Tag = Rules.PresetNames[i];
                cb.Location = new Point(S(76 + (i % 3) * 186), S(40 + (i / 3) * 28));
                cb.Size = new Size(S(182), S(24));
                cb.ForeColor = cText;
                cb.BackColor = Color.Transparent;
                pnlDict.Controls.Add(cb);
                _ruleChecks.Add(cb);
            }
            chkResume = new CheckBox();
            chkResume.Text = "断点续跑（自动保存进度，可从中断处继续）";
            chkResume.Location = new Point(S(76), S(104));
            chkResume.Size = new Size(S(460), S(24));
            chkResume.ForeColor = cText;
            chkResume.BackColor = Color.Transparent;
            chkResume.Checked = true;
            pnlDict.Controls.Add(chkResume);

            // ---- mask panel --------------------------------------------
            pnlMask = new Panel();
            pnlMask.Location = new Point(0, S(76));
            pnlMask.Size = new Size(S(632), S(156));
            pnlMask.BackColor = Color.Transparent;
            pnlMask.Visible = false;
            pnlMask.Controls.Add(MkLabel("掩码", 0, 4, 72, 24, S));
            txtMask = new TextBox();
            txtMask.Location = new Point(S(76), S(2));
            txtMask.Size = new Size(S(446), S(25));
            pnlMask.Controls.Add(txtMask);
            pnlMask.Controls.Add(MkLabel("自定义集", 0, 40, 72, 24, S));
            Label l1 = MkLabel("-1:", 76, 42, 30, 24, S);
            Label l2 = MkLabel("-2:", 76, 70, 30, 24, S);
            txtSet1 = new TextBox();
            txtSet1.Location = new Point(S(110), S(38));
            txtSet1.Size = new Size(S(300), S(25));
            txtSet2 = new TextBox();
            txtSet2.Location = new Point(S(110), S(66));
            txtSet2.Size = new Size(S(300), S(25));
            pnlMask.Controls.Add(l1);
            pnlMask.Controls.Add(l2);
            pnlMask.Controls.Add(txtSet1);
            pnlMask.Controls.Add(txtSet2);
            pnlMask.Controls.Add(MkLabel("长度", 428, 42, 40, 24, S));
            numMin = new NumericUpDown();
            numMin.Minimum = 1; numMin.Maximum = 16; numMin.Value = 1;
            numMin.Location = new Point(S(472), S(40));
            numMin.Size = new Size(S(52), S(25));
            numMax = new NumericUpDown();
            numMax.Minimum = 1; numMax.Maximum = 16; numMax.Value = 6;
            numMax.Location = new Point(S(532), S(40));
            numMax.Size = new Size(S(52), S(25));
            pnlMask.Controls.Add(numMin);
            pnlMask.Controls.Add(numMax);
            lblMaskSpace = MkLabel("", 76, 102, 470, 40, S);
            pnlMask.Controls.Add(lblMaskSpace);
            EventHandler spaceChanged = delegate(object s, EventArgs e) { ScheduleSpaceUpdate(); };
            txtMask.TextChanged += spaceChanged;
            txtSet1.TextChanged += spaceChanged;
            txtSet2.TextChanged += spaceChanged;
            numMin.ValueChanged += spaceChanged;
            numMax.ValueChanged += spaceChanged;

            // ---- comb panel --------------------------------------------
            // dedicated A/B boxes: the main dict box (txtDict) lives in the
            // dict panel which is hidden while this mode is active
            pnlComb = new Panel();
            pnlComb.Location = new Point(0, S(76));
            pnlComb.Size = new Size(S(632), S(156));
            pnlComb.BackColor = Color.Transparent;
            pnlComb.Visible = false;
            pnlComb.Controls.Add(MkLabel("字典 A", 0, 4, 72, 24, S));
            pnlComb.Controls.Add(MkLabel("字典 B", 0, 36, 72, 24, S));
            txtDictA = new TextBox();
            txtDictA.Location = new Point(S(76), S(2));
            txtDictA.Size = new Size(S(446), S(25));
            Button btnDictA = Btn2("浏览...", 532, -2, 100, 30, cText, S);
            btnDictA.Click += delegate(object s, EventArgs e)
            { Browse(txtDictA, "文本文件 (*.txt;*.dic;*.lst)|*.txt;*.dic;*.lst|所有文件 (*.*)|*.*"); };
            txtDictB = new TextBox();
            txtDictB.Location = new Point(S(76), S(34));
            txtDictB.Size = new Size(S(446), S(25));
            Button btnDictB = Btn2("浏览...", 532, 30, 100, 30, cText, S);
            btnDictB.Click += delegate(object s, EventArgs e)
            { Browse(txtDictB, "文本文件 (*.txt;*.dic;*.lst)|*.txt;*.dic;*.lst|所有文件 (*.*)|*.*"); };
            Label lblCombNote = MkLabel("候选 = A 每行 + B 每行 逐行拼接", 76, 72, 500, 24, S);
            pnlComb.Controls.Add(txtDictA);
            pnlComb.Controls.Add(btnDictA);
            pnlComb.Controls.Add(txtDictB);
            pnlComb.Controls.Add(btnDictB);
            pnlComb.Controls.Add(lblCombNote);

            // ---- threads row -------------------------------------------
            content.Controls.Add(MkLabel("并行线程", 0, 246, 72, 24, S));
            cmbThreads = new ComboBox();
            cmbThreads.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbThreads.Location = new Point(S(76), S(244));
            cmbThreads.Size = new Size(S(200), S(25));
            int cores = Environment.ProcessorCount;
            _threadValues = new List<int>();
            int auto = Math.Max(1, Math.Min(32, cores - 2));
            cmbThreads.Items.Add("自动（" + cores + " 核 → " + auto + " 线程）");
            _threadValues.Add(0);
            foreach (int t in new int[] { 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 32 })
            {
                if (t <= cores)
                {
                    cmbThreads.Items.Add(t + " 线程");
                    _threadValues.Add(t);
                }
            }
            cmbThreads.SelectedIndex = 0;
            btnBench = Btn2("基准测速", 288, 241, 100, 30, cText, S);
            btnBench.Click += OnBench;
            lblFormat = MkLabel("", 400, 246, 240, 24, S);
            lblFormat.ForeColor = cPrimary;
            lblFormat.AutoEllipsis = true;

            // ---- progress + buttons ------------------------------------
            pbTrack = new Panel();
            pbTrack.Location = new Point(S(76), S(290));
            pbTrack.Size = new Size(S(556), S(8));
            pbTrack.BackColor = cTrack;
            pbFill = new Panel();
            pbFill.Location = new Point(0, 0);
            pbFill.Size = new Size(0, S(8));
            pbFill.BackColor = cPrimary;
            pbTrack.Controls.Add(pbFill);

            btnStart = new Button();
            btnStart.Text = "开始破解";
            btnStart.Location = new Point(S(76), S(312));
            btnStart.Size = new Size(S(152), S(40));
            btnStart.FlatStyle = FlatStyle.Flat;
            btnStart.FlatAppearance.BorderSize = 0;
            btnStart.FlatAppearance.MouseOverBackColor = cPrimHov;
            btnStart.BackColor = cPrimary;
            btnStart.ForeColor = Color.White;
            btnStart.Font = new Font("Microsoft YaHei UI", 9.5f, FontStyle.Bold);
            btnStart.Cursor = Cursors.Hand;
            btnStart.Click += OnStart;
            btnStop = Btn2("停止", 238, 312, 100, 40, cRed, S);
            btnStop.Enabled = false;
            btnStop.Click += delegate(object s, EventArgs e) { RequestCancel(); };

            lblStatus = MkLabel("待机 - 选择压缩包后点击开始", 76, 368, 556, 22, S);
            lblCurrent = MkLabel("", 76, 392, 556, 20, S);
            lblStats = MkLabel("", 76, 416, 556, 20, S);

            // ---- result group ------------------------------------------
            grp = new GroupBox();
            grp.Text = "破解结果";
            grp.Location = new Point(S(76), S(448));
            grp.Size = new Size(S(556), S(148));
            grp.ForeColor = cSub;
            grp.BackColor = cBg;
            txtPwd = new TextBox();
            txtPwd.ReadOnly = true;
            txtPwd.Location = new Point(S(16), S(28));
            txtPwd.Size = new Size(S(392), S(34));
            txtPwd.BorderStyle = BorderStyle.FixedSingle;
            txtPwd.Font = new Font("Microsoft YaHei UI", 13f, FontStyle.Bold);
            txtPwd.ForeColor = cText;
            txtPwd.Cursor = Cursors.Default;
            txtPwd.TabStop = false;
            btnCopy = Btn2("复制密码", 416, 27, 110, 34, cText, S);
            btnCopy.Enabled = false;
            btnCopy.Click += delegate(object s, EventArgs e)
            {
                if (txtPwd.Text.Length > 0) { Clipboard.SetText(txtPwd.Text); SetStatus("密码已复制到剪贴板。", cSub); }
            };
            btnMove = Btn2("密码提前到字典首行", 16, 74, 180, 32, cText, S);
            btnMove.Enabled = false;
            btnMove.Click += OnMoveToTop;
            btnExtract = Btn2("用此密码解压...", 206, 74, 140, 32, cText, S);
            btnExtract.Enabled = false;
            btnExtract.Click += OnExtract;
            lblSave = new Label();
            lblSave.Text = "";
            lblSave.Location = new Point(S(16), S(112));
            lblSave.Size = new Size(S(500), S(26));
            lblSave.ForeColor = cSub;
            lblSave.AutoEllipsis = true;
            lblSave.BackColor = Color.Transparent;
            grp.Controls.Add(txtPwd);
            grp.Controls.Add(btnCopy);
            grp.Controls.Add(btnMove);
            grp.Controls.Add(btnExtract);
            grp.Controls.Add(lblSave);

            Label lblHint = new Label();
            lblHint.Text = "提示：可把压缩包 / 字典拖进窗口 · Enter 开始 · Esc 停止 · 找到密码自动复制并提示";
            lblHint.Location = new Point(0, S(612));
            lblHint.Size = new Size(S(632), S(18));
            lblHint.ForeColor = Color.FromArgb(107, 114, 128);
            lblHint.Font = new Font("Microsoft YaHei UI", 8f);
            lblHint.BackColor = Color.Transparent;

            content.Controls.Add(txtArch);
            content.Controls.Add(btnArch);
            content.Controls.Add(rbDict);
            content.Controls.Add(rbMask);
            content.Controls.Add(rbComb);
            content.Controls.Add(pnlDict);
            content.Controls.Add(pnlMask);
            content.Controls.Add(pnlComb);
            content.Controls.Add(cmbThreads);
            content.Controls.Add(btnBench);
            content.Controls.Add(lblFormat);
            content.Controls.Add(pbTrack);
            content.Controls.Add(btnStart);
            content.Controls.Add(btnStop);
            content.Controls.Add(lblStatus);
            content.Controls.Add(lblCurrent);
            content.Controls.Add(lblStats);
            content.Controls.Add(grp);
            content.Controls.Add(lblHint);

            Controls.Add(content);
            Controls.Add(header);

            // anchors: size the content to its designed size BEFORE anchors
            // snapshot the edge gaps (documented WinForms trap)
            content.Size = new Size(S(672), S(706));
            txtArch.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            btnArch.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            pbTrack.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblStatus.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblCurrent.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblStats.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            grp.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            btnCopy.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            lblHint.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;

            AcceptButton = btnStart;
            KeyPreview = true;
            KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Escape) { e.SuppressKeyPress = true; RequestCancel(); }
            };
            FormClosing += delegate(object s, FormClosingEventArgs e) { RequestCancel(); };
            Shown += delegate(object s, EventArgs e) { MinimumSize = Size; };

            AllowDrop = true;
            DragEnter += OnDragEnter;
            DragDrop += OnDragDrop;

            _timer = new System.Windows.Forms.Timer();
            _timer.Interval = 150;
            _timer.Tick += OnTick;

            _spaceTimer = new System.Windows.Forms.Timer();
            _spaceTimer.Interval = 200;
            _spaceTimer.Tick += delegate(object s, EventArgs e)
            {
                _spaceTimer.Stop();
                UpdateMaskSpace();
            };

            _formatTimer = new System.Windows.Forms.Timer();
            _formatTimer.Interval = 400;
            _formatTimer.Tick += delegate(object s, EventArgs e)
            {
                _formatTimer.Stop();
                ProbeFormat();
            };

            LoadSettings();
            HandleAutoStart();
        }

        // ----------------------------------------------------------------
        private void UpdateModePanels()
        {
            pnlDict.Visible = rbDict.Checked;
            pnlMask.Visible = rbMask.Checked;
            pnlComb.Visible = rbComb.Checked;
            if (rbMask.Checked) ScheduleSpaceUpdate();
        }

        private void ScheduleSpaceUpdate()
        {
            _spaceTimer.Stop();
            _spaceTimer.Start();
        }

        private void ScheduleFormatProbe()
        {
            _formatTimer.Stop();
            _formatTimer.Start();
        }

        private static string FmtBig(double v)
        {
            if (v >= 1e16) return (v / 1e16).ToString("0.##") + " 千万亿";
            if (v >= 1e12) return (v / 1e12).ToString("0.##") + " 万亿";
            if (v >= 1e8) return (v / 1e8).ToString("0.##") + " 亿";
            if (v >= 1e4) return (v / 1e4).ToString("0.##") + " 万";
            return v.ToString("0");
        }

        private void UpdateMaskSpace()
        {
            try
            {
                string[] sets = new string[] { txtSet1.Text, txtSet2.Text, "", "" };
                MaskSource ms = new MaskSource(txtMask.Text, sets, (int)numMin.Value, (int)numMax.Value);
                long? total = ms.Total;
                lblMaskSpace.Text = total.HasValue
                    ? "候选空间: " + FmtBig(total.Value) + " 个"
                    : "候选空间: 超大（> 1.8×10^19，不建议）";
                lblMaskSpace.ForeColor = cSub;
            }
            catch
            {
                lblMaskSpace.Text = "掩码无效（可用 ?l ?u ?d ?s ?a ?h ?H ?1 ?2）";
                lblMaskSpace.ForeColor = cRed;
            }
        }

        private void ProbeFormat()
        {
            string path = txtArch.Text.Trim();
            if (path.Length == 0 || !File.Exists(path))
            {
                lblFormat.Text = "";
                return;
            }
            ThreadPool.QueueUserWorkItem(delegate(object state)
            {
                string note = null;
                try
                {
                    ArchiveInfo info = ArchiveParser.Parse(path);
                    if (info.Kind == ArchiveKind.Rar5 && info.NativeSupported)
                        note = info.Rar5.HeaderEncrypted
                            ? "RAR5 原生加速（-hp 头加密）"
                            : "RAR5 原生加速" + (info.Rar5.EntryName != null ? " · 加密条目: " + info.Rar5.EntryName : "");
                    else if (info.Kind == ArchiveKind.Zip && info.NativeSupported)
                        note = (info.Zip.Aes ? "ZIP AES-" + (info.Zip.AesStrength * 64 + 64) : "ZIP ZipCrypto")
                            + " 原生加速 · 加密条目: " + info.Zip.Name;
                    else if (info.Kind == ArchiveKind.Zip && info.Zip == null) note = "ZIP（未检测到加密条目）";
                    else if (info.Kind == ArchiveKind.RarLegacy) note = "RAR 1.5-4.x（外部工具）";
                    else if (info.Kind == ArchiveKind.SevenZip) note = "7z（外部工具）";
                    else note = "未知格式（尝试外部工具）";
                }
                catch { note = ""; }
                try { BeginInvoke((MethodInvoker)delegate() { lblFormat.Text = note ?? ""; }); }
                catch { }
            });
        }

        // ----------------------------------------------------------------
        private void Browse(TextBox target, string filter)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Title = "选择文件";
            dlg.Filter = filter;
            try
            {
                if (target.Text.Trim().Length > 0)
                {
                    string d = Path.GetDirectoryName(target.Text);
                    if (d != null && Directory.Exists(d)) dlg.InitialDirectory = d;
                }
            }
            catch { }
            if (dlg.ShowDialog(this) == DialogResult.OK) target.Text = dlg.FileName;
        }

        private void OnDragEnter(object s, DragEventArgs e)
        {
            e.Effect = DragDropEffects.None;
            if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string f in files)
            {
                string ext = (Path.GetExtension(f) ?? "").ToLowerInvariant();
                if (ext == ".rar" || ext == ".zip" || ext == ".7z" || ext == ".txt" || ext == ".dic" || ext == ".lst")
                { e.Effect = DragDropEffects.Copy; return; }
            }
        }

        private void OnDragDrop(object s, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            bool gotArch = false, gotDict = false;
            foreach (string f in files)
            {
                string ext = (Path.GetExtension(f) ?? "").ToLowerInvariant();
                if (ext == ".rar" || ext == ".zip" || ext == ".7z") { txtArch.Text = f; gotArch = true; }
                else if (ext == ".txt" || ext == ".dic" || ext == ".lst")
                {
                    if (pnlComb.Visible)
                    {
                        // fill A first, then B; re-dropping over a full
                        // panel replaces A
                        if (txtDictA.Text.Trim().Length == 0) txtDictA.Text = f;
                        else if (txtDictB.Text.Trim().Length == 0) txtDictB.Text = f;
                        else txtDictA.Text = f;
                    }
                    else txtDict.Text = f;
                    gotDict = true;
                }
            }
            if (gotArch || gotDict) SetStatus("拖入成功。", cSub);
            else SetStatus("拖入的文件类型不受支持（需要 rar/zip/7z 或 txt/dic/lst）。", cOrange);
        }

        private void SetStatus(string text, Color color)
        {
            lblStatus.Text = text;
            lblStatus.ForeColor = color;
        }

        // ----------------------------------------------------------------
        private CrackConfig BuildConfig()
        {
            CrackConfig cfg = new CrackConfig();
            cfg.ArchivePath = txtArch.Text.Trim();
            cfg.Threads = _threadValues[Math.Max(0, cmbThreads.SelectedIndex)];
            cfg.CheckpointEnabled = chkResume.Checked;
            if (rbMask.Checked)
            {
                cfg.Mode = "mask";
                cfg.Mask = txtMask.Text;
                cfg.CustomSets[0] = txtSet1.Text;
                cfg.CustomSets[1] = txtSet2.Text;
                cfg.MaskMin = (int)numMin.Value;
                cfg.MaskMax = (int)numMax.Value;
            }
            else if (rbComb.Checked)
            {
                cfg.Mode = "comb";
                cfg.DictFiles.Add(txtDictA.Text.Trim());
                cfg.DictFileB = txtDictB.Text.Trim();
            }
            else
            {
                cfg.Mode = "dict";
                cfg.DictFiles.Add(txtDict.Text.Trim());
                foreach (CheckBox cb in _ruleChecks)
                    if (cb.Checked) cfg.Presets.Add((string)cb.Tag);
            }
            return cfg;
        }

        private void OnStart(object s, EventArgs e)
        {
            if (_running) return;
            if (txtArch.Text.Trim().Length == 0) { MessageBox.Show(this, "请先选择压缩包文件。", "DictCrack"); txtArch.Focus(); return; }
            if (!File.Exists(txtArch.Text.Trim())) { MessageBox.Show(this, "压缩包文件不存在。", "DictCrack"); return; }
            if (rbDict.Checked && txtDict.Text.Trim().Length == 0)
            { MessageBox.Show(this, "需要字典 A（主字典框）。", "DictCrack"); txtDict.Focus(); return; }
            if (rbComb.Checked && txtDictA.Text.Trim().Length == 0)
            { MessageBox.Show(this, "组合攻击需要字典 A。", "DictCrack"); txtDictA.Focus(); return; }
            if (rbComb.Checked && txtDictB.Text.Trim().Length == 0)
            { MessageBox.Show(this, "组合攻击需要字典 B。", "DictCrack"); txtDictB.Focus(); return; }
            if (rbMask.Checked && txtMask.Text.Trim().Length == 0)
            { MessageBox.Show(this, "掩码攻击需要掩码。", "DictCrack"); txtMask.Focus(); return; }
            List<TextBox> mustExist = new List<TextBox>();
            if (rbDict.Checked) mustExist.Add(txtDict);
            if (rbComb.Checked) { mustExist.Add(txtDictA); mustExist.Add(txtDictB); }
            foreach (TextBox tb in mustExist)
            {
                string t = tb.Text.Trim();
                if (t.Length > 0 && !File.Exists(t)) { MessageBox.Show(this, "字典文件不存在: " + t, "DictCrack"); return; }
            }

            CrackConfig cfg = BuildConfig();
            if (rbDict.Checked || rbComb.Checked) _lastDict = cfg.DictFiles[0];
            else _lastDict = null;
            bool resume = false;
            if (chkResume.Checked)
            {
                SessionState sess = SessionState.Load(CrackEngine.SessionPath);
                if (sess != null && sess.Matches(Path.GetFullPath(cfg.ArchivePath), cfg.ParamsHash()))
                {
                    DialogResult dr = MessageBox.Show(this,
                        "检测到上次未完成的会话（" + sess.SaveTimeText + "，已试 " + sess.TriedAll + " 个）。\n\n从上次进度继续吗？\n\n是 = 续跑；否 = 从头开始。", "DictCrack",
                        MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
                    if (dr == DialogResult.Cancel) return;
                    if (dr == DialogResult.Yes) resume = true;
                }
            }
            cfg.ResumeRequested = resume;
            SaveSettings(cfg);
            StartEngine(cfg);
        }

        private void StartEngine(CrackConfig cfg)
        {
            _result = null;
            txtPwd.Text = "";
            btnCopy.Enabled = false;
            btnMove.Enabled = false;
            btnExtract.Enabled = false;
            lblSave.Text = "";
            txtPwd.BackColor = Color.White;
            txtPwd.ForeColor = cText;
            grp.Text = "破解结果";
            pbFill.Width = 0;
            pbFill.BackColor = cPrimary;
            lblCurrent.Text = "";
            lblStats.Text = "";
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            btnBench.Enabled = false;
            _running = true;
            int shown = cfg.Threads > 0 ? cfg.Threads : Math.Max(1, Math.Min(32, Environment.ProcessorCount - 2));
            SetStatus("正在启动（" + shown + " 线程）...", cText);

            _watch.Restart();
            _rateTried = 0;
            _rateTick.Restart();
            _rate = 0;

            _engine = new CrackEngine(cfg);
            _cts = new CancellationTokenSource();
            CancellationTokenSource cts = _cts;
            CrackEngine engine = _engine;
            _workThread = new Thread(delegate()
            {
                CrackResult r = null;
                try { r = engine.Run(cts.Token); }
                catch (Exception ex) { r = new CrackResult(); r.Error = ex.Message; }
                _result = r;
            }) { IsBackground = true };
            _workThread.Start();
            _timer.Start();
        }

        private void RequestCancel()
        {
            if (!_running) return;
            if (_cts != null)
            {
                try { _cts.Cancel(); } catch { }
            }
            SetStatus("正在停止（等待收尾）...", cOrange);
        }

        private void OnBench(object s, EventArgs e)
        {
            if (_running) return;
            if (txtArch.Text.Trim().Length == 0 || !File.Exists(txtArch.Text.Trim()))
            { MessageBox.Show(this, "请先选择有效的压缩包。", "DictCrack"); return; }
            btnBench.Enabled = false;
            SetStatus("正在测速（约 4 秒）...", cText);
            int threads = _threadValues[Math.Max(0, cmbThreads.SelectedIndex)];
            string arch = Path.GetFullPath(txtArch.Text.Trim());
            ThreadPool.QueueUserWorkItem(delegate(object state)
            {
                double single = 0, all = 0; string err = null;
                try
                {
                    ArchiveInfo info = ArchiveParser.Parse(arch);
                    if (!info.NativeSupported) err = "该格式不支持原生测速（需要 RAR5 或加密 ZIP）";
                    else
                    {
                        Verifier v = VerifierFactory.Create(info, null, arch);
                        single = Benchmark.Measure(v, 1, 2);
                        all = Benchmark.Measure(v, threads > 0 ? threads : Math.Max(1, Math.Min(32, Environment.ProcessorCount - 2)), 2);
                    }
                }
                catch (Exception ex) { err = ex.Message; }
                try
                {
                    BeginInvoke((MethodInvoker)delegate()
                    {
                        btnBench.Enabled = true;
                        if (err != null) SetStatus("测速失败: " + err, cRed);
                        else if (!_running)
                            SetStatus(string.Format("测速完成: 单线程 {0} 个/秒 · 多线程 {1} 个/秒", Math.Round(single, 1), Math.Round(all, 1)), cPrimary);
                    });
                }
                catch { }
            });
        }

        private void OnMoveToTop(object s, EventArgs e)
        {
            btnMove.Enabled = false;
            try
            {
                MovePasswordToTop(_lastDict, txtPwd.Text);
                lblSave.Text = lblSave.Text + "  密码已提前到字典第 1 行。";
                SetStatus("密码已提前到字典开头，下次将第一个尝试。", cGreen);
            }
            catch (Exception ex)
            {
                SetStatus("移动密码到字典开头失败: " + ex.Message, cRed);
            }
        }

        // rewrite the dictionary with the hit password at line 1. The
        // encoding is rediscovered by locating the hit line: whichever
        // planned encoding decodes a line equal to the password wins, so
        // GBK/UTF-8/UTF-16 dictionaries are all preserved byte-faithfully.
        private static void MovePasswordToTop(string dictPath, string pwdLine)
        {
            string note;
            List<Encoding> encs = DictEncoding.Plan(dictPath, out note);
            Encoding chosen = null;
            foreach (Encoding e in encs)
            {
                try
                {
                    foreach (string l in File.ReadLines(dictPath, e))
                        if (l == pwdLine) { chosen = e; break; }
                }
                catch { }
                if (chosen != null) break;
            }
            if (chosen == null) chosen = encs[encs.Count - 1];
            Encoding save = DictEncoding.SaveEncoding(chosen);
            List<string> lines = new List<string>(File.ReadAllLines(dictPath, save));
            lines.RemoveAll(delegate(string l) { return l == pwdLine; });
            lines.Insert(0, pwdLine);
            string tmp = dictPath + ".tmp";
            File.WriteAllLines(tmp, lines.ToArray(), save);
            bool done = false;
            string errs = "";
            try { File.Replace(tmp, dictPath, null); done = true; }
            catch (Exception ex) { errs = "Replace: " + ex.Message; }
            if (!done)
            {
                try { File.Copy(tmp, dictPath, true); done = true; }
                catch (Exception ex) { errs += " Copy: " + ex.Message; }
            }
            if (!done)
            {
                try { File.Delete(dictPath); File.Move(tmp, dictPath); done = true; }
                catch (Exception ex) { errs += " Move: " + ex.Message; }
            }
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            if (!done) throw new IOException("无法写入字典文件（可能被其他程序占用）：" + errs);
        }

        private void OnExtract(object s, EventArgs e)
        {
            FolderBrowserDialog dlg = new FolderBrowserDialog();
            dlg.Description = "选择解压目标目录";
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            string dir = dlg.SelectedPath;
            string arch = Path.GetFullPath(txtArch.Text.Trim());
            string pwd = txtPwd.Text;
            btnExtract.Enabled = false;
            SetStatus("正在解压...", cText);
            ThreadPool.QueueUserWorkItem(delegate(object state)
            {
                string tool = ToolLocator.FindExtractor();
                string err = null;
                if (tool == null) err = "找不到 7z.exe / rar.exe";
                else
                {
                    try
                    {
                        Directory.CreateDirectory(dir);
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = tool;
                        psi.Arguments = "x -y -p\"" + pwd.Replace("\"", "\"\"") + "\" -o\"" + dir + "\" \"" + arch + "\"";
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        using (Process p = Process.Start(psi))
                        {
                            System.Threading.Tasks.Task so = p.StandardOutput.ReadToEndAsync();
                            p.StandardError.ReadToEnd();
                            p.WaitForExit();
                            if (p.ExitCode != 0) err = "解压失败（退出码 " + p.ExitCode + "）";
                        }
                    }
                    catch (Exception ex) { err = ex.Message; }
                }
                try
                {
                    BeginInvoke((MethodInvoker)delegate()
                    {
                        btnExtract.Enabled = true;
                        if (err == null) { SetStatus("解压完成: " + dir, cGreen); SystemSounds.Exclamation.Play(); }
                        else SetStatus(err, cRed);
                    });
                }
                catch { }
            });
        }

        // ----------------------------------------------------------------
        private static string FmtEta(double sec)
        {
            if (sec < 0 || double.IsNaN(sec) || double.IsInfinity(sec)) return "--:--";
            TimeSpan t = TimeSpan.FromSeconds(Math.Floor(sec));
            if (t.TotalHours >= 1) return string.Format("{0:00}:{1:00}:{2:00}", (int)t.TotalHours, t.Minutes, t.Seconds);
            return string.Format("{0:00}:{1:00}", t.Minutes, t.Seconds);
        }

        private void OnTick(object s, EventArgs e)
        {
            if (!_running) return;
            try
            {
                EngineStats st = _engine.Stats;
                long triedAllNow = st.Tried;

                if (_rateTick.Elapsed.TotalSeconds >= 0.5)
                {
                    double dt = _rateTick.Elapsed.TotalSeconds;
                    double r = (triedAllNow - _rateTried) / dt;
                    if (r > 0) _rate = r;
                    _rateTried = triedAllNow;
                    _rateTick.Restart();
                }
                TimeSpan el = _watch.Elapsed;
                string statsLine = string.Format("已用时 {0:00}:{1:00}", (int)el.TotalMinutes, el.Seconds);
                if (_rate > 0)
                {
                    statsLine += string.Format(" · 速度 {0} 个/秒", Math.Round(_rate, 1));
                    long total = st.Total;
                    if (total > triedAllNow && _rate > 0)
                        statsLine += " · 预计剩余 " + FmtEta((total - triedAllNow) / _rate);
                }
                lblStats.Text = statsLine;

                string phase = st.Phase ?? "";
                long tot = st.Total;
                if (tot > 0)
                    lblStatus.Text = string.Format("{0}   已尝试 {1} / {2}", phase, triedAllNow, tot);
                else
                    lblStatus.Text = phase + "   已尝试 " + triedAllNow;
                lblStatus.ForeColor = cText;
                if (st.Current.Length > 0)
                {
                    string tag = st.CurrentTag;
                    lblCurrent.Text = (tag.Length > 0 ? "当前尝试[" + tag + "]: " : "当前尝试: ") + st.Current;
                }

                if (tot > 0 && pbTrack.Width > 0)
                    pbFill.Width = (int)Math.Min((long)pbTrack.Width, (long)pbTrack.Width * triedAllNow / tot);

                if (_result != null) FinishRun();
            }
            catch (Exception ex)
            {
                _running = false;
                _timer.Stop();
                btnStart.Enabled = true;
                btnStop.Enabled = false;
                btnBench.Enabled = true;
                SetStatus("内部错误: " + ex.Message, cRed);
            }
        }

        private void FinishRun()
        {
            _timer.Stop();
            lblCurrent.Text = "";
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            btnBench.Enabled = true;
            _running = false;
            CrackResult res = _result;
            TimeSpan el = _watch.Elapsed;
            double avg = res.Tried > 0 && el.TotalSeconds > 0 ? res.Tried / el.TotalSeconds : 0;
            lblStats.Text = string.Format("总计尝试 {0} 个 · 用时 {1:00}:{2:00} · 平均 {3} 个/秒",
                res.Tried, (int)el.TotalMinutes, el.Seconds, Math.Round(avg, 1));
            if (res.Found)
            {
                txtPwd.Text = res.Password;
                btnCopy.Enabled = true;
                btnMove.Enabled = _lastDict != null && File.Exists(_lastDict);
                btnExtract.Enabled = true;
                txtPwd.BackColor = cGreenBg;
                txtPwd.ForeColor = cGreenDk;
                grp.Text = "破解结果 — 已找到密码";
                grp.ForeColor = cGreen;
                pbFill.Width = pbTrack.Width;
                pbFill.BackColor = cGreen;
                try { if (res.Password.Length > 0) Clipboard.SetText(res.Password); } catch { }
                SystemSounds.Exclamation.Play();
                SetStatus("找到密码！（已自动复制到剪贴板）", cGreen);
                if (res.ResultFile != null) lblSave.Text = "已保存到: " + res.ResultFile;
            }
            else if (res.Error != null)
            {
                SetStatus("出错: " + res.Error, cRed);
            }
            else if (res.Cancelled)
            {
                SetStatus(chkResume.Checked ? "已停止（进度已保存，下次开始可选择继续）。" : "已停止。", cSub);
            }
            else
            {
                SetStatus("未找到密码。" + (_engine.LogNote.Length > 0 ? "（编码方案: " + _engine.LogNote + "）" : ""), cOrange);
            }
        }

        // ----------------------------------------------------------------
        private void SaveSettings(CrackConfig cfg)
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("arch=").Append(txtArch.Text).Append("\r\n");
                sb.Append("dict=").Append(txtDict.Text).Append("\r\n");
                sb.Append("dicta=").Append(txtDictA.Text).Append("\r\n");
                sb.Append("dictb=").Append(txtDictB.Text).Append("\r\n");
                sb.Append("mode=").Append(cfg.Mode).Append("\r\n");
                sb.Append("mask=").Append(txtMask.Text).Append("\r\n");
                sb.Append("threads=").Append(cfg.Threads).Append("\r\n");
                sb.Append("resume=").Append(chkResume.Checked ? "1" : "0").Append("\r\n");
                List<string> rules = new List<string>();
                foreach (CheckBox cb in _ruleChecks) if (cb.Checked) rules.Add((string)cb.Tag);
                sb.Append("rules=").Append(string.Join(",", rules.ToArray())).Append("\r\n");
                File.WriteAllText(_cfgFile, sb.ToString(), new UTF8Encoding(true));
            }
            catch { }
        }

        private void LoadSettings()
        {
            string mode = "dict", rules = "";
            int threads = 0;
            try
            {
                if (File.Exists(_cfgFile))
                {
                    foreach (string line in File.ReadAllLines(_cfgFile, new UTF8Encoding(true)))
                    {
                        int idx = line.IndexOf('=');
                        if (idx < 1) continue;
                        string k = line.Substring(0, idx).Trim();
                        string v = line.Substring(idx + 1);
                        if (k == "arch") txtArch.Text = v;
                        else if (k == "dict") txtDict.Text = v;
                        else if (k == "dicta") txtDictA.Text = v;
                        else if (k == "dictb") txtDictB.Text = v;
                        else if (k == "mode") mode = v;
                        else if (k == "mask") txtMask.Text = v;
                        else if (k == "threads") threads = ParseInt(v);
                        else if (k == "rules") rules = v;
                        else if (k == "resume") chkResume.Checked = v == "1";
                    }
                }
            }
            catch { }
            if (rules.Length > 0)
            {
                string[] active = rules.Split(',');
                foreach (CheckBox cb in _ruleChecks)
                    if (Array.IndexOf(active, (string)cb.Tag) >= 0) cb.Checked = true;
            }
            if (threads > 0)
            {
                int i = _threadValues.IndexOf(threads);
                if (i >= 0) cmbThreads.SelectedIndex = i;
            }
            if (mode == "mask") rbMask.Checked = true;
            else if (mode == "comb") rbComb.Checked = true;

            // command line overrides (also drive auto-start)
            bool hasW2 = false;
            for (int i = 0; i < _args.Length; i++)
                if (_args[i] == "-w2" && i + 1 < _args.Length) hasW2 = true;
            for (int i = 0; i < _args.Length; i++)
            {
                string a = _args[i];
                if (i + 1 < _args.Length && (a == "-a" || a == "--archive")) txtArch.Text = _args[i + 1];
                if (i + 1 < _args.Length && (a == "-w" || a == "--dict"))
                {
                    // with -w2 present, -w feeds the combinator's dict A
                    if (hasW2) txtDictA.Text = _args[i + 1];
                    else txtDict.Text = _args[i + 1];
                }
                if (i + 1 < _args.Length && a == "-w2") { txtDictB.Text = _args[i + 1]; rbComb.Checked = true; }
                if (i + 1 < _args.Length && a == "--mask") { txtMask.Text = _args[i + 1]; rbMask.Checked = true; }
                if (i + 1 < _args.Length && (a == "-t" || a == "--threads"))
                {
                    int t = ParseInt(_args[i + 1]);
                    if (t > 0)
                    {
                        int ix = _threadValues.IndexOf(t);
                        if (ix < 0)
                        {
                            cmbThreads.Items.Add(t + " 线程");
                            _threadValues.Add(t);
                            ix = _threadValues.IndexOf(t);
                        }
                        cmbThreads.SelectedIndex = ix;
                    }
                }
            }
        }

        private static int ParseInt(string s)
        {
            int v;
            return int.TryParse(s, out v) ? v : 0;
        }

        private void HandleAutoStart()
        {
            bool hasArch = false, hasCand = false;
            for (int i = 0; i < _args.Length; i++)
            {
                if (_args[i] == "-a" || _args[i] == "--archive") hasArch = i + 1 < _args.Length;
                if (_args[i] == "-w" || _args[i] == "--dict" || _args[i] == "--mask" || _args[i] == "-w2") hasCand = i + 1 < _args.Length;
            }
            if (hasArch && hasCand)
            {
                Shown += delegate(object s, EventArgs e)
                {
                    bool ok = File.Exists(txtArch.Text.Trim());
                    if (rbDict.Checked) ok = ok && File.Exists(txtDict.Text.Trim());
                    if (rbComb.Checked) ok = ok && File.Exists(txtDictA.Text.Trim()) && File.Exists(txtDictB.Text.Trim());
                    if (rbMask.Checked) ok = ok && txtMask.Text.Trim().Length > 0;
                    if (ok) OnStart(this, EventArgs.Empty);
                    else SetStatus("命令行指定的文件不存在。", cOrange);
                };
            }
        }
    }
}
