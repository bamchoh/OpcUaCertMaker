using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;

namespace OpcUaCertMaker
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            this.DataContext = new MainWindowVM();
        }

        private void BrowseRevokeCert_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFileDialog();
            dialog.Filter = "Certificate Files (*.cer;*.crt;*.der;*.pem)|*.cer;*.crt;*.der;*.pem|All Files (*.*)|*.*";
            if (dialog.ShowDialog() == true)
            {
                if (this.DataContext is MainWindowVM vm)
                {
                    vm.RevokeCertificateInput = dialog.FileName;
                }
            }
        }
    }
}