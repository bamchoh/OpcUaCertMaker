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
        private const string CertificateFilter = "Certificate Files (*.cer;*.crt;*.der;*.pem)|*.cer;*.crt;*.der;*.pem|All Files (*.*)|*.*";

        private const string PrivateKeyFilter = "Private Key Files (*.key;*.pfx;*.pem)|*.key;*.pfx;*.pem|All Files (*.*)|*.*";

        public MainWindow()
        {
            InitializeComponent();

            this.DataContext = new MainWindowVM();
        }

        private void OpenFileDialog(string filter, Action<string> action)
        {
            var dialog = new OpenFileDialog();
            dialog.Filter = filter;
            if (dialog.ShowDialog() == true)
            {
                action(dialog.FileName);
            }
        }

        private void BrowseRevokeCert_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog(CertificateFilter, (filename) => {
                if (this.DataContext is MainWindowVM vm)
                {
                    vm.RevokeCertificateInput = filename;
                }
            });
        }

        private void BrowseRootCAPrivateKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog(PrivateKeyFilter, (filename) => {
                if (this.DataContext is MainWindowVM vm)
                {
                    vm.RootCAPrivateKeyInput = filename;
                }
            });
        }

        private void BrowseRootCACert_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog(CertificateFilter, (filename) => {
                if (this.DataContext is MainWindowVM vm)
                {
                    vm.RootCACertificateInput = filename;
                }
            });
        }
    }
}