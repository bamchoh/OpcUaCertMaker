using Microsoft.Xaml.Behaviors;
using System.Windows.Controls;
using System.Windows;

namespace OpcUaCertMaker.Behaviors
{
    public class TextBoxSelectAllBehavior : Behavior<TextBox>
    {
        protected override void OnAttached()
        {
            base.OnAttached();
            AssociatedObject.GotFocus += TextBox_GotFocus;
        }

        protected override void OnDetaching()
        {
            AssociatedObject.GotFocus -= TextBox_GotFocus;
            base.OnDetaching();
        }

        private void TextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            var textBox = sender as TextBox;
            if (textBox != null)
            {
                textBox.Dispatcher.BeginInvoke(() =>
                {
                    textBox.SelectAll();
                });
            }
        }
    }
}