using System;
using System.Collections.Specialized;
using System.Text;
using System.Threading;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace Helper
{

    public class EmbeddedBrowserRequest
    {
        private Uri requestUri;
        private byte[] postData;
        private string additionalHeaders;
        public Uri ResponseUri { get; private set; }
        public Uri RedirectUri { get; set; }
        public string DocumentText { get; private set; }
        public EmbeddedBrowserRequest()
        {
        }
        private void Navigating(object sender, NavigatingCancelEventArgs e)
        {
            var form = (sender as WebBrowser).Parent as Window;
            //Console.WriteLine("Navigating " + e.Url);
            var b = new UriBuilder(e.Uri);
            b.Query = null;
            if (this.RedirectUri == b.Uri)
            {
                this.ResponseUri = e.Uri;
                this.DocumentText = (sender as WebBrowser).Document as string;
                form.DialogResult = true;
                form.Close();
                e.Cancel = true;
            }
        }
        private void Navigated(object sender, NavigationEventArgs e)
        {
            var form = (sender as WebBrowser).Parent as Window;
            //Console.WriteLine("Navigated " + e.Url);
            var b = new UriBuilder(e.Uri);
            b.Query = null;
            if (this.RedirectUri == b.Uri)
            {
                this.ResponseUri = e.Uri;
                this.DocumentText = (sender as WebBrowser).Document as string;
                form.DialogResult = true;
                form.Close();
            }
        }
        private void Run()
        {
            WebBrowser web;
            var form = new Window()
            {
                Width = 800,
                Height = 640,
                Content = (web = new WebBrowser())
            };
            //form.Width = 800;
            //form.Height = 640;
            //var web = new WebBrowser();
            //web.Size = form.ClientSize;
            //web.Anchor = (AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right | AnchorStyles.Bottom);
            web.Navigating += Navigating;
            web.Navigated += Navigated;
            if (postData != null)
            {
                web.Navigate(requestUri, null, postData, additionalHeaders);
            }
            else
            {
                web.Navigate(requestUri);
            }
            form.ShowDialog();
        }
        public Uri AuthorizationRequest(Uri authorizationRequest)
        {
            if (authorizationRequest.Query == null)
            {
                throw new ArgumentException("WebBrowserRequest", "authorizationRequest");
            }
            NameValueCollection qs = HttpUtility.ParseQueryString(authorizationRequest.Query);
            var s = qs.Get("redirect_uri");
            if (s == null)
            {
                throw new ArgumentException("WebBrowserRequest", "redirect_uri");
            }
            this.RedirectUri = new Uri(s);
            return Get(authorizationRequest)
                ? this.ResponseUri
                : null;
        }
        public bool Get(Uri requestUri)
        {
            this.requestUri = requestUri;
            this.postData = null;
            this.additionalHeaders = null;
            var t = new Thread(this.Run);
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();
            return this.ResponseUri != null;
        }
        public bool Post(Uri requestUri, string data)
        {
            this.requestUri = requestUri;
            this.postData = Encoding.UTF8.GetBytes(data);
            this.additionalHeaders = "Content-Type: application/x-www-form-urlencoded";
            var t = new Thread(this.Run);
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join();
            return this.ResponseUri != null;
        }
    }
}
