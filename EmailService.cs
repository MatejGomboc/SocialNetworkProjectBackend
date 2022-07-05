using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace SocialNetworkProjectBackend
{
    public class EmailService
    {
        public class Settings
        {
            public string SendgridApiKey { get; set; } = string.Empty;
            public string FromAddress { get; set; } = string.Empty;
            public string FromName { get; set; } = string.Empty;
        }

        private readonly SendGridClient _sendGridClient;
        private readonly EmailAddress _fromEmailAddress;

        public EmailService(IOptions<Settings> settings)
        {
            _sendGridClient = new SendGridClient(settings.Value.SendgridApiKey);
            _fromEmailAddress = new EmailAddress(settings.Value.FromAddress, settings.Value.FromName);
        }

        public async Task<bool> SendRegisterConfirmEmailAsync(string toAddress, string username, string confirmUrl)
        {
            var msg = new SendGridMessage()
            {
                From = _fromEmailAddress,
                Subject = "Social Network Project user " + username + " registration confirmation",
                PlainTextContent = "Visit this link to confirm the registration: " + confirmUrl
            };

            msg.AddTo(new EmailAddress(toAddress, username));

            Response response = await _sendGridClient.SendEmailAsync(msg);
            return response.IsSuccessStatusCode;
        }
    }
}