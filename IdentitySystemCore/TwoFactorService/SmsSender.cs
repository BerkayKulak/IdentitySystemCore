using Microsoft.Extensions.Options;

namespace IdentitySystemCore.TwoFactorService
{
    public class SmsSender
    {
        private readonly TwoFactorOptions _twoFactorOptions;
        private readonly TwoFactorService _twoFactorService;

        public SmsSender(IOptions<TwoFactorOptions> options, TwoFactorService twoFactorService)
        {
            _twoFactorOptions = options.Value;
            _twoFactorService = twoFactorService;
        }

        public string Send(string phone)
        {
            string code = _twoFactorService.GetCodeVerification().ToString();

            // SMS PROVIDER


            return code;
        }
    }
}
