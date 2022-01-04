namespace IdentitySystemCore.TwoFactorService
{
    public class TwoFactorOptions
    {
        public string SendGrid_API_KEY { get; set; }
        public int CodeTimeExpire { get; set; }

    }
}
