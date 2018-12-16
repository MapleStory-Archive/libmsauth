# libmsauth
An authentication library for MapleStory written in C#. Authenticates accounts and obtains the passport token to spawn a new MapleStory instance or authorize a login attempt. 

libmsauth currently only supports Web Authentication and Authorisation. Authentication and authorisation through NMCO*.dll's is not yet supported.

## Example
```csharp
private async void ExampleFunction(string email, string password)
{
    WebAuthentication web = new WebAuthentication();
    NexonPassport passport = default(NexonPassport);

    try
    {
        passport = await web.GetNexonPassport(email, password);
    }
    catch (WebAuthenticationException wEx)
    {
        switch(wEx.ErrorCode)
        {
            case WebAuthenticationErrorCodes.InvalidEmail:
            case WebAuthenticationErrorCodes.InvalidPassword:
                MessageBox.Show(wEx.Message, "Authentication Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            case WebAuthenticationErrorCodes.InvalidClient:
            case WebAuthenticationErrorCodes.UntrustedDevice:
                MessageBox.Show(wEx.Message + "\r\n" + "Check your e-mail and manually verify your identity.", "API Configuration Error", MessageBoxButton.OK, MessageBoxImage.Stop);
                return;
        }
    }
    
    //Use the token here by accessing passport.Token;
    ...
}
```

## Disclaimer
I wrote this library in a relatively short amount of time and it is the first library that was created with the intent to share. If you have any improvements feel free to contribute.

This library is created for the sole purpose of allowing people to roll their own launcher. The Nexon Launcher is a painfully awful launcher filled with unnecessary features. Use at your own risk, as I am unsure whether this is in violation of Nexon's Terms of Service.
