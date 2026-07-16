# Configure Application For Use

Follow this guide to configure Zerodha accounts for use in Zerodha-Trade-Point.

1. Create a Zerodha Developer account at https://developers.kite.trade/.
2. Assume you need to manage 4 Zerodha accounts (your own plus 3 family members).
3. To connect all 4 accounts in Zerodha-Trade-Point, create 4 separate apps in your Zerodha Developer account.
4. Use one app for each Zerodha account.
5. In each app, provide:
    - App name
    - Zerodha Account Client ID
    - Callback URL

    Example callback URL for an Azure-hosted app named zerodha_trade_point:
    https://zerodha_trade_point.azurewebsites.net/kite/callback/
6. For each app, note down the API Key and API Secret.
7. Share each API Key and API Secret securely with the corresponding Zerodha account holder using a separate secure channel.
8. In the Zerodha Developer portal, open the Profile section and locate IP whitelisting. You will use this later.
9. Log in to Zerodha-Trade-Point as a superuser or admin.
10. Go to Manage Users and create one Zerodha-Trade-Point username and password for each Zerodha account holder.
11. Assign each account holder the role self_only.
12. Create one trader account and assign the role trader_all (trade-only account).
13. Share each user's Zerodha-Trade-Point username and password securely, using a separate secure channel.
14. At this point, each user has 4 credentials:
     - Zerodha-Trade-Point username
     - Zerodha-Trade-Point password
     - API Key
     - API Secret
15. Each user logs in to Zerodha-Trade-Point and opens Configure ZK Auth.
16. Each user enters their API Key and API Secret (Zerodha User ID is optional) and clicks Authenticate to start the authentication flow. (The Add User button just saves the credentials without authenticating yet.)
17. Zerodha-Trade-Point opens the Zerodha Kite login page. The user enters Kite credentials and authorizes the app.
18. After successful authentication, Access Token Status should show Active.
19. If status later shows Needs Authentication, click Authenticate and complete the same flow again.
20. Log in using the trader account and open the Trade dashboard.
21. Use the top dropdown to select a configured Zerodha account and load account and trade data.
22. Place a valid order. If you see an IP not whitelisted error, copy the IP address shown in the message.
23. Go back to https://developers.kite.trade/ -> Profile -> IP whitelist.
24. Add that IP address to the whitelist.
25. Return to Zerodha-Trade-Point and continue using the application.

## Notes

- Token validity can change over time based on Zerodha policies. If token status is not Active, re-authenticate.
- Always share secrets (API Secret and passwords) only through secure channels.
