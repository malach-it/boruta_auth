# Notes about confidential clients

This server manage confidential clients as stated in [OAuth 2.0 RFC](https://datatracker.ietf.org/doc/html/rfc6749). Clients have a `confidential` attribute as a boolean to state if the client is set to be confidential. Here is described how this implementation manage them for each flow:
- __Client Credentials__ - checks client secret wheter client is confidential or not
- __Authorization Code Grant__ - enforces check of client secret only for confidential clients on access token request, does not check client secret during authorization phase.
- __Hybrid Flow__ - has the same behavior as authorization code grant
- __Implicit Grant__ - never checks client secret wheter client is confidential or not
- __Resource Owner Password Credentials__ - enforces check of client secret only for confidential clients
- __Refresh Token__ - enforces check of client secret only for confidential clients, `public_refresh_token` overrides the confidentiality
- __Introspect__ - always enforces check of client secret wheter client is confidential or not
- __Revoke__ - always enforces check of client secret wheter client is confidential or not, `public_revoke` overrides the confidentiality
