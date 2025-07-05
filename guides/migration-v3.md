# Migration from 2.X to 3.X

Version 3 of Boruta brings decentralized identity, several additions were made in order to stick to the according specifications:

## Resource owners

`Boruta.Oauth.ResourceOwner` schema come with several attributes additions to support OID4VC protocols:

- `authorization_details` help to have the associated credential issuance information that is later on stored at `Boruta.Aotuh.Token` level to enable credentials restriction in provided credential offers.
- `credential_configuration` help to define the resource owner accessible credentials configurations used in credential issuance process to provide credential information to the wallet.
- `presentation_configuration` help to define the resource owner, may it be represented by a wallet or not, to access the presentations provided by the server.

## Authorize requests

Authorization controller, part of the application layer, `Boruta.Oauth.AuthorizeApplication.authorize_success` callback manage, on top of already existing responses, `Boruta.Openid.CredentialOfferResponse`, `Boruta.Openid.SiopV2Response` and `Boruta.Openid.VerifiablePresentationResponse`. Those responses may be handled by the controller

## Direct post

`Boruta.Openid.DirectPostApplication` behaviour may be implemented to handle direct post requests, helping to manage the client/server requesting inversion for the wallet to interface with the issuer and verifier. Both the endpoint exposition and the callbacks are to be implemented.

## Credentials controller

OpenID 4 Verifiable Credentials Issuance expose a credential endpoint that is to be implemented in order to issue credentials provided an access token with the right privileges. `Boruta.Openid.CredentialApplication` gives the callbacks to be implemented when `Boruta.Openid.credential` function is called.

## Token response

`Boruta.Oauth.TokenResponse` has added attributes to support decentralized identity additions:

- `c_nonce` is the credential nonce that is access token bounded to ensure credentials are the ones that correspond to the request.
- `agent_token` is from a custom protocol enabling to bind data to tokens to be used later on.
- `authorization_details` is the credential restriction the access token have access to.

## Pushed authorization requests

`Boruta.Oauth.PushedAuthorizationRequestApplication` behaviour is to be implemented to expose pushed authorization requests endpoint in application layer. Both the `Boruta.Oauth.pushed_authorization_request` function call and given callbacks are to be implemented.
