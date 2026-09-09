# DID client authorization bypasses redirect URI and grant validation

## Summary

Boruta's OpenID4VP/SIOPv2 presentation and OpenID4VCI pre-authorized-code flows treated any client identifier beginning with `did:` as the server's public client without running normal client authorization.

As a result, an attacker-controlled DID client could supply an unregistered redirect URI and use a grant type that was not enabled for the public client. If a resource owner completed the resulting flow, Boruta could deliver an authorization response, presentation response, or credential-related code to an attacker-controlled destination.

## Severity

High

Suggested CVSS 3.1 vector: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1)

The score assumes that a deployment exposes the affected wallet or credential flows and that an attacker can convince a resource owner to complete an attacker-crafted authorization request. Deployments that do not expose these flows are not directly exploitable.

## Confidence

High. The validation bypass is directly confirmed in the authorization implementations. The exact impact depends on the host application's enabled flows, consent behavior, scopes, response contents, and redirect handling.

## CWE

- CWE-601: URL Redirection to Untrusted Site
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization

## Affected Versions

Confirmed affected in the `3.0.0-master` development source before the patch that routes DID clients through `Boruta.Oauth.Authorization.Client.authorize/1`.

Maintainers should review other release lines containing either of these behaviors:

- `Boruta.Oauth.PreauthorizedCodeRequest` returns `ClientsAdapter.public!()` directly for a `did:` client identifier.
- `Boruta.Oauth.PresentationRequest` returns `ClientsAdapter.public!()` directly for a `did:` client identifier.

## Affected Flows

- SIOPv2 direct-post authorization using a DID client identifier
- OpenID4VP presentation authorization using a DID client identifier
- OpenID4VCI pre-authorized-code authorization using a DID client identifier

## Impact

The affected branches trusted the `did:` prefix as sufficient client authorization. They did not verify that:

- the supplied redirect URI was registered for the public client; or
- the public client supported the requested grant or response type.

An attacker can construct an authorization request containing an attacker-selected DID client identifier and redirect URI. If the request reaches an affected endpoint and a resource owner completes the flow, the response may be sent to an unauthorized location.

Depending on the enabled flow and application callbacks, exposed data can include authorization codes, pre-authorized credential codes, presentation results, or other response parameters. Intercepted one-time codes may allow the attacker to continue a token or credential flow. Grant validation bypass can also expose protocol functionality that administrators intended to disable for the shared public client.

The vulnerability does not by itself bypass resource-owner authentication or consent. It changes where a successfully authorized response may be delivered and which public-client grants may be invoked.

## Attack Scenario

1. An attacker creates an authorization URL for an affected endpoint.
2. The request uses an attacker-controlled identifier such as `did:key:...` and an attacker-controlled `redirect_uri`.
3. The attacker convinces a resource owner to open the URL and complete the wallet, presentation, or credential authorization flow.
4. Boruta recognizes the `did:` prefix and substitutes the server's public client.
5. In affected versions, Boruta does not validate the redirect URI or requested grant against that public client.
6. The authorization response or code is delivered to the attacker's destination.
7. The attacker uses the disclosed response or code according to the capabilities of the enabled flow.

## Technical Details

The pre-authorized-code implementation previously authorized every DID client with:

```elixir
case client_id do
  "did:" <> _key ->
    {:ok, ClientsAdapter.public!()}

  _ ->
    Authorization.Client.authorize(
      id: client_id,
      source: nil,
      redirect_uri: redirect_uri,
      grant_type: grant_type
    )
end
```

The presentation implementation contained the equivalent shortcut:

```elixir
defp authorize_presentation_client("did:" <> _key, _redirect_uri, _response_types) do
  {:ok, ClientsAdapter.public!()}
end
```

Both branches returned the public client before invoking the checks performed by `Boruta.Oauth.Authorization.Client.authorize/1`. In particular, the shortcut omitted `Boruta.Oauth.Client.check_redirect_uri/2` and `Boruta.Oauth.Client.grant_type_supported?/2`.

The non-DID branches already used the shared client authorizer and were not affected by this specific bypass.

## Remediation

Route DID-based requests through the same client authorization boundary as other requests. Resolve the server's public-client identifier, then pass it together with the untrusted redirect URI and requested grant type to `Boruta.Oauth.Authorization.Client.authorize/1`.

For pre-authorized-code requests:

```elixir
Authorization.Client.authorize(
  id: ClientsAdapter.public!().id,
  source: nil,
  redirect_uri: redirect_uri,
  grant_type: grant_type
)
```

For presentation requests, perform the same authorization using the requested presentation response type as the grant type.

Deployments must also configure the shared public client with only the redirect URIs and wallet grant types that are explicitly intended. Avoid broad wildcard redirect patterns, and ensure that any allowed custom URI scheme is bound to the expected wallet application.

## Regression Tests

Add integration tests proving that DID and public-client requests:

- reject an unregistered redirect URI with `invalid_client`;
- reject a grant or response type not enabled for the public client;
- continue to accept explicitly registered redirect URIs for enabled wallet grants;
- apply the checks to both presentation and pre-authorized-code flows;
- cannot bypass validation by changing only the DID value after a request is created; and
- preserve the same validation when a previous code, request object, or direct-post response mode is used.

Schema validation should be tested separately. A malformed `response_type` can be rejected as `invalid_request` before client authorization is reached.

## Workarounds

Until a patched version is deployed:

- disable DID-based presentation and pre-authorized-code flows if they are not required;
- reject requests whose redirect URI is not on a strict server-side allowlist before calling Boruta;
- restrict the public client to the minimum required wallet grant types;
- avoid wildcard redirect URI registrations;
- require clear resource-owner confirmation showing the destination client and requested action; and
- monitor wallet and credential authorization requests for unexpected DID identifiers or redirect destinations.

## Detection and Monitoring

Review authorization logs and stored codes for:

- DID client identifiers paired with redirect URIs not registered for the public client;
- use of wallet grant or response types not enabled for the public client;
- unusual custom URI schemes or web origins;
- repeated authorization attempts that vary the DID or redirect URI; and
- credential or presentation codes followed by redemption from an unrelated client or network source.

Historical review may be limited if the host application did not record the original client identifier and redirect URI.

## References

- RFC 6749, sections 3.1.2 and 10.6: redirect endpoint registration and URI manipulation
- RFC 9700: Best Current Practice for OAuth 2.0 Security
- OpenID for Verifiable Presentations
- OpenID for Verifiable Credential Issuance
- CWE-601: URL Redirection to Untrusted Site
- CWE-862: Missing Authorization
- CWE-863: Incorrect Authorization
