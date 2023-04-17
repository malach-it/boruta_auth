# How to create an OAuth client

Boruta goes with some __administration utilities__. The best way to have an OAuth client up and running is to __create a client with a seed script__ as following example:

```elixir
# priv/repo/seeds.exs

id = SecureRandom.uuid()
secret = SecureRandom.hex(64)

Boruta.Ecto.Admin.create_client(%{
  id: id, # OAuth client_id
  secret: secret, # OAuth client_secret
  name: "A client", # Display name
  access_token_ttl: 60 * 60 * 24, # one day
  authorization_code_ttl: 60, # one minute
  refresh_token_ttl: 60 * 60 * 24 * 30, # one month
  id_token_ttl: 60 * 60 * 24, # one day
  id_token_signature_alg: "RS256", # ID token signature algorithm, defaults to "RS512"
  userinfo_signed_response_alg: "RS256", # userinfo signature algorithm, defaults to nil (no signature)
  redirect_uris: ["http://redirect.uri"], # OAuth client redirect_uris
  authorize_scope: true, # take following authorized_scopes into account (skip public scopes)
  authorized_scopes: [%{name: "a:scope"}], # scopes that are authorized using this client
  supported_grant_types: [ # client supported grant types
    "client_credentials",
    "password",
    "authorization_code",
    "refresh_token",
    "implicit",
    "revoke",
    "introspect"
  ],
  pkce: false, # PKCE enabled
  public_refresh_token: false, # do not require client_secret for refreshing tokens
  public_revoke: false # do not require client_secret for revoking tokens
  confidential: true, # see OAuth 2.0 confidentiality (requires client secret for some flows)
  token_endpont_auth_methods: [ # activable client authentication methods
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  ],
  token_endpoint_jwt_auth_alg: nil # associated to authentication methods, the algorithm to use along
  jwt_public_key: nil # pem public key to be used with `private_key_jwt` authentication method
}) |> IO.inspect
```

Or so, you can use all administration utilities described in [Boruta API documentation](https://hexdocs.pm/boruta/Boruta.Ecto.Admin.html) to manage all entities you need to have your server up and running. If some are missing or can be improved do not hesitate to open an issue on [GitLab](https://gitlab.com/patatoid/boruta_auth/-/issues), it would be very welcome.
