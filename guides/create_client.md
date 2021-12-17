# How to create an OAuth client

Boruta goes with some administration utilities. The best way to create a client is to go by a seed script as follow:

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
}) |> IO.inspect
```

Or so, you can use all administration utilities described in [Boruta API documentation](https://hexdocs.pm/boruta/Boruta.Ecto.Admin.html) to get all entities you need to have your server up and running. If some are missing or can be improved do not hesitate to open an issue on [GitLab](https://gitlab.com/patatoid/boruta_auth/-/issues) it would be very welcome.
