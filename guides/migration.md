# Migration from 1.X

Version 2 of Boruta brings OpenID Connect, several changes were made in order to stick to the specification:

## OAuth response structs changes

`Boruta.Oauth.AuthorizeResponse` and `Boruta.Oauth.TokenResponse` do not provide token value in `value` field but prefer giving value by token type `code`, `access_token` or `id_token`.

```elixir
%AuthorizeResponse{
   type: "code",
   value: value,
   expires_in: 60
}
```

becomes

```elixir
%AuthorizeResponse{
   type: :code,
   code: value,
   expires_in: 60
}
```

## Database migrations

`boruta.gen.migration` task has been updated. Running the task will create required migrations to upgrade database schemas according to the updated `Ecto.Schema` modules.

In order to have the schema up to date, you need to generate migrations and run them

```
mix boruta.gen.migration
mix ecto.migrate
```

