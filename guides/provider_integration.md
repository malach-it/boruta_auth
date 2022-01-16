# Setting up Boruta OAuth/OpenID Connect provider
Boruta provides as its core all authorization business rules in order to handle underlying authorization logic of OAuth and OpenID Connect. Then it provides a generator that helps creating required controllers, views and templates as we will see.

## 1. Bootstrap the application

We will start by botsrapping a Phoenix web application with authentication capabilities provided by `phx.gen.auth` since OAuth and OpenID Connect specifications does not provide any recommandations about how to authenticate users. Instead, it provides all protocols required to authorize them to secure an HTTP service, with relative identity information in destination to the client brought by OpenID Connect core. Here we go, first bootstrapping the application:
```sh
~> mix phx.new boruta_example
```
Then the authentication
```sh
~> mix phx.gen.auth Accounts User users
```
We have now a web application in which we can log in. If you want to know more about those, have a look at [phx.new](https://hexdocs.pm/phoenix/Mix.Tasks.Phx.New.html) and [phx.gen.auth](https://hexdocs.pm/phoenix/Mix.Tasks.Phx.Gen.Auth.html) documentations.

In order to run the newly created application, you have to set up dependencies and database. You'll find development database configuration in `config/dev.exs` file, fill it with valid PostgreSQL credentials, you would be able to run
```sh
~> mix do deps.get, ecto.setup
```
Here is the application up and running, starting the web server with `mix phx.server` you'll be able to visit `http://localhost:4000` with your favorite browser.

## 2. Bootstrap Boruta _[commit](https://gitlab.com/patatoid/boruta_example/-/commit/fef019e22cb51c5a82b87193bc95676e8ccefbf0)_

Once the application up, we can pass to the authorization part. First, you can add the Boruta dependency in `mix.exs`
```elixir
# mix.exs

  def deps do
  ...
      {:boruta, git: "https://gitlab.com/patatoid/boruta_auth.git"},
  ...
  end
```

After that, you'll be able to generate controllers in order to expose Oauth and OpenID Connect core specifications endpoints and database migrations to persist required clients, scopes and tokens needed by your newly created provider.

```sh
~> mix do deps.get, boruta.gen.migration, ecto.migrate, boruta.gen.controllers
```

It will print the remaining steps to have the provider up and running as described in [documentation](https://patatoid.gitlab.io/boruta_auth/Mix.Tasks.Boruta.Gen.Controllers.html). From there we will skip the testing part which uses Mox in order to mock Boruta and focus tests on the application layer.

## 3. Configure Boruta _[commit](https://gitlab.com/patatoid/boruta_example/-/commit/cf3e4e3a9d2b0baf5ed24a8c38062fa34d2f3ea0)_

As described in `boruta.gen.controllers` mix task output, you need to expose controller actions in `router.ex` as follow

```elixir
# lib/boruta_example_web/router.ex

  scope "/oauth", BorutaExampleWeb.Oauth do
    pipe_through :api

    post "/revoke", RevokeController, :revoke
    post "/token", TokenController, :token
    post "/introspect", IntrospectController, :introspect
  end

  scope "/oauth", BorutaExampleWeb.Oauth do
    pipe_through [:browser, :fetch_current_user]

    get "/authorize", AuthorizeController, :authorize
  end

  scope "/openid", BorutaExampleWeb.Openid do
    pipe_through [:browser, :fetch_current_user]

    get "/authorize", AuthorizeController, :authorize
  end
```

And give mandatory boruta configuration
```elixir
# config/config.exs

config :boruta, Boruta.Oauth,
  repo: BorutaExample.Repo
```
Here client credentials flow should be up. For user flows you need further configuration and to implement `Boruta.Oauth.ResourceOwners` context.

## 4. User flows _[commit #1](https://gitlab.com/patatoid/boruta_example/-/commit/10c573e3663d1ba533f7613b8b1fe7e9eb266e06), [commit #2](https://gitlab.com/patatoid/boruta_example/-/commit/f88bec800cd8e46b624075e6024d5b83ccbda056)_

In order to have user flows operational, you need to implement `Boruta.Oauth.ResourceOwners` context as described in [Boruta README](https://patatoid.gitlab.io/boruta_auth/readme.html). Here it would look like
```elixir
# lib/boruta_example/resource_owners.ex

defmodule BorutaExample.ResourceOwners do
  @behaviour Boruta.Oauth.ResourceOwners

  alias Boruta.Oauth.ResourceOwner
  alias MyApp.Accounts.User
  alias MyApp.Repo

  @impl Boruta.Oauth.ResourceOwners
  def get_by(username: username) do
    with %User{id: id, email: email} <- Repo.get_by(User, email: username) do
      {:ok, %ResourceOwner{sub: to_string(id), username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end
  def get_by(sub: sub) do
    with %User{id: id, email: email} <- Repo.get_by(User, id: sub) do
      {:ok, %ResourceOwner{sub: to_string(id), username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    user = Repo.get_by(User, id: resource_owner.sub)
    case User.valid_password?(user, password) do
      true -> :ok
      false -> {:error, "Invalid email or password."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def authorized_scopes(%ResourceOwner{}), do: []
end
```

and inject it with main configuration

```elixir
# config/config.exs

config :boruta, Boruta.Oauth,
  repo: BorutaExample.Repo,
  contexts: [
    resource_owners: BorutaExample.ResourceOwners
  ]
```

Last, you'll have to setup is the redirection in the OAuth authorize controller

```elixir
# lib/boruta_example_web/controllers/oauth/authorize_controller.ex

...
  defp redirect_to_login(conn) do
    redirect(conn, to: Routes.user_session_path(conn, :new))
  end
```

Here all OAuth flows should be up and running !

## 5. OpenID Connect _[commit #1](https://gitlab.com/patatoid/boruta_example/-/commit/a1bbf67ea4182c7adda0f30788a4d0e9722e6cbc)_, _[commit #2](https://gitlab.com/patatoid/boruta_example/-/commit/a99740613d6efebbd5b2729d40edf9b5eb9c7860)_

In order to setup OpenID Connect flows, you need to tweak `phx.gen.auth` in order to redirect to login after logging out
```elixir
# lib/boruta_example_web/controllers/user_auth.ex:80

...
  def log_out_user(conn) do
    ...
    conn
    |> renew_session()
    |> delete_resp_cookie(@remember_me_cookie)
    |> redirect(to: Routes.user_session_path(conn, :new))
  end
```

And set redirections in the OpenID authorize controller
```elixir
# lib/boruta_example_web/controllers/openid/authorize_controller.ex

...
  defp redirect_to_login(conn) do
    redirect(conn, to: Routes.user_session_path(conn, :new))
  end

  defp log_out_user(conn) do
    UserAuth.log_out_user(conn)
  end
```

Last, you need to store `last_login_at` field of users to keep track of timestamp when user logs in

```elixir
# priv/repo/migrations/<timestamp>_add_last_login_at_to_users.exs

defmodule BorutaExample.Repo.Migrations.AddLastLoginAtToUsers do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :last_login_at, :utc_datetime_usec
    end
  end
end

# lib/boruta_example/accounts.ex:223

...
   def generate_user_session_token(user) do
     {token, user_token} = UserToken.build_session_token(user)
     Repo.insert!(user_token)
     user |> User.login_changeset() |> Repo.update!()
     token
   end

# lib/boruta_example/accounts/user.ex

...
  schema "users" do
    ...
    field :last_login_at, :utc_datetime_usec

    timestamps()
  end
...
   def login_changeset(user) do
     change(user, last_login_at: DateTime.utc_now())
   end
```

Here we are! You have a basic OpenID Connect provider. You can now create a client as described [here](https://patatoid.gitlab.io/boruta_auth/create_client.html) and start using it.
Departing from there, you can use any OAuth/OpenID Connect client of your choice.

Hope you enjoyed so far. The process can definitely improved at some points, all contributions of any kind will be very welcome.

