defmodule Boruta.MixProject do
  use Mix.Project

  def project do
    [
      name: "Boruta core",
      app: :boruta,
      version: "2.1.2",
      elixir: "~> 1.11",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description(),
      source_url: "https://gitlab.com/patatoid/boruta_auth",
      dialyzer: [
        plt_add_apps: [:mix]
      ]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Boruta.Application, []},
      extra_applications: [:logger, :runtime_tools, :crypto, :public_key]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "priv/boruta", "test/support"]
  defp elixirc_paths(_), do: ["lib", "priv/boruta"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:credo, "~> 1.1", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ecto_sql, ">= 3.5.2"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:ex_json_schema, "~> 0.6"},
      {:ex_machina, "~> 2.4", only: :test},
      {:joken, "~> 2.0"},
      {:jose, "~> 1.11"},
      {:mox, "~> 0.5", only: :test},
      {:nebulex, "~> 2.0"},
      {:phoenix, "~> 1.0"},
      {:plug, "~> 1.0"},
      {:postgrex, ">= 0.0.0"},
      {:puid, "~> 1.0"},
      {:secure_random, "~> 0.5"},
      {:shards, "~> 1.0"}
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: "https://gitlab.com/patatoid/boruta-core",
      source_ref: "master",
      extras: [
        "README.md",
        "guides/provider_integration.md",
        "guides/create_client.md",
        "guides/authorize_requests.md",
        "guides/pkce.md",
        "guides/migration.md",
        "CHANGELOG.md"
      ],
      groups_for_modules: [
        Applications: [
          Boruta.Oauth.AuthorizeApplication,
          Boruta.Oauth.TokenApplication,
          Boruta.Oauth.IntrospectApplication,
          Boruta.Oauth.RevokeApplication,
          Boruta.Openid.JwksApplication,
          Boruta.Openid.UserinfoApplication
        ],
        Responses: [
          Boruta.Oauth.AuthorizeResponse,
          Boruta.Oauth.TokenResponse,
          Boruta.Oauth.IntrospectResponse
        ],
        Admin: [
          Boruta.Ecto.Admin.Tokens,
          Boruta.Ecto.Admin.Clients,
          Boruta.Ecto.Admin.Scopes,
          Boruta.Ecto.Admin.Users
        ],
        Authorization: [
          Boruta.Oauth.Authorization,
          Boruta.Oauth.Authorization.AccessToken,
          Boruta.Oauth.Authorization.Client,
          Boruta.Oauth.Authorization.Code,
          Boruta.Oauth.Authorization.Nonce,
          Boruta.Oauth.Authorization.ResourceOwner,
          Boruta.Oauth.Authorization.Scope,
          Boruta.Oauth.AuthorizationSuccess
        ],
        Introspection: [
          Boruta.Oauth.Introspect
        ],
        Revocation: [
          Boruta.Oauth.Revoke
        ],
        Contexts: [
          Boruta.Oauth.AccessTokens,
          Boruta.Oauth.Clients,
          Boruta.Oauth.Codes,
          Boruta.Oauth.ResourceOwners,
          Boruta.Oauth.Scopes
        ],
        Schemas: [
          Boruta.Oauth.Token,
          Boruta.Oauth.IdToken,
          Boruta.Oauth.Client,
          Boruta.Oauth.Scope,
          Boruta.Oauth.ResourceOwner
        ],
        "OAuth request": [
          Boruta.Oauth.AuthorizationCodeRequest,
          Boruta.Oauth.ClientCredentialsRequest,
          Boruta.Oauth.CodeRequest,
          Boruta.Oauth.HybridRequest,
          Boruta.Oauth.IntrospectRequest,
          Boruta.Oauth.PasswordRequest,
          Boruta.Oauth.RefreshTokenRequest,
          Boruta.Oauth.RevokeRequest,
          Boruta.Oauth.TokenRequest,
          Boruta.Oauth.Request
        ],
        "Ecto Adapter": [
          Boruta.Cache,
          Boruta.Cache.Primary,
          Boruta.AccessTokensAdapter,
          Boruta.CodesAdapter,
          Boruta.ClientsAdapter,
          Boruta.ScopesAdapter,
          Boruta.ScopesAdapter
        ],
        "Ecto Schemas": [
          Boruta.Ecto.Token,
          Boruta.Ecto.Client,
          Boruta.Ecto.Scope
        ],
        Utilities: [
          Boruta.Cache,
          Boruta.BasicAuth,
          Boruta.Oauth.BearerToken,
          Boruta.Oauth.Validator,
          Boruta.Oauth.TokenGenerator
        ],
        Errors: [
          Boruta.Oauth.Error
        ]
      ]
    ]
  end

  defp package do
    %{
      name: "boruta",
      licenses: ["MIT"],
      links: %{
        "Gitlab" => "https://gitlab.com/patatoid/boruta_auth"
      }
    }
  end

  defp description do
    """
    Boruta is the core of an OAuth/OpenID Connect provider managing authorization business rules.
    """
  end

  defp aliases do
    [
      "ecto.setup": ["ecto.create", "ecto.migrate"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate", "test"]
    ]
  end
end
