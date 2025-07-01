defmodule Boruta.MixProject do
  use Mix.Project

  def project do
    [
      name: "Boruta core",
      app: :boruta,
      version: "3.0.0-beta.4",
      elixir: "~> 1.11",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      docs: docs(),
      package: package(),
      description: description(),
      source_url: "https://github.com/malach-it/boruta_auth",
      test_coverage: [tool: ExCoveralls],
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
      {:bypass, "~> 2.1", only: :test},
      {:credo, "~> 1.1", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ecto_sql, ">= 3.5.2"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:ex_json_schema, "~> 0.6"},
      {:ex_machina, "~> 2.4", only: :test},
      {:excoveralls, "~> 0.10", only: :test},
      {:finch, "~> 0.16"},
      {:owl, "~> 0.8.0 or ~> 0.9.0 or ~> 0.10.0 or ~> 0.11.0 or ~> 0.12.0"},
      {:jason, "~> 1.4"},
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
      source_url: "https://github.com/malach-it/boruta_auth",
      source_ref: "master",
      extras: [
        "README.md",
        "guides/provider_integration.md",
        "guides/create_client.md",
        "guides/authorize_requests.md",
        "guides/pkce.md",
        "guides/confidential_clients.md",
        "guides/migration.md",
        "CHANGELOG.md"
      ],
      groups_for_modules: [
        Applications: [
          Boruta.Oauth.Application,
          Boruta.Oauth.AuthorizeApplication,
          Boruta.Oauth.TokenApplication,
          Boruta.Oauth.IntrospectApplication,
          Boruta.Oauth.RevokeApplication,
          Boruta.Openid.JwksApplication,
          Boruta.Openid.Application,
          Boruta.Openid.DynamicRegistrationApplication,
          Boruta.Openid.UserinfoApplication,
          Boruta.Openid.CredentialApplication,
          Boruta.Openid.DirectPostApplication,
          Boruta.Oauth.PushedAuthorizationRequestApplication
        ],
        Responses: [
          Boruta.Oauth.AuthorizeResponse,
          Boruta.Oauth.TokenResponse,
          Boruta.Oauth.PushedAuthorizationResponse,
          Boruta.Openid.CredentialOfferResponse,
          Boruta.Openid.CredentialResponse,
          Boruta.Openid.DeferedCredentialResponse,
          Boruta.Openid.SiopV2Response,
          Boruta.Oauth.IntrospectResponse,
          Boruta.Openid.VerifiablePresentationResponse
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
          Boruta.Oauth.AuthorizationSuccess,
          Boruta.Dpop
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
          Boruta.Oauth.Requests,
          Boruta.Oauth.Scopes,
          Boruta.Openid.PreauthorizedCodes,
          Boruta.Openid.Credentials
        ],
        Schemas: [
          Boruta.Oauth.Token,
          Boruta.Oauth.IdToken,
          Boruta.Oauth.Client,
          Boruta.Oauth.Scope,
          Boruta.Oauth.ResourceOwner,
          Boruta.Openid.Credential
        ],
        "OAuth request": [
          Boruta.Oauth.AuthorizationRequest,
          Boruta.Oauth.PreauthorizedCodeRequest,
          Boruta.Oauth.PreauthorizationCodeRequest,
          Boruta.Oauth.AuthorizationCodeRequest,
          Boruta.Oauth.ClientCredentialsRequest,
          Boruta.Oauth.CodeRequest,
          Boruta.Oauth.HybridRequest,
          Boruta.Oauth.IntrospectRequest,
          Boruta.Oauth.PasswordRequest,
          Boruta.Oauth.RefreshTokenRequest,
          Boruta.Oauth.RevokeRequest,
          Boruta.Oauth.TokenRequest,
          Boruta.Oauth.PresentationRequest,
          Boruta.Oauth.Request
        ],
        "Ecto Adapter": [
          Boruta.Cache,
          Boruta.Cache.Primary,
          Boruta.AccessTokensAdapter,
          Boruta.CodesAdapter,
          Boruta.ClientsAdapter,
          Boruta.ScopesAdapter,
          Boruta.CredentialsAdapter,
          Boruta.PreauthorizedCodesAdapter,
          Boruta.RequestsAdapter
        ],
        "Ecto Schemas": [
          Boruta.Ecto.Token,
          Boruta.Ecto.Client,
          Boruta.Ecto.Scope,
          Boruta.Ecto.AuthorizationRequest,
          Boruta.Ecto.Credential
        ],
        Utilities: [
          Boruta.Cache,
          Boruta.BasicAuth,
          Boruta.Oauth.BearerToken,
          Boruta.Oauth.Validator,
          Boruta.Oauth.TokenGenerator,
          Boruta.Did,
          Boruta.Openid.VerifiableCredentials.Hotp
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
        "GitHub" => "https://github.com/malach-it/boruta_auth"
      }
    }
  end

  defp description do
    """
    Core of an OAuth/OpenID Connect provider enabling authorization in your applications.
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
