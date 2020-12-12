defmodule Boruta.Config do
  @moduledoc """
  Utilities to access Boruta configuration ad set defaults.

  Configuration can be set as following in `config.exs` (this configuration is the default)
  ```
  config :boruta, Boruta.Oauth,
    repo: MyApp.Repo,
    contexts: [
      access_tokens: Boruta.Ecto.AccessTokens,
      clients: Boruta.Ecto.Clients,
      codes: Boruta.Ecto.Codes,
      resource_owners: nil,
      scopes: Boruta.Ecto.Scopes
    ],
    max_ttl: [
      authorization_code: 60,
      access_token: 60 * 60 * 24
    ],
    token_generator: Boruta.TokenGenerator
  ```

  NOTE: Since all configurations expected `resource_owners` are macro, they are assigned at compile time
  """

  @defaults repo: Boruta.Repo,
    contexts: [
      access_tokens: Boruta.Ecto.AccessTokens,
      clients: Boruta.Ecto.Clients,
      codes: Boruta.Ecto.Codes,
      resource_owners: nil,
      scopes: Boruta.Ecto.Scopes
    ],
    max_ttl: [
      authorization_code: 60,
      access_token: 60 * 60 * 24
    ],
    token_generator: Boruta.TokenGenerator

  @spec repo() :: module()
  @doc false
  def repo do
    Keyword.fetch!(oauth_config(), :repo)
  end

  @spec access_token_max_ttl() :: integer()
  @doc false
  def access_token_max_ttl do
    Keyword.fetch!(oauth_config(), :max_ttl)[:access_token]
  end

  @spec authorization_code_max_ttl() :: integer()
  @doc false
  def authorization_code_max_ttl do
    Keyword.fetch!(oauth_config(), :max_ttl)[:authorization_code]
  end

  @spec token_generator() :: module()
  @doc false
  def token_generator do
    Keyword.fetch!(oauth_config(), :token_generator)
  end

  @spec access_tokens() :: module()
  @doc false
  def access_tokens do
    Keyword.fetch!(oauth_config(), :contexts)[:access_tokens]
  end

  @spec clients() :: module()
  @doc false
  def clients do
    Keyword.fetch!(oauth_config(), :contexts)[:clients]
  end

  @spec codes() :: module()
  @doc false
  def codes do
    Keyword.fetch!(oauth_config(), :contexts)[:codes]
  end

  @spec scopes() :: module()
  @doc false
  def scopes do
    Keyword.fetch!(oauth_config(), :contexts)[:scopes]
  end

  @spec resource_owners() :: module()
  @doc false
  # NOTE resource_owners is not a macro in order to get config at runtime
  def resource_owners do
    Keyword.fetch!(oauth_config(), :contexts)[:resource_owners]
  end

  @spec oauth_config() :: keyword()
  @doc false
  defp oauth_config do
      Keyword.merge(
        @defaults,
        Application.get_env(:boruta, Boruta.Oauth) || [],
        fn _, a, b ->
          if Keyword.keyword?(a) && Keyword.keyword?(b) do
            Keyword.merge(a, b)
          else
            b
          end
        end
      )
  end
end
