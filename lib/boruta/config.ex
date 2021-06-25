defmodule Boruta.Config do
  @moduledoc """
  Utilities to access Boruta configuration ad set defaults.

  Configuration can be set as following in `config.exs` (this configuration is the default)
  ```
  config :boruta, Boruta.Oauth,
    repo: MyApp.Repo, # mandatory
    cache_backend: Boruta.Cache,
    contexts: [
      access_tokens: Boruta.Ecto.AccessTokens,
      clients: Boruta.Ecto.Clients,
      codes: Boruta.Ecto.Codes,
      resource_owners: MyApp.ResourceOwners, # mandatory for user flows
      scopes: Boruta.Ecto.Scopes
    ],
    max_ttl: [
      authorization_code: 60,
      access_token: 60 * 60 * 24
    ],
    token_generator: Boruta.TokenGenerator
  ```
  """

  @defaults repo: Boruta.Repo,
    cache_backend: Boruta.Cache,
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

  @spec cache_backend() :: module()
  @doc false
  def cache_backend do
    Keyword.fetch!(oauth_config(), :cache_backend)
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
