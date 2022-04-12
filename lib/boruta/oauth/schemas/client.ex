defmodule Boruta.Oauth.Client do
  @moduledoc """
  OAuth client schema and utilities
  """

  @enforce_keys [:id]
  defstruct id: nil,
            name: nil,
            secret: nil,
            authorize_scope: nil,
            authorized_scopes: [],
            redirect_uris: [],
            supported_grant_types: [],
            access_token_ttl: nil,
            id_token_ttl: nil,
            authorization_code_ttl: nil,
            refresh_token_ttl: nil,
            pkce: nil,
            public_refresh_token: nil,
            public_revoke: nil,
            public_key: nil,
            private_key: nil

  @type t :: %__MODULE__{
          id: any(),
          secret: String.t(),
          name: String.t(),
          authorize_scope: boolean(),
          authorized_scopes: list(Boruta.Oauth.Scope.t()),
          redirect_uris: list(String.t()),
          supported_grant_types: list(String.t()),
          access_token_ttl: integer(),
          id_token_ttl: integer(),
          authorization_code_ttl: integer(),
          refresh_token_ttl: integer(),
          pkce: boolean(),
          public_refresh_token: boolean(),
          public_revoke: boolean(),
          public_key: String.t(),
          private_key: String.t()
        }

  @grant_types [
    "client_credentials",
    "password",
    "authorization_code",
    "refresh_token",
    "implicit",
    "revoke",
    "introspect"
  ]

  @doc """
  Returns grant types supported by the server. `Boruta.Oauth.Client` `supported_grant_types` attribute may be a subset of them.
  """
  @spec grant_types() :: grant_types :: list(String.t())
  def grant_types, do: @grant_types

  @spec grant_type_supported?(client :: t(), grant_type :: String.t()) :: boolean()
  def grant_type_supported?(%__MODULE__{supported_grant_types: supported_grant_types}, grant_type) do
    Enum.member?(supported_grant_types, grant_type)
  end

  @spec check_secret(client :: t(), secret :: String.t()) :: :ok | {:error, String.t()}
  def check_secret(%__MODULE__{secret: secret}, secret), do: :ok
  def check_secret(_client, _secret), do: {:error, "Invalid client secret."}

  @spec check_redirect_uri(client :: t(), redirect_uri :: String.t()) ::
          :ok | {:error, String.t()}
  def check_redirect_uri(%__MODULE__{redirect_uris: client_redirect_uris}, redirect_uri) do
    case Enum.any?(client_redirect_uris, fn client_redirect_uri ->
           redirect_uri_regex =
             client_redirect_uri
             |> Regex.escape()
             |> String.replace("\\*", "([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9])")
             |> Regex.compile!()

           Regex.match?(redirect_uri_regex, redirect_uri)
         end) do
      true -> :ok
      false -> {:error, "Client redirect_uri do not match."}
    end
  end

  @spec public_refresh_token?(client :: t()) :: boolean()
  def public_refresh_token?(%__MODULE__{public_refresh_token: public_refresh_token}) do
    public_refresh_token
  end

  @spec public_revoke?(client :: t()) :: boolean()
  def public_revoke?(%__MODULE__{public_revoke: public_revoke}) do
    public_revoke
  end
end
