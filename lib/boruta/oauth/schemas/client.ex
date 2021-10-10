defmodule Boruta.Oauth.Client do
  @moduledoc """
  OAuth client schema
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

  @spec grant_type_supported?(client :: t(), grant_type :: String.t()) :: boolean()
  def grant_type_supported?(%__MODULE__{supported_grant_types: supported_grant_types}, grant_type) do
    Enum.member?(supported_grant_types, grant_type)
  end

  @spec check_secret(client :: t(), secret :: String.t()) :: :ok | {:error, String.t()}
  def check_secret(%__MODULE__{secret: client_secret}, secret) do
    case client_secret == secret do
      true -> :ok
      false -> {:error, "Invalid client secret."}
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
