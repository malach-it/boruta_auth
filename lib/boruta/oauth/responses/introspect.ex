defmodule Boruta.Oauth.IntrospectResponse do
  @moduledoc """
  Response returned in case of introspection request success. Provides mandatory data needed to respond to token introspection.
  """

  @type t :: %__MODULE__{
    active: boolean(),
    client_id: String.t(),
    username: String.t(),
    scope: String.t(),
    sub: String.t(),
    iss: String.t(),
    exp: integer(),
    iat: integer(),
    private_key: String.t()
  }

  @enforce_keys [:active]
  defstruct [
    active: nil,
    client_id: nil,
    username: nil,
    scope: nil,
    sub: nil,
    iss: "boruta",
    exp: nil,
    iat: nil,
    private_key: nil
  ]

  alias Boruta.Config
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.IntrospectResponse
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  @spec from_token(token :: Token.t()) :: introspect_response :: t()
  def from_token(%Token{
    client: %Client{id: id, private_key: private_key},
    sub: sub,
    resource_owner: resource_owner,
    expires_at: expires_at,
    scope: scope,
    inserted_at: inserted_at
  }) do
    username = case resource_owner do
      %ResourceOwner{username: username} -> username
      nil -> nil
    end

    %IntrospectResponse{
      active: true,
      client_id: id,
      username: username,
      scope: scope,
      sub: sub,
      iss: Config.issuer(),
      exp: expires_at,
      iat: DateTime.to_unix(inserted_at),
      private_key: private_key
    }
  end

  @spec from_error(error :: Boruta.Oauth.Error.t()) :: introspect_response :: %IntrospectResponse{active: false}
  def from_error(_), do: %IntrospectResponse{active: false}
end
