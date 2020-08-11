defmodule Boruta.Oauth.IntrospectResponse do
  @moduledoc """
  Introspect response
  """

  @type t :: %__MODULE__{
    active: boolean(),
    client_id: String.t(),
    username: String.t(),
    scope: String.t(),
    sub: String.t(),
    iss: String.t(),
    exp: integer(),
    iat: integer()
  }

  defstruct [
    active: nil,
    client_id: nil,
    username: nil,
    scope: nil,
    sub: nil,
    iss: "boruta",
    exp: nil,
    iat: nil
  ]

  alias Boruta.Oauth.IntrospectResponse
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def from_token(%Token{
    client: client,
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
      client_id: client.id,
      username: username,
      scope: scope,
      sub: sub,
      iss: "boruta", # TODO change to hostname
      exp: expires_at,
      iat: DateTime.to_unix(inserted_at)
    }
  end

  def from_error(_), do: %IntrospectResponse{active: false}
end
