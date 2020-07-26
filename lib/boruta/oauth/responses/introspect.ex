defmodule Boruta.Oauth.IntrospectResponse do
  @moduledoc """
  Introspect response
  """

  import Boruta.Config, only: [resource_owners: 0]

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
  alias Boruta.Oauth.Token

  def from_token(%Token{
    client: client,
    resource_owner: resource_owner,
    expires_at: expires_at,
    scope: scope,
    inserted_at: inserted_at
  }) do
    %IntrospectResponse{
      active: true,
      client_id: client.id,
      username: resource_owners().username(resource_owner),
      scope: scope,
      sub: resource_owners().sub(resource_owner),
      iss: "boruta", # TODO change to hostname
      exp: expires_at,
      iat: DateTime.to_unix(inserted_at)
    }
  end

  def from_error(_), do: %IntrospectResponse{active: false}
end
