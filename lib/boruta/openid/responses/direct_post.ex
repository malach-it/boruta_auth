defmodule Boruta.Openid.DirectPostResponse do
  @moduledoc """
  Response in case of direct post request
  """

  defstruct [
    :id_token,
    :vp_token,
    :code,
    :code_chain,
    :redirect_uri,
    :client_encryption_key,
    :client_encryption_alg,
    :response_types,
    :state,
    :presentation_definition,
    :error
  ]

  @type t :: %__MODULE__{
    id_token: String.t() | nil,
    vp_token: String.t() | nil,
    code: Boruta.Oauth.Token.t(),
    code_chain: list(Boruta.Oauth.Token.t()),
    redirect_uri: String.t(),
    client_encryption_key: map() | nil,
    client_encryption_alg: String.t() | nil,
    response_types: String.t(),
    state: String.t() | nil,
    presentation_definition: map() | nil,
    error: Boruta.Oauth.Error.t() | nil
  }
end
