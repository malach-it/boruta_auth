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
    :response_types,
    :state,
    :error
  ]

  @type t :: %__MODULE__{
    id_token: String.t() | nil,
    vp_token: String.t() | nil,
    code: Boruta.Oauth.Token.t(),
    code_chain: list(Boruta.Oauth.Token.t()),
    redirect_uri: String.t(),
    response_types: String.t(),
    state: String.t() | nil,
    error: Boruta.Oauth.Error.t() | nil
  }
end
