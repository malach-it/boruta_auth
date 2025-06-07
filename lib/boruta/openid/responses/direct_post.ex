defmodule Boruta.Openid.DirectPostResponse do
  @moduledoc """
  Response in case of direct post request
  """

  defstruct [
    :id_token,
    :vp_token,
    :token,
    :code,
    :redirect_uri,
    :state
  ]

  @type t :: %__MODULE__{
    id_token: String.t() | nil,
    vp_token: String.t() | nil,
    code: Boruta.Oauth.Token.t(),
    token: Boruta.Oauth.Token.t() | nil,
    redirect_uri: String.t(),
    state: String.t() | nil
  }
end
