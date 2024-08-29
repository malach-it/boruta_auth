defmodule Boruta.Openid.UserinfoResponse do
  @moduledoc false

  @enforce_keys [:userinfo, :format]
  defstruct userinfo: nil, jwt: nil, format: nil

  alias Boruta.Oauth.Client

  @type t() :: %__MODULE__{
          userinfo: String.t(),
          jwt: String.t() | nil,
          format: :json | :jwt
        }

  @spec from_userinfo(userinfo :: map(), client :: Client.t()) :: t()
  def from_userinfo(
        userinfo,
        %Client{userinfo_signed_response_alg: nil}
      ) do
    %__MODULE__{
      userinfo: userinfo,
      format: :json
    }
  end

  def from_userinfo(userinfo, client) do
    %__MODULE__{
      userinfo: userinfo,
      jwt: Client.Crypto.userinfo_sign(userinfo, client),
      format: :jwt
    }
  end

  @spec content_type(response :: t()) :: content_type :: String.t()
  def content_type(%__MODULE__{format: :json}) do
    "application/json"
  end

  def content_type(%__MODULE__{format: :jwt}) do
    "application/jwt"
  end

  @spec payload(response :: t()) :: payload :: map() | String.t()
  def payload(%__MODULE__{userinfo: userinfo, format: :json}) do
    userinfo
  end

  def payload(%__MODULE__{jwt: jwt, format: :jwt}) do
    jwt
  end
end
