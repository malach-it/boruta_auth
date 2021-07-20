defmodule Boruta.Oauth.TokenResponse do
  @moduledoc """
  Token response
  """

  defstruct token_type: "bearer",
            access_token: nil,
            expires_in: nil,
            refresh_token: nil,
            id_token: nil

  @type t :: %__MODULE__{
          token_type: String.t(),
          access_token: String.t(),
          id_token: String.t(),
          expires_in: integer(),
          refresh_token: String.t()
        }

  alias Boruta.Oauth.Token
  alias Boruta.Oauth.TokenResponse

  @spec from_token(%{
    (type :: :token | :id_token) => token :: Boruta.Oauth.Token.t() | String.t()
  }) :: t()
  def from_token(
        %{
          token: %Token{
            value: value,
            expires_at: expires_at,
            refresh_token: refresh_token
          }
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %TokenResponse{
      access_token: value,
      token_type: "bearer",
      expires_in: expires_in,
      refresh_token: refresh_token,
      id_token: params[:id_token] && params[:id_token].value
    }
  end
end
