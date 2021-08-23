defmodule Boruta.Oauth.PasswordRequest do
  @moduledoc """
  Resource owner password credentials request
  """

  @typedoc """
  Type representing a resource owner password credentials request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.3.2).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_secret: String.t(),
          username: String.t(),
          password: String.t(),
          scope: String.t(),
          grant_type: String.t()
        }
  @enforce_keys [:client_id, :client_secret, :username, :password]
  defstruct client_id: nil,
            client_secret: nil,
            username: "",
            password: "",
            scope: "",
            grant_type: "password"
end
