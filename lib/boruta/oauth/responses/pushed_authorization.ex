defmodule Boruta.Oauth.PushedAuthorizationResponse do
  @moduledoc """
  Response returned in case of pushed authorization request success. Provides utilities and mandatory data needed to respond to the pushed authorize part of implicit, code and hybrid flows.
  """

  alias Boruta.Oauth.AuthorizationRequest

  @enforce_keys [:request_uri, :expires_in]
  defstruct request_uri: nil,
            expires_in: nil

  @type t :: %__MODULE__{
          request_uri: String.t(),
          expires_in: integer()
        }

  @spec from_request(request :: AuthorizationRequest.t()) :: t()
  def from_request(%AuthorizationRequest{id: request_id, expires_at: expires_at}) do
    request_uri = "urn:ietf:params:oauth:request_uri:#{request_id}"
    expires_in = expires_at - :os.system_time(:seconds)

    %__MODULE__{
      request_uri: request_uri,
      expires_in: expires_in
    }
  end
end
