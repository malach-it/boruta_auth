defmodule Boruta.Oauth.PreauthorizedCodeRequest do
  @moduledoc """
  Code request
  """

  @typedoc """
  Type representing a code request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.1.1).

  Note : `resource_owner` is an addition that must be provided by the application layer.
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          state: String.t(),
          prompt: String.t(),
          scope: String.t(),
          resource_owner: struct(),
          grant_type: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          grant_type: String.t()
        }

  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct client_id: nil,
            redirect_uri: nil,
            state: "",
            prompt: "",
            scope: "",
            resource_owner: nil,
            response_type: "code",
            code_challenge: "",
            code_challenge_method: "plain",
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
end
