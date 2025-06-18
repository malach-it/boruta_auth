defmodule Boruta.Oauth.PreauthorizedCodeRequest do
  @moduledoc """
  Preauthorized code request
  """

  @typedoc """
  Type representing a code request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.1.1).

  Note : `resource_owner` is an addition that must be provided by the application layer.
  """
  @type t :: %__MODULE__{
          agent_token: String.t() | nil,
          client_id: String.t(),
          redirect_uri: String.t(),
          state: String.t(),
          prompt: String.t(),
          scope: String.t(),
          resource_owner: struct(),
          response_type: String.t(),
          grant_type: String.t()
        }

  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct agent_token: nil,
            client_id: nil,
            redirect_uri: nil,
            state: "",
            prompt: "",
            scope: "",
            resource_owner: nil,
            response_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            grant_type: "preauthorized_code"
end
