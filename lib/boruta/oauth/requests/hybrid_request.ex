defmodule Boruta.Oauth.HybridRequest do
  @moduledoc """
  Hybrid request
  """

  @typedoc """
  Type representing an hybrid request as stated in [OpenId Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth).

  Note : `resource_owner` is an addition that must be provided by the application layer.
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          state: String.t(),
          nonce: String.t(),
          scope: String.t(),
          resource_owner: struct(),
          grant_type: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          response_types: list(String.t())
        }
  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct client_id: nil,
            redirect_uri: nil,
            state: "",
            nonce: "",
            scope: "",
            resource_owner: nil,
            grant_type: "authorization_code",
            code_challenge: "",
            code_challenge_method: "plain",
            response_types: [],
            prompt: ""
end
