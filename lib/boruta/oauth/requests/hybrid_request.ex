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
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          grant_type: String.t(),
          nonce: String.t(),
          redirect_uri: String.t(),
          resource_owner: struct(),
          response_mode: String.t(),
          response_types: list(String.t()),
          scope: String.t(),
          state: String.t(),
          authorization_details: String.t()
        }
  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct client_id: nil,
            code_challenge: "",
            code_challenge_method: "plain",
            grant_type: "authorization_code",
            nonce: "",
            prompt: "",
            redirect_uri: nil,
            resource_owner: nil,
            response_mode: "fragment",
            response_types: [],
            scope: "",
            state: "",
            authorization_details: "[]"
end
