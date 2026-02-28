defmodule Boruta.Oauth.PresentationRequest do
  @moduledoc """
  Code request
  """

  @typedoc """
  Type representing a SiopV2 request as stated in [Self-Issued OpenID Provider v2 - draft 13](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          resource_owner: Boruta.Oauth.ResourceOwner.t(),
          redirect_uri: String.t(),
          state: String.t(),
          nonce: String.t(),
          prompt: String.t(),
          scope: String.t(),
          grant_type: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          response_type: String.t(),
          client_metadata: String.t(),
          authorization_details: String.t(),
          code: String.t()
        }

  @enforce_keys [:client_id, :redirect_uri]
  defstruct client_id: nil,
            resource_owner: nil,
            redirect_uri: nil,
            state: "",
            nonce: "",
            prompt: "",
            scope: "",
            response_type: "id_token",
            grant_type: "siopv2",
            code_challenge: "",
            code_challenge_method: "plain",
            authorization_details: "[]",
            client_metadata: "{}",
            code: nil
end
