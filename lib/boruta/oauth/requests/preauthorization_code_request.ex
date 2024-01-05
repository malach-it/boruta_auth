defmodule Boruta.Oauth.PreauthorizationCodeRequest do
  @moduledoc """
  Preauthorization code request
  """

  @typedoc """
  Type representing an authorization code request following the pre-authorized code flow as stated in [OpenID for Verifiable Credential Issuance - draft 12](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).


  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          preauthorized_code: String.t(),
          grant_type: String.t(),
          code_verifier: String.t()
        }
  @enforce_keys [:client_id, :client_authentication, :preauthorized_code]
  defstruct client_id: nil,
            client_authentication: nil,
            preauthorized_code: nil,
            grant_type: "authorization_code",
            code_verifier: ""
end
