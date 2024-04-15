defmodule Boruta.Oauth.PresentationDefinitionRequest do
  @moduledoc """
  Presentation definition request
  """

  @typedoc """
  Type representing a presentation definition request as stated in [OpenID for Verifiable Presentations - draft 20](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          presentation_definition: String.t(),
          nonce: String.t()
        }
  @enforce_keys [:client_id, :redirect_uri, :presentation_definition, :nonce]
  defstruct client_id: nil,
            redirect_uri: nil,
            presentation_definition: nil,
            nonce: nil
end
