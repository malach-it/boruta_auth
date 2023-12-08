defmodule Boruta.Openid.CredentialOfferResponse do
  @moduledoc """
  Response returned in case of pre authorized code request success. Provides utilities and mandatory data needed to respond to the authorize part of pre-authorized code flow.
  """

  @enforce_keys [:credential_issuer]
  defstruct credential_issuer: nil,
    credentials: [],
    grants: %{}

  alias Boruta.Config
  alias Boruta.Oauth.PreauthorizedCodeRequest

  @type t :: %__MODULE__{
    credential_issuer: String.t(),
    credentials: list(String.t()),
    grants: %{
      optional(String.t()) => map()
    }
  }

  def from_tokens(%{
    preauthorized_code: preauthorized_code
  }, %PreauthorizedCodeRequest{
    resource_owner: resource_owner
  }) do
    %__MODULE__{
      credential_issuer: Config.issuer(),
      credentials: resource_owner.available_credentials,
      grants: %{
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
          "pre-authorized_code" => preauthorized_code.value
        }
      }
    }
  end
end
