defmodule Boruta.Oauth.ResourceOwner do
  @moduledoc """
  Oauth resource owner schema
  """

  @enforce_keys [:sub]
  defstruct sub: nil,
            username: nil,
            last_login_at: nil,
            extra_claims: %{},
            authorization_details: [],
            presentation_configuration: %{},
            credential_configuration: %{}

  @type t :: %__MODULE__{
          sub: String.t(),
          username: String.t() | nil,
          last_login_at: DateTime.t() | nil,
          extra_claims: Boruta.Oauth.IdToken.claims(),
          authorization_details: list(map()),
          presentation_configuration: %{
            String.t() => %{
              definition: map()
            }
          },
          credential_configuration: %{
            String.t() => %{
              version: String.t(),
              vct: String.t() | nil,
              defered: boolean(),
              types: list(String.t()),
              format: list(String.t()),
              time_to_live: integer(),
              claims: list(String.t() | %{
                String.t() => String.t()
              })
            }
          }
        }
end
