defmodule Boruta.Openid.CredentialOfferResponse do
  @moduledoc """
  Response returned in case of pre authorized code request success. Provides utilities and mandatory data needed to respond to the authorize part of pre-authorized code flow.
  """

  @enforce_keys [:credential_issuer]
  defstruct credential_issuer: nil,
            # draft 13
            credential_configuration_ids: [],
            # draft 11
            credentials: [],
            grants: %{},
            tx_code: nil,
            tx_code_required: nil

  alias Boruta.Config
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.PreauthorizedCodeRequest

  @type t :: %__MODULE__{
          credential_issuer: String.t(),
          credential_configuration_ids: list(String.t()),
          credentials: list(String.t()),
          grants: %{
            optional(String.t()) => map()
          },
          tx_code: String.t(),
          tx_code_required: boolean()
        }

  def from_tokens(
        %{
          preauthorized_code: preauthorized_code
        },
        %PreauthorizedCodeRequest{
          resource_owner: resource_owner
        }
      ) do
    credential_identifiers =
      Enum.flat_map(resource_owner.authorization_details, fn detail ->
        detail["credential_identifiers"] || []
      end)
      |> Enum.uniq()

    credentials =
      Enum.reject(resource_owner.credential_configuration, fn {_identifier, configuration} ->
        not Enum.empty?(configuration[:types] -- credential_identifiers)
      end)
      |> Enum.group_by(fn {_identifier, configuration} ->
        configuration[:format]
      end)
      |> Enum.reduce(%{}, fn {format, configurations}, acc ->
        types =
          Enum.flat_map(configurations, fn {_identifier, configuration} ->
            configuration[:types]
          end)

        case acc[format] do
          nil ->
            Map.put(acc, format, types)

          types ->
            acc[format] ++ types
        end
      end)
      |> Enum.map(fn {format, types} ->
        %{
          format: format,
          types: Enum.uniq(types)
        }
      end)

    credential_configuration_ids =
      Enum.map(resource_owner.authorization_details, fn detail ->
        detail["credential_configuration_id"]
      end)
      |> Enum.uniq()

    grant = %{"pre-authorized_code" => preauthorized_code.value}

    grant =
      case preauthorized_code.client do
        %Client{enforce_tx_code: true} ->
          Map.put(grant, "tx_code", %{
            "length" => Config.token_generator().tx_code_length(),
            "input_mode" => Config.token_generator().tx_code_input_mode(),
            "description" => "Please provide the one-time code that was sent via e-mail"
          })

        _ ->
          grant
      end

    %__MODULE__{
      credential_issuer: Config.issuer(),
      credential_configuration_ids: credential_configuration_ids,
      credentials: credentials,
      tx_code: preauthorized_code.tx_code,
      grants: %{
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => grant
      },
      tx_code_required: preauthorized_code.client.enforce_tx_code
    }
  end
end
