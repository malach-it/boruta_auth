defmodule Boruta.Openid.Clients do
  @moduledoc false

  # NOTE params inherited from Dynamic registration specification https://openid.net/specs/openid-connect-registration-1_0.html
  @type registration_params :: %{
          redirect_uris: list(String.t())
          # optional fields
          # response_types: list(String.t()), # TODO add response type configuration to clients
          # grant_types: list(String.t()),
          # application_type: String.t(), # TODO enforce validation according to the specs
          # contacts: list(String.t()), # TODO add this field to clients
          # client_name: String.t(),
          # logo_uri: String.t(), # TODO add this field to clients
          # client_uri: String.t(), # TODO add this field to clients
          # policy_uri: String.t(), # TODO add this field to clients
          # tos_uri: String.t(), # TODO add this field to clients
          # jwks_uri: String.t(), # NOTE this field cannot be configured yet
          # jwks: %{keys: %JOSE.JWK{}},
          # sector_identifier_uri: String.t(), # TODO add this field to clients
          # subject_type: String.t(), # TODO find out what it is
          # id_token_signed_response_alg: String.t(),
          # id_token_encrypted_response_alg: String.t(), # TODO client id token encryption configuration
          # userinfo_signed_response: String.t(), # TODO sign userinfo responses
          # userinfo_encrypted_response_alg: String.t(), # TODO encrypt userinfo response
          # userinfo_encrypted_response_enc: String.t(), # TODO find out what it is
          # request_object_signing_alg: String.t(), # TODO add request object signing alg configuration to clients
          # request_object_encryption_alg: String.t(), # TODO enable encryption for request objects
          # request_object_encryption_enc: String.t(), # TODO find out what it is
          # token_endpoint_auth_method: String.(), # TODO add token endpoint auth method configuration to clients
          # token_endpoint_auth_signing_alg: String.(), # TODO implement jwt token endpoint auth methods
          # default_max_age: integer(), # TODO add max age configuration to clients
          # require_auth_time: bolean(), # TODO add auth_time configuration to clients
          # default_acr_values: list(String.t()), # TODO implement acr values
          # inititiate_login_uri: String.t(), # NOTE cannot be configured yet
          # request_uris: list(String.t()) # TODO add caching abilities
        }

  @callback create_client(params :: registration_params()) ::
              {:ok, client :: Boruta.Oauth.Client.t()} | {:error, Ecto.Changeset.t()}
end
