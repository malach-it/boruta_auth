defmodule Boruta.Ecto.PreauthorizedCodes do
  @moduledoc false
  @behaviour Boruta.Openid.PreauthorizedCodes

  import Boruta.Config, only: [token_generator: 0]

  alias Boruta.Ecto.Errors
  alias Boruta.Ecto.TokenStore
  alias Boruta.Oauth

  @impl Boruta.Openid.PreauthorizedCodes
  def create(
        %{
          client:
            %Oauth.Client{
              authorization_code_ttl: authorization_code_ttl
            } = client,
          scope: scope,
          state: state,
          redirect_uri: redirect_uri
        } = params
      ) do
    sub = params[:sub]

    token = %Oauth.Token{
      agent_token: params[:agent_token],
      authorization_details:
        params[:resource_owner] && params[:resource_owner].authorization_details,
      client: client,
      code_challenge: params[:code_challenge],
      code_challenge_method: params[:code_challenge_method],
      id: SecureRandom.uuid(),
      nonce: params[:nonce],
      presentation_definition: params[:presentation_definition],
      previous_code: params[:previous_code],
      public_client_id: params[:public_client_id],
      redirect_uri: redirect_uri,
      resource_owner: params[:resource_owner],
      scope: scope,
      state: state,
      sub: sub,
      type: "preauthorized_code"
    }

    with token <- %{token | tx_code: token_generator().generate(:tx_code, token)},
         token <- %{token | expires_at: :os.system_time(:seconds) + authorization_code_ttl},
         token <- %{token | value: token_generator().generate(:preauthorized_code, token)},
         {:ok, token} <- TokenStore.put(token) do
      {:ok, token}
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        error_message = Errors.message_from_changeset(changeset)

        {:error, "Could not create code : #{error_message}"}
    end
  end
end
