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
          resource_owner: resource_owner,
          scope: scope,
          state: state,
          redirect_uri: redirect_uri
        } = params
      ) do
    sub = params[:sub]

    # TODO store resource owner credentials
    token = %Oauth.Token{
      type: "preauthorized_code",
      resource_owner: resource_owner,
      client: client,
      sub: sub,
      state: state,
      nonce: params[:nonce],
      agent_token: params[:agent_token],
      scope: scope,
      redirect_uri: redirect_uri,
      authorization_details: resource_owner.authorization_details
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
