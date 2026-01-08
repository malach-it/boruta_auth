defmodule Boruta.Ecto.PreauthorizedCodes do
  @moduledoc false
  @behaviour Boruta.Openid.PreauthorizedCodes

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto.Errors
  alias Boruta.Ecto.Token
  alias Boruta.Ecto.TokenStore
  alias Boruta.Oauth

  @impl Boruta.Openid.PreauthorizedCodes
  def create(
        %{
          client:
            %Oauth.Client{
              id: client_id,
              authorization_code_ttl: authorization_code_ttl
            } = client,
          scope: scope,
          state: state,
          redirect_uri: redirect_uri
        } = params
      ) do
    sub = params[:sub]

    # TODO store resource owner credentials
    changeset =
      apply(Token, changeset_method(client), [
        %Token{resource_owner: params[:resource_owner]},
        %{
          agent_token: params[:agent_token],
          authorization_code_ttl: authorization_code_ttl,
          authorization_details: params[:authorization_details],
          client_id: client_id,
          code_challenge: params[:code_challenge],
          code_challenge_method: params[:code_challenge_method],
          nonce: params[:nonce],
          presentation_definition: params[:presentation_definition],
          previous_code: params[:previous_code],
          public_client_id: params[:public_client_id],
          redirect_uri: redirect_uri,
          response_type: params[:response_type],
          scope: scope,
          state: state,
          sub: sub
        }
      ])

    with {:ok, token} <- repo().insert(changeset),
         {:ok, token} <- TokenStore.put(to_oauth_schema(token)) do
      {:ok, token}
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        error_message = Errors.message_from_changeset(changeset)

        {:error, "Could not create code : #{error_message}"}
    end
  end

  defp changeset_method(%Oauth.Client{pkce: false}), do: :preauthorized_code_changeset
  defp changeset_method(%Oauth.Client{pkce: true}), do: :pkce_preauthorized_code_changeset
end
