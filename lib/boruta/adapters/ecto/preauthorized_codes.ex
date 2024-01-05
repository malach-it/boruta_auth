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
          resource_owner: resource_owner,
          scope: scope,
          state: state,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        } = params
      ) do
    sub = params[:sub]

    # TODO store resource owner credentials
    changeset =
      apply(Token, changeset_method(client), [
        %Token{resource_owner: resource_owner},
        %{
          client_id: client_id,
          sub: sub,
          state: state,
          nonce: params[:nonce],
          scope: scope,
          authorization_code_ttl: authorization_code_ttl,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          authorization_details: resource_owner.authorization_details
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
