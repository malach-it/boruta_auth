defmodule Boruta.Ecto.Codes do
  @moduledoc false
  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [repo: 0]
  import Ecto.Query
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto.Errors
  alias Boruta.Ecto.Token
  alias Boruta.Ecto.TokenStore
  alias Boruta.Oauth

  @impl Boruta.Oauth.Codes
  def get_by(value: value, redirect_uri: redirect_uri) do
    with {:ok, token} <- TokenStore.get(value: value),
         true <- token.redirect_uri == redirect_uri do
      token
    else
      {:error, "Not cached."} ->
        with %Token{} = token <-
               repo().one(
                 from t in Token,
                   where:
                     t.type in ["code", "preauthorized_code"] and t.value == ^value and
                       t.redirect_uri == ^redirect_uri
               ),
             {:ok, token} <-
               token
               |> to_oauth_schema()
               |> TokenStore.put() do
          token
        end

      false ->
        nil
    end
  end

  def get_by(id: id) do
    with {:ok, id} <- Ecto.UUID.cast(id),
     {:ok, token} <- TokenStore.get(id: id) do
        token
    else
      :error -> nil
      {:error, "Not cached."} ->
        with %Token{} = token <-
               repo().one(
                 from t in Token,
                   where: t.type in ["code", "preauthorized_code"] and t.id == ^id
               ),
             {:ok, token} <-
               token
               |> to_oauth_schema()
               |> TokenStore.put() do
          token
        end
    end
  end

  def get_by(value: value) do
    case TokenStore.get(value: value) do
      {:ok, token} ->
        token

      {:error, "Not cached."} ->
        with %Token{} = token <-
               repo().one(
                 from t in Token,
                   where: t.type in ["code", "preauthorized_code"] and t.value == ^value
               ),
             {:ok, token} <-
               token
               |> to_oauth_schema()
               |> TokenStore.put() do
          token
        end
    end
  end

  @impl Boruta.Oauth.Codes
  def create(
        %{
          client:
            %Oauth.Client{
              id: client_id,
              authorization_code_ttl: authorization_code_ttl
            } = client,
          redirect_uri: redirect_uri,
          scope: scope,
          state: state,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          authorization_details: authorization_details
        } = params
      ) do
    sub = params[:sub]

    changeset =
      apply(Token, changeset_method(client), [
        %Token{resource_owner: params[:resource_owner]},
        %{
          client_id: client_id,
          sub: sub,
          redirect_uri: redirect_uri,
          state: state,
          nonce: params[:nonce],
          scope: scope,
          authorization_code_ttl: authorization_code_ttl,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          authorization_details: authorization_details,
          presentation_definition: params[:presentation_definition],
          public_client_id: params[:public_client_id],
          relying_party_redirect_uri: params[:relying_party_redirect_uri],
          previous_code: params[:previous_code]
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

  defp changeset_method(%Oauth.Client{pkce: false}), do: :code_changeset
  defp changeset_method(%Oauth.Client{pkce: true}), do: :pkce_code_changeset

  @impl Boruta.Oauth.Codes
  def revoke(%Oauth.Token{value: value} = code) do
    with %Token{} = token <- repo().get_by(Token, value: value),
         {:ok, token} <-
           Token.revoke_changeset(token)
           |> repo().update(),
         {:ok, _token} <- TokenStore.invalidate(code) do
      {:ok, token}
    else
      nil ->
        {:error, "Code not found."}

      error ->
        error
    end
  end

  @impl Boruta.Oauth.Codes
  def revoke_previous_token(%Oauth.Token{value: value} = code) do
    with %Token{} = previous_token <- repo().get_by(Token, previous_code: value),
         {:ok, _token} <-
           Token.revoke_changeset(previous_token)
           |> repo().update() do
      {:ok, code}
    end
  end
end
