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
      :error ->
        nil

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
        with "" <> value <- value,
             %Token{} = token <-
               repo().one(
                 from t in Token,
                   where: t.type in ["code", "preauthorized_code"] and t.value == ^value
               ),
             {:ok, token} <-
               token
               |> to_oauth_schema()
               |> TokenStore.put() do
          token
        else
          {:error, error} -> {:error, error}
          nil -> {:error, "Code not found."}
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
          response_type: params[:response_type],
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
          client_encryption_key: params[:client_encryption_key],
          client_encryption_alg: params[:client_encryption_alg],
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
  def update_client_encryption(%Oauth.Token{value: value} = code, params) do
    with %Token{} = token <- repo().get_by(Token, value: value),
         {:ok, token} <- Token.client_encryption_changeset(token, params) |> repo().update(),
         {:ok, _token} <- TokenStore.invalidate(code) do
      {:ok, to_oauth_schema(token)}
    end
  end

  @impl Boruta.Oauth.Codes
  def revoke(codes) when is_list(codes) do
    code_count = Enum.count(codes)
    code_ids = Enum.map(codes, fn code -> code.id end)
    now = DateTime.utc_now()

    with {^code_count, _} <-
           from(t in Token, where: t.id in ^code_ids)
           |> repo().update_all(set: [revoked_at: now]),
         :ok <-
           Enum.reduce(codes, :ok, fn code, acc ->
             case TokenStore.invalidate(code) do
               {:ok, _token} ->
                 acc

               error ->
                 error
             end
           end) do
      {:ok, Enum.map(codes, fn code -> %{code | revoked_at: now} end)}
    else
      _ -> {:error, "Could not revoke code chain."}
    end
  end

  def revoke(%Oauth.Token{value: value} = code) do
    with %Token{} = token <- repo().get_by(Token, value: value),
         {:ok, token} <-
           Token.revoke_changeset(token)
           |> repo().update(),
         {:ok, _token} <- TokenStore.invalidate(code) do
      {:ok, to_oauth_schema(token)}
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

  @impl Boruta.Oauth.Codes
  def update_sub(%Oauth.Token{id: id}, sub, metadata_policy) do
    with %Token{} = code <-
           repo().one(
             from t in Token,
               where: t.type in ["code", "preauthorized_code"] and t.id == ^id
           ),
         {:ok, code} <- Token.sub_changeset(code, sub, metadata_policy) |> repo().update(),
         {:ok, code} <- TokenStore.invalidate(code) do
      {:ok, to_oauth_schema(code)}
    else
      _ ->
        {:error, "Preauthorized code not found."}
    end
  end

  @impl Boruta.Oauth.Codes
  def code_chain(token, acc \\ [])

  def code_chain(%Oauth.Token{previous_code: nil} = code, acc) do
    Enum.reject([code | acc], &is_nil/1) |> Enum.reverse()
  end

  def code_chain(%Oauth.Token{type: "preauthorized_code", previous_code: value} = code, acc) do
    case code_chain(get_by(value: value)) do
      chain when is_list(chain) ->
        [code | acc ++ chain]

      _ ->
        acc
    end
  end

  def code_chain(%Oauth.Token{type: "code", previous_code: value} = code, acc) do
    case code_chain(get_by(value: value)) do
      chain when is_list(chain) ->
        [code | acc ++ chain]

      _ ->
        acc
    end
  end

  def code_chain(nil, _acc), do: {:error, "Previous code not found."}
end
