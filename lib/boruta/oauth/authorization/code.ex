defmodule Boruta.Oauth.Authorization.Code do
  @moduledoc """
  Check against given params and return the corresponding code
  """

  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token

  @doc """
  Authorize the code corresponding to the given params.

  ## Examples
      iex> authorize(value: "value", redirect_uri: "redirect_uri")
      {:ok, %Boruta.Oauth.Token{...}}
  """
  @spec authorize(
          %{
            value: String.t(),
            client: Client.t(),
            code_verifier: String.t(),
            redirect_uri: String.t()
          }
          | %{value: String.t()}
        ) ::
          {:error,
           %Error{
             :error => :invalid_code,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok, Token.t()}
  def authorize(%{
        value: value,
        redirect_uri: redirect_uri,
        client: %Client{id: client_id, pkce: false}
      }) do
    case CodesAdapter.get_by(value: value, redirect_uri: redirect_uri) do
      %Token{client: %Client{id: ^client_id}} = token ->
        case Token.ensure_valid(token) do
          :ok ->
            {:ok, token}

          {:error, _error} ->
            CodesAdapter.revoke_previous_token(token)

            {:error,
             %Error{
               status: :bad_request,
               error: :invalid_grant,
               error_description: "Given authorization code is invalid, revoked, or expired."
             }}
        end

      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given authorization code is invalid, revoked, or expired."
         }}
    end
  end

  def authorize(%{
        value: value,
        redirect_uri: redirect_uri,
        client: %Client{id: client_id, pkce: true},
        code_verifier: code_verifier
      }) do
    with %Token{client: %Client{id: ^client_id}} = token <-
           CodesAdapter.get_by(value: value, redirect_uri: redirect_uri),
         :ok <- check_code_challenge(token, code_verifier),
         :ok <- Token.ensure_valid(token) do
      {:ok, token}
    else
      {:error, :invalid_code_verifier} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code verifier is invalid."
         }}

      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given authorization code is invalid, revoked, or expired."
         }}
    end
  end

  def authorize(%{value: value}) do
    with %Token{} = token <-
           CodesAdapter.get_by(value: value),
         :ok <- Token.ensure_valid(token) do
      {:ok, token}
    else
      {:error, :invalid_code_verifier} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code verifier is invalid."
         }}

      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given authorization code is invalid, revoked, or expired."
         }}
    end
  end

  defp check_code_challenge(
         %Token{
           code_challenge_hash: code_challenge_hash,
           code_challenge_method: "plain"
         },
         code_verifier
       ) do
    case Token.hash(code_verifier) == code_challenge_hash do
      true -> :ok
      false -> {:error, :invalid_code_verifier}
    end
  end

  defp check_code_challenge(
         %Token{
           code_challenge_hash: code_challenge_hash,
           code_challenge_method: "S256"
         },
         code_verifier
       ) do
    case :crypto.hash(:sha256, code_verifier) |> Base.url_encode64(padding: false) |> Token.hash() ==
           code_challenge_hash do
      true -> :ok
      false -> {:error, :invalid_code_verifier}
    end
  end
end
