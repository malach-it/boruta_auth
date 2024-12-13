defmodule Boruta.Oauth.Authorization.AccessToken do
  @moduledoc """
  Check against given params and return the corresponding access token
  """

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token

  @doc """
  Authorize the access token corresponding to the given params.

  ## Examples
      iex> authorize(%{value: "value"})
      {:ok, %Boruta.Oauth.Token{...}}
  """
  @spec authorize(
          params ::
            [value: String.t()]
            | [refresh_token: String.t()]
        ) ::
          {:error,
           %Error{
             :error => :invalid_access_token,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :unauthorized
           }}
          | {:ok, %Token{}}
  def authorize(value: value) do
    with %Token{} = token <- Boruta.AccessTokensAdapter.get_by(value: value),
         :ok <- Token.ensure_valid(token) do
      {:ok, token}
    else
      {:error, msg} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_access_token,
           error_description: msg
         }}
      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_access_token,
           error_description: "Given access token is invalid."
         }}
    end
  end

  def authorize(refresh_token: refresh_token) do
    with %Token{} = token <- Boruta.AccessTokensAdapter.get_by(refresh_token: refresh_token),
      :ok <- Token.ensure_valid(token, :refresh_token) do
      {:ok, token}
    else
      _ ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given refresh token is invalid, revoked, or expired."
         }}
    end
  end
end
