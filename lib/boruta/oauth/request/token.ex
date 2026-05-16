defmodule Boruta.Oauth.Request.Token do
  @moduledoc false

  import Boruta.Oauth.Request.Base

  alias Boruta.ClientsAdapter
  alias Boruta.Oauth
  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.Validator

  @spec request(conn :: Plug.Conn.t() | map()) ::
          {:error,
           %Error{
             :error => :invalid_request,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok,
             oauth_request ::
               AuthorizationCodeRequest.t()
               | ClientCredentialsRequest.t()
               | PasswordRequest.t()}
  def request(%{body_params: body_params} = request) do
    with {:ok, body_params} <- decrypt_request(body_params),
         {:ok, unsigned_params} <- fetch_unsigned_request(request),
         {:ok, client_authentication_params} <- fetch_client_authentication(request),
         {:ok, dpop} <- fetch_dpop(request),
         {:ok, params} <-
           Validator.validate(
             :token,
             body_params
             |> Map.put("dpop", %{dpop: dpop, request: request})
             |> Enum.into(unsigned_params)
             |> Enum.into(client_authentication_params)
           ) do
      build_request(params)
    else
      {:error, error_description} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: error_description
         }}
    end
  end

  def decrypt_request(%{"client_id" => client_id, "encrypted_request" => request} = params) when is_binary(request) do
    with %Oauth.Client{} = client <- ClientsAdapter.get_client(client_id),
         {:ok, request_params} <- Oauth.Client.Crypto.decrypt(request, client) do
      {:ok, Map.merge(params, request_params)}
    else
      _ ->
        {:ok, params}
    end
  end

  def decrypt_request(params), do: {:ok, params}

  defp fetch_dpop(%{req_headers: req_headers}) do
    with {"dpop", dpop} <- List.keyfind(req_headers, "dpop", 0),
         nil <- List.keyfind(req_headers, "dpop", 1) do
      {:ok, dpop}
    else
      {"dpop", _dpop} ->
        {:error, "More than one DPoP header present in the request."}
      _ ->
        {:ok, nil}
    end
  end
end
