defmodule Boruta.Oauth.Request.Authorize do
  @moduledoc false

  import Boruta.Oauth.Request.Base

  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.TokenRequest
  alias Boruta.Oauth.Validator

  @spec request(conn :: map(), resource_owner :: struct()) ::
          {:error,
           %Boruta.Oauth.Error{
             :error => :invalid_request,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok,
             oauth_request ::
               CodeRequest.t()
               | TokenRequest.t()
               | HybridRequest.t()}
  def request(%{query_params: query_params} = request, resource_owner) do
    with {:ok, unsigned_params} <- fetch_unsigned_request(request),
         {:ok, params} <-
           Validator.validate(
             :authorize,
             query_params
             |> Enum.into(unsigned_params)
           ) do
      build_request(Enum.into(params, %{"resource_owner" => resource_owner}))
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

  def pushed_request(%{body_params: body_params} = request) do
    with {:ok, unsigned_params} <- fetch_unsigned_request(request),
         {:ok, params} <-
           Validator.validate(
             :authorize,
             body_params
             |> Enum.into(unsigned_params)
           ) do
      build_request(Enum.into(params, %{"method" => "POST"}))
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
end
