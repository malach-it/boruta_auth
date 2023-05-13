defmodule Boruta.Oauth.Request.Introspect do
  @moduledoc false

  import Boruta.Oauth.Request.Base

  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.Validator

  @spec request(conn :: map()) ::
          {:error,
           %Boruta.Oauth.Error{
             :error => :invalid_request,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok, request :: IntrospectRequest.t()}
  def request(%{body_params: body_params} = request) do
    with {:ok, client_authentication_params} <- fetch_client_authentication(request),
         {:ok, params} <-
           Validator.validate(
             :introspect,
             body_params
             |> Enum.into(client_authentication_params)
             |> Enum.into(%{"response_type" => "introspect"})
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
end
