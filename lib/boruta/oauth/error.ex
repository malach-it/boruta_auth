defmodule Boruta.Oauth.Error do
  @moduledoc """
  Boruta OAuth errors

  > __Note__: Intended to follow [OAuth 2.0 errors](https://tools.ietf.org/html/rfc6749#section-5.2). Additional errors are provided as purpose.
  """

  alias Boruta.Oauth.AuthorizationRequest
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.PreauthorizedCodeRequest
  alias Boruta.Oauth.PresentationRequest
  alias Boruta.Oauth.TokenRequest

  @type t :: %__MODULE__{
          status: :internal_server_error | :bad_request | :unauthorized | :not_found,
          error:
            :invalid_request
            | :invalid_client
            | :invalid_access_token
            | :invalid_agent_token
            | :invalid_scope
            | :invalid_code
            | :invalid_resource_owner
            | :login_required
            | :not_found
            | :unknown_error,
          error_description: String.t(),
          format: :query | :fragment | :json | nil,
          redirect_uri: String.t() | nil,
          state: String.t() | nil
        }

  @enforce_keys [:status, :error, :error_description]
  defstruct status: nil,
            error: nil,
            error_description: nil,
            format: nil,
            redirect_uri: nil,
            state: nil

  @doc """
  Returns the OAuth error augmented with the format according to request type.
  """
  @spec with_format(
          error :: Error.t(),
          request ::
            CodeRequest.t()
            | TokenRequest.t()
            | HybridRequest.t()
            | AuthorizationRequest.t()
            | PreauthorizedCodeRequest.t()
            | PresentationRequest.t()
        ) :: Error.t()
  def with_format(%Error{error: :invalid_client} = error, _) do
    %{error | format: nil, redirect_uri: nil}
  end

  def with_format(
        %Error{error: :invalid_resource_owner} = error,
        %HybridRequest{
          redirect_uri: redirect_uri,
          state: state,
          prompt: "none"
        } = request
      ) do
    %{
      error
      | error: :login_required,
        error_description: "User is not logged in.",
        format: response_mode(request),
        redirect_uri: redirect_uri,
        state: state
    }
  end

  def with_format(%Error{error: :invalid_resource_owner} = error, %CodeRequest{
        redirect_uri: redirect_uri,
        state: state,
        prompt: "none"
      }) do
    %{
      error
      | error: :login_required,
        error_description: "User is not logged in.",
        format: :query,
        redirect_uri: redirect_uri,
        state: state
    }
  end

  def with_format(%Error{error: :invalid_resource_owner} = error, %TokenRequest{
        redirect_uri: redirect_uri,
        state: state,
        prompt: "none"
      }) do
    %{
      error
      | error: :login_required,
        error_description: "User is not logged in.",
        format: :fragment,
        redirect_uri: redirect_uri,
        state: state
    }
  end

  def with_format(%Error{} = error, %CodeRequest{redirect_uri: redirect_uri, state: state}) do
    %{error | format: :query, redirect_uri: redirect_uri, state: state}
  end

  def with_format(%Error{} = error, %AuthorizationRequest{
        redirect_uri: redirect_uri,
        state: state
      }) do
    %{error | format: :json, redirect_uri: redirect_uri, state: state}
  end

  def with_format(%Error{} = error, %PresentationRequest{redirect_uri: redirect_uri, state: state}) do
    %{error | format: :query, redirect_uri: redirect_uri, state: state}
  end

  def with_format(
        %Error{} = error,
        %HybridRequest{redirect_uri: redirect_uri, state: state} = request
      ) do
    %{error | format: response_mode(request), redirect_uri: redirect_uri, state: state}
  end

  def with_format(%Error{} = error, %TokenRequest{redirect_uri: redirect_uri, state: state}) do
    %{error | format: :fragment, redirect_uri: redirect_uri, state: state}
  end

  def with_format(%Error{} = error, %PreauthorizedCodeRequest{
        redirect_uri: redirect_uri,
        state: state
      }) do
    %{error | format: :fragment, redirect_uri: redirect_uri, state: state}
  end

  defp response_mode(%HybridRequest{response_mode: "query"}), do: :query
  defp response_mode(%HybridRequest{response_mode: "fragment"}), do: :fragment
  # fallback to fragment since it is the hybrid default response mode
  defp response_mode(%HybridRequest{response_mode: nil}), do: :fragment

  @doc """
  Returns the URL to be redirected according to error format.
  """
  @spec redirect_to_url(error :: t()) :: url :: String.t()
  def redirect_to_url(%__MODULE__{format: nil}), do: ""

  def redirect_to_url(%__MODULE__{} = error) do
    query_params = query_params(error)

    url(error, query_params)
  end

  defp query_params(%__MODULE__{
         error: error,
         error_description: error_description,
         state: state
       }) do
    %{error: error, error_description: error_description, state: state}
    |> Enum.filter(fn
      {_key, nil} -> false
      _ -> true
    end)
    |> URI.encode_query()
  end

  defp url(%Error{redirect_uri: redirect_uri, format: :query}, query_params),
    do: "#{redirect_uri}?#{query_params}"

  defp url(%Error{redirect_uri: redirect_uri, format: :fragment}, query_params),
    do: "#{redirect_uri}##{query_params}"
end
