defmodule Boruta.Oauth.Authorization.Data do
  @moduledoc """
  Check against given params and return the corresponding bind data and configuration
  """

  alias Boruta.Oauth.Error

  @spec authorize(bind_data :: String.t() | nil, bind_configuration :: String.t() | nil) ::
          {:ok, bind_data :: map(), bind_configuration :: map()} | {:error, reason :: String.t()}
  def authorize(bind_data, bind_configuration) when is_binary(bind_data) and is_binary(bind_configuration) do
    with {:ok, bind_data} <- Jason.decode(bind_data),
         {:ok, bind_configuration} <- Jason.decode(bind_configuration) do
      {:ok, bind_data, bind_configuration}
    else
      {:error, %Jason.DecodeError{} = error} ->
        {:error, %Error{
          status: :bad_request,
          error: :invalid_request,
          error_description: "Invalid bind parameter: " <> Jason.DecodeError.message(error)
        }}
    end
  end

  def authorize(_bind_data, _bind_configuration), do: %Error{
    status: :bad_request,
    error: :invalid_request,
    error_description: "Missing parameter bind_data or bind_configuration"
  }
end
