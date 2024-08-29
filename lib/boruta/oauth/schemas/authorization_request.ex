defmodule Boruta.Oauth.AuthorizationRequest do
  @moduledoc """
  Authorization request and utilities
  """

  defstruct id: nil,
            client_id: nil,
            client_authentication: %{},
            response_type: nil,
            redirect_uri: nil,
            scope: nil,
            state: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            expires_at: nil

  @type client_authentication :: %{
          client_id: String.t(),
          credentials: %{
            String.t() => String.t()
          }
        }

  @type t :: %__MODULE__{
          id: nil | String.t(),
          client_id: String.t(),
          client_authentication: nil | client_authentication(),
          response_type: String.t(),
          redirect_uri: String.t(),
          scope: String.t(),
          state: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          expires_at: nil | integer()
        }

  def persisted?(%__MODULE__{id: nil}), do: false
  def persisted?(_request), do: true

  def expired?(%__MODULE__{expires_at: expires_at}) do
    expires_at < :os.system_time(:seconds)
  end

  @spec to_params(request :: t()) :: params :: map()
  def to_params(request) do
    Map.from_struct(request)
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Enum.map(fn {k, v} -> {to_string(k), v} end)
    |> Enum.into(%{})
  end
end
